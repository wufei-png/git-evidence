from __future__ import annotations

from typing import Any

from .base import RESOURCE_SOURCES, CollectionRequest, RepositoryTarget, instance_web_base
from .catalog import PROVIDER_DESCRIPTORS
from .resource_base import (
    RepositorySnapshot,
    ResourceProvider,
    SourceResult,
    actor_from,
    api_error_diagnostics,
    first_timestamp,
    in_window_or_malformed,
    in_window,
    is_valid_native_id,
    merge_diagnostics,
    native_id,
)
from .transport import ApiError, JsonTransport, PageResult, UrllibTransport, paginate


class GiteeProvider(ResourceProvider):
    """Gitee v5 resource collector; activity/ref APIs remain optional."""

    descriptor = PROVIDER_DESCRIPTORS["gitee"]

    def __init__(
        self,
        transport: JsonTransport | None = None,
        *,
        instance: str = "gitee.com",
        token: str | None = None,
        verify_tls: bool = True,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        max_pages: int = 100,
        max_requests: int = 1000,
        retry_backoff_seconds: float = 0.5,
        retry_jitter_seconds: float = 0.25,
        retry_after_max_seconds: float = 60.0,
        cache_enabled: bool = False,
        cache_path: str | None = None,
        cache_ttl_seconds: float = 300.0,
        cache_max_entries: int = 256,
    ) -> None:
        base = instance if instance.startswith("http") else f"https://{instance}"
        api_base = f"{base.rstrip('/')}/api/v5"
        super().__init__(
            transport
            or UrllibTransport(
                api_base,
                token,
                token_param="access_token",
                verify_tls=verify_tls,
                timeout=timeout_seconds,
                max_retries=max_retries,
                retry_backoff=retry_backoff_seconds,
                provider_kind="gitee",
                instance=instance,
                max_requests=max_requests,
                retry_jitter=retry_jitter_seconds,
                retry_after_max=retry_after_max_seconds,
                cache_enabled=cache_enabled,
                cache_path=cache_path,
                cache_ttl_seconds=cache_ttl_seconds,
                cache_max_entries=cache_max_entries,
            ),
            instance,
            max_pages=max_pages,
        )

    @staticmethod
    def _repo_path(target: RepositoryTarget) -> str:
        return f"/repos/{target.owner}/{target.name}"

    @staticmethod
    def _id(target: RepositoryTarget, kind: str, native_id: Any) -> str:
        if not is_valid_native_id(native_id):
            raise ValueError(f"{kind} response omitted a stable native id")
        return f"{kind}:gitee:{target.instance}:{target.owner}/{target.name}:{native_id}"

    def _page(self, path: str, params: dict[str, Any]) -> PageResult:
        return paginate(self.transport, path, params, per_page=100, max_pages=self.max_pages)

    def _collect_repository(
        self, target: RepositoryTarget, request: CollectionRequest
    ) -> RepositorySnapshot:
        try:
            response = self.transport.get(self._repo_path(target))
            if not isinstance(response.body, dict):
                raise ApiError(f"expected repository object from {response.url}")
        except ApiError as exc:
            failed = {
                source: SourceResult([], "incomplete", str(exc), api_error_diagnostics(exc))
                for source in RESOURCE_SOURCES
            }
            return RepositorySnapshot(None, failed)

        raw = response.body
        repository = {
            "id": target.canonical_id,
            "provider_id": f"provider:gitee:{target.instance}",
            "full_name": raw.get("full_name"),
            "name": raw.get("name"),
            "web_url": raw.get("html_url") or f"{instance_web_base(target.instance)}/{target.owner}/{target.name}",
        }
        issue_result = self._safe_page(
            "work_items",
            lambda: self._page(
                f"{self._repo_path(target)}/issues",
                {"state": "all", "since": request.window_start},
            ),
        )
        issue_result = self._normalize_items(
            issue_result,
            "work_items",
            lambda item: self._normalize_issue(target, item),
            filter_item=lambda item: in_window_or_malformed(item, request, "updated_at", "created_at"),
        )
        pull_result = self._safe_page(
            "change_requests",
            lambda: self._page(
                f"{self._repo_path(target)}/pulls",
                # Gitee's public v5 endpoint rejects GitHub-style
                # ``sort=updated_at``.  The collector filters the returned
                # resources by the explicit local window below, so the
                # provider does not need a non-portable ordering parameter.
                {"state": "all"},
            ),
        )
        pull_result = self._normalize_items(
            pull_result,
            "change_requests",
            lambda item: self._normalize_pull(target, item),
            filter_item=lambda item: self._change_request_in_window(item, request),
        )
        interactions = self._collect_interactions(target, issue_result.items, pull_result.items, request)
        commit_result = self._safe_page(
            "commits",
            lambda: self._page(
                f"{self._repo_path(target)}/commits",
                {"since": request.window_start, "until": request.window_end},
            ),
        )
        commit_result = self._normalize_items(
            commit_result,
            "commits",
            lambda item: self._normalize_commit(target, item),
            filter_item=lambda item: in_window_or_malformed(
                {"timestamp": self._commit_timestamp(item)} if isinstance(item, dict) else item,
                request,
                "timestamp",
            ),
        )
        release_result = self._safe_page(
            "releases",
            lambda: self._page(f"{self._repo_path(target)}/releases", {}),
        )
        release_result = self._normalize_items(
            release_result,
            "releases",
            lambda item: self._normalize_release(target, item),
            filter_item=lambda item: in_window_or_malformed(item, request, "published_at", "created_at"),
        )
        return RepositorySnapshot(
            repository,
            {
                "work_items": issue_result,
                "change_requests": pull_result,
                "interactions": interactions,
                "commits": commit_result,
                "releases": release_result,
            },
        )

    def _collect_activity(
        self, target: RepositoryTarget, request: CollectionRequest
    ) -> dict[str, SourceResult]:
        return {
            "activities": SourceResult(
                [],
                "unsupported",
                "Gitee activity/ref endpoint semantics are not part of the public contract slice",
            ),
            "ref_changes": SourceResult(
                [],
                "unsupported",
                "Gitee activity/ref endpoint semantics are not part of the public contract slice",
            ),
        }

    def _normalize_issue(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        number = item.get("number") or item.get("id")
        return {
            "id": self._id(target, "work_item", number),
            "kind": "issue",
            "repository_id": target.canonical_id,
            "number": number,
            "title": item.get("title") or "",
            "state": item.get("state"),
            "occurred_at": first_timestamp(item, "updated_at", "created_at"),
            "web_url": item.get("html_url"),
            "_native_id": number,
            "_actor": actor_from(item, "user", "author"),
            "_summary": item.get("title") or f"Issue #{number}",
            "_section": "project",
        }

    def _normalize_pull(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        number = item.get("number") or item.get("id")
        merged_at = item.get("merged_at")
        head = item.get("head") if isinstance(item.get("head"), dict) else {}
        association_shas = [
            item.get("merge_commit_sha"),
            head.get("sha"),
        ]
        return {
            "id": self._id(target, "change_request", number),
            "kind": "pull_request",
            "repository_id": target.canonical_id,
            "number": number,
            "title": item.get("title") or "",
            "state": "merged" if merged_at else item.get("state"),
            "merged_at": merged_at,
            "occurred_at": first_timestamp(item, "merged_at", "updated_at", "created_at"),
            "web_url": item.get("html_url"),
            "_association_shas": association_shas,
            "_native_id": number,
            "_actor": actor_from(item, "user", "author"),
            "_summary": item.get("title") or f"Pull request #{number}",
            "_section": "release" if merged_at else "change",
        }

    def _collect_interactions(
        self,
        target: RepositoryTarget,
        issues: list[dict[str, Any]],
        pulls: list[dict[str, Any]],
        request: CollectionRequest,
    ) -> SourceResult:
        records: list[dict[str, Any]] = []
        complete = True
        notes: list[str] = []
        diagnostics: dict[str, Any] = {}
        for item in [*issues, *pulls]:
            number = item.get("number")
            collection = "issues" if item.get("kind") == "issue" else "pulls"
            result = self._safe_page(
                "interactions",
                lambda number=number, collection=collection: self._page(
                    f"{self._repo_path(target)}/{collection}/{number}/comments",
                    {},
                ),
            )
            result = self._normalize_items(
                result,
                "interactions",
                lambda comment, number=number, subject=item: self._normalize_comment(
                    target, comment, number, subject
                ),
                filter_item=lambda comment: in_window_or_malformed(
                    comment, request, "created_at", "updated_at"
                ),
            )
            merge_diagnostics(diagnostics, result.diagnostics)
            if result.status != "supported":
                complete = False
                notes.append(result.note)
            records.extend(result.items)
        return SourceResult(
            records,
            "supported" if complete else "incomplete",
            "; ".join(notes),
            diagnostics,
        )

    @staticmethod
    def _change_request_in_window(item: dict[str, Any], request: CollectionRequest) -> bool:
        return in_window_or_malformed(item, request, "created_at", "updated_at", "closed_at", "merged_at")

    def _normalize_comment(
        self,
        target: RepositoryTarget,
        comment: dict[str, Any],
        number: Any,
        subject: dict[str, Any],
    ) -> dict[str, Any]:
        comment_id = comment.get("id")
        return {
            "id": self._id(target, "interaction", comment_id),
            "kind": "comment",
            "repository_id": target.canonical_id,
            "subject_number": number,
            "occurred_at": first_timestamp(comment, "created_at", "updated_at"),
            "body_collected": False,
            "web_url": comment.get("html_url") or subject.get("web_url"),
            "_native_id": comment_id,
            "_actor": actor_from(comment, "user", "author"),
            "_summary": "Observed comment",
            "_section": "project",
        }

    @staticmethod
    def _commit_timestamp(item: dict[str, Any]) -> str | None:
        commit = item.get("commit") or {}
        return first_timestamp(
            commit.get("committer") or {}, "date"
        ) or first_timestamp(commit.get("author") or {}, "date") or first_timestamp(
            item, "committed_date", "created_at"
        )

    def _normalize_commit(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        sha = item.get("sha") or item.get("id")
        commit = item.get("commit") or {}
        message = str(commit.get("message") or item.get("message") or "")
        title = message.splitlines()[0] if message else f"Commit {sha}"
        return {
            "id": self._id(target, "commit", sha),
            "sha": sha,
            "repository_id": target.canonical_id,
            "occurred_at": self._commit_timestamp(item),
            "title": title,
            "web_url": item.get("html_url"),
            "_native_id": sha,
            "_actor": actor_from(item, "author", "committer"),
            "_summary": title,
            "_section": "change",
        }

    def _normalize_release(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        release_id = item.get("id") or item.get("tag_name")
        return {
            "id": self._id(target, "release", release_id),
            "repository_id": target.canonical_id,
            "tag": item.get("tag_name"),
            "name": item.get("name") or item.get("tag_name") or "",
            "occurred_at": first_timestamp(item, "published_at", "created_at"),
            "web_url": item.get("html_url"),
            "_native_id": release_id,
            "_summary": item.get("name") or item.get("tag_name") or "Release",
            "_section": "release",
        }
