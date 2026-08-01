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
    in_window,
    merge_diagnostics,
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
            ),
            instance,
        )

    @staticmethod
    def _repo_path(target: RepositoryTarget) -> str:
        return f"/repos/{target.owner}/{target.name}"

    @staticmethod
    def _id(target: RepositoryTarget, kind: str, native_id: Any) -> str:
        return f"{kind}:gitee:{target.instance}:{target.owner}/{target.name}:{native_id}"

    def _page(self, path: str, params: dict[str, Any]) -> PageResult:
        return paginate(self.transport, path, params, per_page=100)

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
            "full_name": raw.get("full_name") or f"{target.owner}/{target.name}",
            "name": raw.get("name") or target.name,
            "web_url": raw.get("html_url") or f"{instance_web_base(target.instance)}/{target.owner}/{target.name}",
        }
        issue_result = self._safe_page(
            "work_items",
            lambda: self._page(
                f"{self._repo_path(target)}/issues",
                {"state": "all", "since": request.window_start},
            ),
        )
        issue_result.items = [
            self._normalize_issue(target, item)
            for item in issue_result.items
            if in_window(item.get("updated_at"), request) or in_window(item.get("created_at"), request)
        ]
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
        pull_result.items = [
            self._normalize_pull(target, item)
            for item in pull_result.items
            if self._change_request_in_window(item, request)
        ]
        interactions = self._collect_interactions(target, issue_result.items, pull_result.items, request)
        commit_result = self._safe_page(
            "commits",
            lambda: self._page(
                f"{self._repo_path(target)}/commits",
                {"since": request.window_start, "until": request.window_end},
            ),
        )
        commit_result.items = [
            self._normalize_commit(target, item)
            for item in commit_result.items
            if in_window(self._commit_timestamp(item), request)
        ]
        release_result = self._safe_page(
            "releases",
            lambda: self._page(f"{self._repo_path(target)}/releases", {}),
        )
        release_result.items = [
            self._normalize_release(target, item)
            for item in release_result.items
            if in_window(first_timestamp(item, "published_at", "created_at"), request)
        ]
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
            merge_diagnostics(diagnostics, result.diagnostics)
            if result.status != "supported":
                complete = False
                notes.append(result.note)
            for comment in result.items:
                occurred_at = first_timestamp(comment, "created_at", "updated_at")
                if not in_window(occurred_at, request):
                    continue
                records.append(
                    {
                        "id": self._id(target, "interaction", comment.get("id")),
                        "kind": "comment",
                        "repository_id": target.canonical_id,
                        "subject_number": number,
                        "occurred_at": occurred_at,
                        "body_collected": False,
                        "web_url": comment.get("html_url") or item.get("web_url"),
                        "_actor": actor_from(comment, "user", "author"),
                        "_summary": "Observed comment",
                        "_section": "project",
                    }
                )
        return SourceResult(
            records,
            "supported" if complete else "incomplete",
            "; ".join(notes),
            diagnostics,
        )

    @staticmethod
    def _change_request_in_window(item: dict[str, Any], request: CollectionRequest) -> bool:
        return any(
            in_window(item.get(field), request)
            for field in ("created_at", "updated_at", "closed_at", "merged_at")
        )

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
            "_actor": actor_from(item, "author", "committer"),
            "_summary": title,
            "_section": "change",
        }

    def _normalize_release(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        release_id = item.get("id") or item.get("tag_name") or item.get("name")
        return {
            "id": self._id(target, "release", release_id),
            "repository_id": target.canonical_id,
            "tag": item.get("tag_name"),
            "name": item.get("name") or item.get("tag_name") or "",
            "occurred_at": first_timestamp(item, "published_at", "created_at"),
            "web_url": item.get("html_url"),
            "_summary": item.get("name") or item.get("tag_name") or "Release",
            "_section": "release",
        }
