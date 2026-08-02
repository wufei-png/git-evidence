from __future__ import annotations

from datetime import timedelta
from typing import Any
from urllib.parse import quote

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
    parse_timestamp,
)
from .transport import ApiError, JsonTransport, PageResult, ResponseShapeError, UrllibTransport, paginate


class GitLabProvider(ResourceProvider):
    """GitLab resource collector for GitLab.com and compatible instances."""

    descriptor = PROVIDER_DESCRIPTORS["gitlab"]

    def __init__(
        self,
        transport: JsonTransport | None = None,
        *,
        instance: str = "gitlab.com",
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
        super().__init__(
            transport
            or UrllibTransport(
                f"{base.rstrip('/')}/api/v4",
                token,
                token_header="PRIVATE-TOKEN",
                token_prefix="",
                verify_tls=verify_tls,
                timeout=timeout_seconds,
                max_retries=max_retries,
                retry_backoff=retry_backoff_seconds,
                provider_kind="gitlab",
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
    def _project_path(target: RepositoryTarget) -> str:
        return f"/projects/{quote(f'{target.owner}/{target.name}', safe='')}"

    @staticmethod
    def _id(target: RepositoryTarget, kind: str, native_id: Any) -> str:
        if not is_valid_native_id(native_id):
            raise ResponseShapeError(f"{kind} response omitted a stable native id")
        return f"{kind}:gitlab:{target.instance}:{target.owner}/{target.name}:{native_id}"

    def _page(self, path: str, params: dict[str, Any]) -> PageResult:
        return paginate(self.transport, path, params, per_page=100, max_pages=self.max_pages)

    def _collect_repository(
        self, target: RepositoryTarget, request: CollectionRequest
    ) -> RepositorySnapshot:
        project_path = self._project_path(target)
        try:
            response = self.transport.get(project_path)
            if not isinstance(response.body, dict):
                raise ApiError(f"expected project object from {response.url}")
        except ApiError as exc:
            failed = {
                source: SourceResult([], "incomplete", str(exc), api_error_diagnostics(exc))
                for source in RESOURCE_SOURCES
            }
            return RepositorySnapshot(None, failed)

        raw = response.body
        repository = {
            "id": target.canonical_id,
            "provider_id": f"provider:gitlab:{target.instance}",
            "full_name": raw.get("path_with_namespace"),
            "name": raw.get("name"),
            "web_url": raw.get("web_url") or f"{instance_web_base(target.instance)}/{target.owner}/{target.name}",
        }
        issue_result = self._safe_page(
            "work_items",
            lambda: self._page(
                f"{project_path}/issues",
                {
                    "state": "all",
                    "updated_after": request.window_start,
                    "updated_before": request.window_end,
                    "order_by": "updated_at",
                    "sort": "asc",
                },
            ),
        )
        issue_result = self._normalize_items(
            issue_result,
            "work_items",
            lambda item: self._normalize_issue(target, item),
            filter_item=lambda item: in_window_or_malformed(item, request, "updated_at", "created_at"),
        )

        mr_result = self._safe_page(
            "change_requests",
            lambda: self._page(
                f"{project_path}/merge_requests",
                {
                    "state": "all",
                    "updated_after": request.window_start,
                    "updated_before": request.window_end,
                    "order_by": "updated_at",
                    "sort": "asc",
                },
            ),
        )
        mr_result = self._normalize_items(
            mr_result,
            "change_requests",
            lambda item: self._normalize_merge_request(target, item),
            filter_item=lambda item: self._change_request_in_window(item, request),
        )

        interactions = self._collect_interactions(target, issue_result.items, mr_result.items, request)
        commit_result = self._safe_page(
            "commits",
            lambda: self._page(
                f"{project_path}/repository/commits",
                {
                    "all": "true",
                    "since": request.window_start,
                    "until": request.window_end,
                },
            ),
        )
        commit_result = self._normalize_items(
            commit_result,
            "commits",
            lambda item: self._normalize_commit(target, item),
            filter_item=lambda item: in_window_or_malformed(item, request, "committed_date", "created_at"),
        )

        release_result = self._safe_page(
            "releases",
            lambda: self._page(f"{project_path}/releases", {}),
        )
        release_result = self._normalize_items(
            release_result,
            "releases",
            lambda item: self._normalize_release(target, item),
            filter_item=lambda item: in_window_or_malformed(item, request, "released_at", "created_at"),
        )
        return RepositorySnapshot(
            repository,
            {
                "work_items": issue_result,
                "change_requests": mr_result,
                "interactions": interactions,
                "commits": commit_result,
                "releases": release_result,
            },
        )

    def _collect_activity(
        self, target: RepositoryTarget, request: CollectionRequest
    ) -> dict[str, SourceResult]:
        project_path = self._project_path(target)
        result = self._safe_page(
            "activities",
            lambda: self._page(
                f"{project_path}/events",
                {
                    "after": self._event_date(request.window_start, subtract_days=1),
                    "before": self._event_date(request.window_end),
                    "sort": "asc",
                },
            ),
        )
        result = self._normalize_items(
            result,
            "activities",
            lambda event: dict(event),
            filter_item=lambda event: in_window_or_malformed(event, request, "created_at"),
        )
        events = result.items
        ref_changes: list[dict[str, Any]] = []
        lossy = False
        association_cache: dict[str, tuple[list[str], SourceResult]] = {}
        association_summary = {"attempted": 0, "complete": 0, "failed": 0}
        association_failure_classes: set[str] = set()
        for event in events:
            action = str(event.get("action_name") or "").lower()
            if "push" not in action:
                continue
            push_data = event.get("push_data") if isinstance(event.get("push_data"), dict) else {}
            commit_shas = [
                value
                for value in (push_data.get("commit_from"), push_data.get("commit_to"))
                if isinstance(value, str) and value and not set(value) == {"0"}
            ]
            ref = push_data.get("ref")
            ref_type = push_data.get("ref_type")
            if isinstance(ref, str) and ref and not ref.startswith("refs/"):
                prefix = {"branch": "refs/heads", "tag": "refs/tags"}.get(str(ref_type))
                ref = f"{prefix}/{ref}" if prefix else ref
            commit_count = push_data.get("commit_count")
            ref_count = push_data.get("ref_count")
            if not ref or not commit_shas:
                lossy = True
            if isinstance(commit_count, int) and commit_count > len(commit_shas):
                lossy = True
            if isinstance(ref_count, int) and ref_count > 1:
                lossy = True
            change_request_ids: list[str] = []
            association_complete = bool(commit_shas)
            if commit_shas:
                for sha in commit_shas:
                    if sha not in association_cache:
                        association_cache[sha] = self._commit_change_request_candidates(target, sha)
                    candidates, association_result = association_cache[sha]
                    association_summary["attempted"] += 1
                    change_request_ids.extend(candidates)
                    if association_result.status == "supported":
                        association_summary["complete"] += 1
                    else:
                        association_complete = False
                        association_summary["failed"] += 1
                        failure_class = association_result.diagnostics.get("failure_class")
                        if isinstance(failure_class, str):
                            association_failure_classes.add(failure_class)
            else:
                association_complete = False
            event_id = event.get("id")
            if not is_valid_native_id(event_id):
                lossy = True
            commit_to = push_data.get("commit_to")
            ref_changes.append(
                {
                    "id": self._id(target, "ref_change", event_id) if is_valid_native_id(event_id) else "",
                    "kind": "push",
                    "repository_id": target.canonical_id,
                    "ref": ref,
                    "occurred_at": first_timestamp(event, "created_at"),
                    "web_url": (
                        f"{instance_web_base(target.instance)}/{target.owner}/{target.name}/-/commit/{commit_to}"
                        if isinstance(commit_to, str) and commit_to
                        else None
                    ),
                    "_commit_shas": list(dict.fromkeys(commit_shas)),
                    "_change_request_ids": list(dict.fromkeys(change_request_ids)),
                    "_association_attempted": bool(commit_shas),
                    "_association_complete": association_complete,
                    "_native_id": event_id,
                    "_actor": actor_from(event, "author"),
                    "_summary": f"Observed push on {ref or 'unknown ref'}",
                    "_section": "change",
                }
            )
        note = (
            "GitLab project events are a bounded activity supplement; complete "
            "push/ref coverage is not claimed"
        )
        if lossy:
            note += "; one or more push events were bulk or missing ref/commit detail"
        association_note = ""
        if association_summary["failed"]:
            association_note = (
                "; commit-to-change-request association was only partially observed"
            )
            if association_failure_classes:
                association_note += " (" + ", ".join(sorted(association_failure_classes)) + ")"
        if result.status != "supported":
            note = result.note or note
        activity_status = "incomplete" if result.status == "supported" else result.status
        ref_diagnostics = dict(result.diagnostics or {})
        if association_summary["attempted"]:
            association_diagnostics: dict[str, Any] = {"summary": association_summary}
            if association_failure_classes:
                association_diagnostics["failure_classes"] = sorted(association_failure_classes)
            ref_diagnostics["commit_association"] = association_diagnostics
        return {
            "activities": SourceResult(events, activity_status, note, result.diagnostics or {}),
            "ref_changes": SourceResult(
                ref_changes,
                "incomplete" if result.status == "supported" else result.status,
                note + association_note,
                ref_diagnostics,
            ),
        }

    @staticmethod
    def _event_date(value: str, *, subtract_days: int = 0) -> str:
        timestamp = parse_timestamp(value)
        if timestamp:
            return (timestamp.date() - timedelta(days=subtract_days)).isoformat()
        return value[:10]

    def _commit_change_request_candidates(
        self, target: RepositoryTarget, sha: str
    ) -> tuple[list[str], SourceResult]:
        project_path = self._project_path(target)
        result = self._safe_page(
            "commit_associations",
            lambda: self._page(f"{project_path}/repository/commits/{sha}/merge_requests", {}),
        )
        candidate_ids: list[str] = []
        complete = result.status == "supported"
        malformed_candidates = 0
        for item in result.items:
            iid = item.get("iid")
            if not is_valid_native_id(iid):
                complete = False
                malformed_candidates += 1
                continue
            candidate_ids.append(self._id(target, "change_request", iid))
        if malformed_candidates:
            result.status = "incomplete"
            result.note = (
                f"{result.note}; " if result.note else ""
            ) + f"commit association response dropped {malformed_candidates} malformed candidate(s)"
            merge_diagnostics(
                result.diagnostics,
                {
                    "failure_class": "malformed_response",
                    "dropped_count": malformed_candidates,
                    "malformed_items": malformed_candidates,
                },
            )
        elif not complete and result.status == "supported":
            result = SourceResult(
                result.items,
                "incomplete",
                "commit association response omitted a merge request iid",
                result.diagnostics,
            )
        return list(dict.fromkeys(candidate_ids)), result

    def _normalize_issue(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        iid = item.get("iid")
        return {
            "id": self._id(target, "work_item", iid),
            "kind": "issue",
            "repository_id": target.canonical_id,
            "number": iid,
            "title": item.get("title") or "",
            "state": item.get("state"),
            "occurred_at": first_timestamp(item, "updated_at", "created_at"),
            "web_url": item.get("web_url"),
            "_native_id": iid,
            "_actor": actor_from(item, "author"),
            "_summary": item.get("title") or f"Issue #{iid}",
            "_section": "project",
        }

    def _normalize_merge_request(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        iid = item.get("iid")
        merged_at = item.get("merged_at")
        diff_refs = item.get("diff_refs") if isinstance(item.get("diff_refs"), dict) else {}
        association_shas = [
            item.get("merge_commit_sha"),
            item.get("squash_commit_sha"),
            diff_refs.get("head_sha"),
        ]
        return {
            "id": self._id(target, "change_request", iid),
            "kind": "merge_request",
            "repository_id": target.canonical_id,
            "number": iid,
            "title": item.get("title") or "",
            "state": "merged" if merged_at else item.get("state"),
            "merged_at": merged_at,
            "occurred_at": first_timestamp(item, "merged_at", "updated_at", "created_at"),
            "web_url": item.get("web_url"),
            "_association_shas": association_shas,
            "_native_id": iid,
            "_actor": actor_from(item, "author"),
            "_summary": item.get("title") or f"Merge request !{iid}",
            "_section": "release" if merged_at else "change",
        }

    def _collect_interactions(
        self,
        target: RepositoryTarget,
        issues: list[dict[str, Any]],
        merge_requests: list[dict[str, Any]],
        request: CollectionRequest,
    ) -> SourceResult:
        records: list[dict[str, Any]] = []
        complete = True
        notes: list[str] = []
        diagnostics: dict[str, Any] = {}
        for item in [*issues, *merge_requests]:
            number = item.get("number")
            if item.get("kind") == "issue":
                path = f"{self._project_path(target)}/issues/{number}/notes"
            else:
                path = f"{self._project_path(target)}/merge_requests/{number}/notes"
            result = self._safe_page(
                "interactions",
                lambda path=path: self._page(path, {"sort": "asc", "order_by": "created_at"}),
            )
            result = self._normalize_items(
                result,
                "interactions",
                lambda note, number=number, subject=item: self._normalize_note(
                    target, note, number, subject
                ),
                filter_item=lambda note: in_window_or_malformed(
                    note, request, "created_at", "updated_at"
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
        return in_window_or_malformed(item, request, "merged_at", "updated_at", "created_at")

    def _normalize_note(
        self,
        target: RepositoryTarget,
        note: dict[str, Any],
        number: Any,
        subject: dict[str, Any],
    ) -> dict[str, Any]:
        note_id = note.get("id")
        return {
            "id": self._id(target, "interaction", note_id),
            "kind": "system_note" if note.get("system") else "comment",
            "repository_id": target.canonical_id,
            "subject_number": number,
            "occurred_at": first_timestamp(note, "created_at", "updated_at"),
            "body_collected": False,
            "system": bool(note.get("system")),
            "web_url": note.get("noteable_url") or subject.get("web_url"),
            "_native_id": note_id,
            "_actor": actor_from(note, "author"),
            "_summary": "Observed system note" if note.get("system") else "Observed comment",
            "_section": "project",
        }

    def _normalize_commit(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        sha = item.get("id")
        message = item.get("title") or item.get("message")
        if not isinstance(message, str) or not message.strip():
            raise ResponseShapeError(f"commit {sha} has no commit message")
        title = message.splitlines()[0].strip()
        actor = actor_from(item, "author")
        if actor is None and item.get("author_name"):
            actor = {
                "source_id": item.get("author_email") or item.get("author_name"),
                "handle": item.get("author_name"),
            }
        return {
            "id": self._id(target, "commit", sha),
            "sha": sha,
            "repository_id": target.canonical_id,
            "occurred_at": first_timestamp(item, "committed_date", "created_at"),
            "title": title,
            "web_url": item.get("web_url"),
            "_native_id": sha,
            "_actor": actor,
            "_summary": title or f"Commit {sha}",
            "_section": "change",
        }

    def _normalize_release(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        tag = item.get("tag_name")
        return {
            "id": self._id(target, "release", tag),
            "repository_id": target.canonical_id,
            "tag": item.get("tag_name"),
            "name": item.get("name") or tag or "",
            "occurred_at": first_timestamp(item, "released_at", "created_at"),
            "web_url": item.get("_links", {}).get("self") if isinstance(item.get("_links"), dict) else None,
            "_native_id": tag,
            "_summary": item.get("name") or tag or "Release",
            "_section": "release",
        }
