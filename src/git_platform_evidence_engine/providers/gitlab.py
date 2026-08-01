from __future__ import annotations

from datetime import timedelta
from typing import Any
from urllib.parse import quote

from .base import RESOURCE_SOURCES, CollectionRequest, RepositoryTarget
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
    parse_timestamp,
)
from .transport import ApiError, JsonTransport, PageResult, UrllibTransport, paginate


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
            ),
            instance,
        )

    @staticmethod
    def _project_path(target: RepositoryTarget) -> str:
        return f"/projects/{quote(f'{target.owner}/{target.name}', safe='')}"

    @staticmethod
    def _id(target: RepositoryTarget, kind: str, native_id: Any) -> str:
        return f"{kind}:gitlab:{target.instance}:{target.owner}/{target.name}:{native_id}"

    def _page(self, path: str, params: dict[str, Any]) -> PageResult:
        return paginate(self.transport, path, params, per_page=100)

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
            "full_name": raw.get("path_with_namespace") or f"{target.owner}/{target.name}",
            "name": raw.get("name") or target.name,
            "web_url": raw.get("web_url") or f"https://{target.instance}/{target.owner}/{target.name}",
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
        issue_result.items = [
            self._normalize_issue(target, item)
            for item in issue_result.items
            if in_window(item.get("updated_at"), request) or in_window(item.get("created_at"), request)
        ]

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
        mr_result.items = [
            self._normalize_merge_request(target, item)
            for item in mr_result.items
            if self._change_request_in_window(item, request)
        ]

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
        commit_result.items = [
            self._normalize_commit(target, item)
            for item in commit_result.items
            if in_window(first_timestamp(item, "committed_date", "created_at"), request)
        ]

        release_result = self._safe_page(
            "releases",
            lambda: self._page(f"{project_path}/releases", {}),
        )
        release_result.items = [
            self._normalize_release(target, item)
            for item in release_result.items
            if in_window(first_timestamp(item, "released_at", "created_at"), request)
        ]
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
        events = [
            event
            for event in result.items
            if in_window(first_timestamp(event, "created_at"), request)
        ]
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
            if event_id is None:
                lossy = True
                continue
            commit_to = push_data.get("commit_to")
            ref_changes.append(
                {
                    "id": self._id(target, "ref_change", event_id),
                    "kind": "push",
                    "repository_id": target.canonical_id,
                    "ref": ref,
                    "occurred_at": first_timestamp(event, "created_at"),
                    "web_url": (
                        f"https://{target.instance}/{target.owner}/{target.name}/-/commit/{commit_to}"
                        if isinstance(commit_to, str) and commit_to
                        else None
                    ),
                    "_commit_shas": list(dict.fromkeys(commit_shas)),
                    "_change_request_ids": list(dict.fromkeys(change_request_ids)),
                    "_association_attempted": bool(commit_shas),
                    "_association_complete": association_complete,
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
        for item in result.items:
            iid = item.get("iid")
            if iid is None:
                complete = False
                continue
            candidate_ids.append(self._id(target, "change_request", iid))
        if not complete and result.status == "supported":
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
            merge_diagnostics(diagnostics, result.diagnostics)
            if result.status != "supported":
                complete = False
                notes.append(result.note)
            for note in result.items:
                occurred_at = first_timestamp(note, "created_at", "updated_at")
                if not in_window(occurred_at, request):
                    continue
                records.append(
                    {
                        "id": self._id(target, "interaction", note.get("id")),
                        "kind": "system_note" if note.get("system") else "comment",
                        "repository_id": target.canonical_id,
                        "subject_number": number,
                        "occurred_at": occurred_at,
                        "body_collected": False,
                        "system": bool(note.get("system")),
                        "web_url": note.get("noteable_url") or item.get("web_url"),
                        "_actor": actor_from(note, "author"),
                        "_summary": "Observed system note" if note.get("system") else "Observed comment",
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

    def _normalize_commit(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        sha = item.get("id")
        title = item.get("title") or str(item.get("message") or "").splitlines()[0]
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
            "_actor": actor,
            "_summary": title or f"Commit {sha}",
            "_section": "change",
        }

    def _normalize_release(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        tag = item.get("tag_name") or item.get("name")
        return {
            "id": self._id(target, "release", tag),
            "repository_id": target.canonical_id,
            "tag": item.get("tag_name"),
            "name": item.get("name") or tag or "",
            "occurred_at": first_timestamp(item, "released_at", "created_at"),
            "web_url": item.get("_links", {}).get("self") if isinstance(item.get("_links"), dict) else None,
            "_summary": item.get("name") or tag or "Release",
            "_section": "release",
        }
