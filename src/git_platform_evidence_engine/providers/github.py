from __future__ import annotations

from typing import Any

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
)
from .transport import ApiError, JsonTransport, PageResult, UrllibTransport, paginate


class GitHubProvider(ResourceProvider):
    """GitHub resource collector; activity/ref APIs remain optional."""

    descriptor = PROVIDER_DESCRIPTORS["github"]

    def __init__(
        self,
        transport: JsonTransport | None = None,
        *,
        instance: str = "github.com",
        token: str | None = None,
        verify_tls: bool = True,
    ) -> None:
        if instance == "github.com":
            api_base = "https://api.github.com"
        else:
            host = instance.rstrip("/")
            if not host.startswith(("http://", "https://")):
                host = f"https://{host}"
            api_base = f"{host}/api/v3"
        super().__init__(transport or UrllibTransport(api_base, token, verify_tls=verify_tls), instance)

    @staticmethod
    def _repo_path(target: RepositoryTarget) -> str:
        return f"/repos/{target.owner}/{target.name}"

    @staticmethod
    def _id(target: RepositoryTarget, kind: str, native_id: Any) -> str:
        return f"{kind}:github:{target.instance}:{target.owner}/{target.name}:{native_id}"

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
            "provider_id": f"provider:github:{target.instance}",
            "full_name": raw.get("full_name") or f"{target.owner}/{target.name}",
            "name": raw.get("name") or target.name,
            "web_url": raw.get("html_url") or f"https://{target.instance}/{target.owner}/{target.name}",
        }

        work_items = self._safe_page(
            "work_items",
            lambda: self._page(
                f"{self._repo_path(target)}/issues",
                {"state": "all", "since": request.window_start},
            ),
        )
        work_items.items = [
            self._normalize_issue(target, item)
            for item in work_items.items
            if "pull_request" not in item and in_window(item.get("updated_at"), request)
        ]

        change_requests = self._safe_page(
            "change_requests",
            lambda: self._page(
                f"{self._repo_path(target)}/pulls",
                {"state": "all", "sort": "updated", "direction": "desc"},
            ),
        )
        change_requests.items = [
            self._normalize_pull(target, item)
            for item in change_requests.items
            if self._change_request_in_window(item, request)
        ]

        interactions = self._collect_interactions(target, work_items.items, change_requests.items, request)
        commits = self._safe_page(
            "commits",
            lambda: self._page(
                f"{self._repo_path(target)}/commits",
                {"since": request.window_start, "until": request.window_end},
            ),
        )
        commits.items = [
            self._normalize_commit(target, item)
            for item in commits.items
            if self._commit_in_window(item, request)
        ]

        releases = self._safe_page(
            "releases",
            lambda: self._page(f"{self._repo_path(target)}/releases", {}),
        )
        releases.items = [
            self._normalize_release(target, item)
            for item in releases.items
            if in_window(first_timestamp(item, "published_at", "created_at"), request)
        ]
        return RepositorySnapshot(
            repository,
            {
                "work_items": work_items,
                "change_requests": change_requests,
                "interactions": interactions,
                "commits": commits,
                "releases": releases,
            },
        )

    def _collect_activity(
        self, target: RepositoryTarget, request: CollectionRequest
    ) -> dict[str, SourceResult]:
        result = self._safe_page(
            "activities",
            lambda: self._page(f"{self._repo_path(target)}/events", {}),
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
        repository_url = f"https://{target.instance}/{target.owner}/{target.name}"
        for event in events:
            if event.get("type") != "PushEvent":
                continue
            payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
            commit_shas = [
                item.get("sha")
                for item in payload.get("commits", [])
                if isinstance(item, dict) and isinstance(item.get("sha"), str)
            ]
            head = payload.get("head")
            if not commit_shas and isinstance(head, str) and head:
                commit_shas = [head]
            if not payload.get("ref") or not commit_shas:
                lossy = True
            size = payload.get("size")
            if isinstance(size, int) and size > len(commit_shas):
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
            event_id = event.get("id") or payload.get("push_id")
            if event_id is None:
                lossy = True
                continue
            ref_changes.append(
                {
                    "id": self._id(target, "ref_change", event_id),
                    "kind": "push",
                    "repository_id": target.canonical_id,
                    "ref": payload.get("ref"),
                    "occurred_at": first_timestamp(event, "created_at"),
                    "web_url": f"{repository_url}/commit/{head}" if isinstance(head, str) and head else repository_url,
                    "_commit_shas": commit_shas,
                    "_change_request_ids": list(dict.fromkeys(change_request_ids)),
                    "_association_attempted": bool(commit_shas),
                    "_association_complete": association_complete,
                    "_actor": actor_from(event, "actor"),
                    "_summary": f"Observed push on {payload.get('ref') or 'unknown ref'}",
                    "_section": "change",
                }
            )
        note = (
            "GitHub repository events are a bounded, latency-limited supplement; "
            "complete push/ref coverage is not claimed"
        )
        if lossy:
            note += "; one or more push payloads omitted ref or commit detail"
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

    def _commit_change_request_candidates(
        self, target: RepositoryTarget, sha: str
    ) -> tuple[list[str], SourceResult]:
        result = self._safe_page(
            "commit_associations",
            lambda: self._page(f"{self._repo_path(target)}/commits/{sha}/pulls", {}),
        )
        candidate_ids: list[str] = []
        complete = result.status == "supported"
        for item in result.items:
            number = item.get("number")
            if number is None:
                complete = False
                continue
            candidate_ids.append(self._id(target, "change_request", number))
        if not complete and result.status == "supported":
            result = SourceResult(
                result.items,
                "incomplete",
                "commit association response omitted a pull request number",
                result.diagnostics,
            )
        return list(dict.fromkeys(candidate_ids)), result

    def _normalize_issue(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        number = item.get("number")
        return {
            "id": self._id(target, "work_item", number),
            "kind": "issue",
            "repository_id": target.canonical_id,
            "number": number,
            "title": item.get("title") or "",
            "state": item.get("state"),
            "occurred_at": first_timestamp(item, "updated_at", "created_at"),
            "web_url": item.get("html_url"),
            "_actor": actor_from(item, "user"),
            "_summary": item.get("title") or f"Issue #{number}",
            "_section": "project",
        }

    def _normalize_pull(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        number = item.get("number")
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
            "_actor": actor_from(item, "user"),
            "_summary": item.get("title") or f"Pull request #{number}",
            "_section": "release" if merged_at else "change",
        }

    def _normalize_comment(
        self, target: RepositoryTarget, item: dict[str, Any], number: Any, kind: str
    ) -> dict[str, Any]:
        comment_id = item.get("id")
        return {
            "id": self._id(target, "interaction", f"{kind}:{comment_id}"),
            "kind": kind,
            "repository_id": target.canonical_id,
            "subject_number": number,
            "occurred_at": first_timestamp(item, "created_at", "submitted_at", "updated_at"),
            "body_collected": False,
            "web_url": item.get("html_url") or item.get("pull_request_url"),
            "_actor": actor_from(item, "user", "author"),
            "_summary": f"Observed {kind.replace('_', ' ')}",
            "_section": "project",
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
        pull_numbers = {item.get("number") for item in pulls}
        for item in [*issues, *pulls]:
            number = item.get("number")
            result = self._safe_page(
                "interactions",
                lambda number=number: self._page(
                    f"{self._repo_path(target)}/issues/{number}/comments", {}
                ),
            )
            merge_diagnostics(diagnostics, result.diagnostics)
            if result.status != "supported":
                complete = False
                notes.append(result.note)
            records.extend(
                self._normalize_comment(target, comment, number, "issue_comment")
                for comment in result.items
                if in_window(first_timestamp(comment, "created_at", "updated_at"), request)
            )
            if number in pull_numbers:
                for endpoint, kind, timestamp_fields in (
                    (f"{self._repo_path(target)}/pulls/{number}/reviews", "review", ("submitted_at", "updated_at")),
                    (f"{self._repo_path(target)}/pulls/{number}/comments", "review_comment", ("created_at", "updated_at")),
                ):
                    result = self._safe_page("interactions", lambda endpoint=endpoint: self._page(endpoint, {}))
                    merge_diagnostics(diagnostics, result.diagnostics)
                    if result.status != "supported":
                        complete = False
                        notes.append(result.note)
                    records.extend(
                        self._normalize_comment(target, comment, number, kind)
                        for comment in result.items
                        if in_window(first_timestamp(comment, *timestamp_fields), request)
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
    def _commit_in_window(item: dict[str, Any], request: CollectionRequest) -> bool:
        commit = item.get("commit") or {}
        return any(
            in_window(first_timestamp(commit.get(field) or {}, "date"), request)
            for field in ("committer", "author")
            if isinstance(commit.get(field), dict)
        )

    def _normalize_commit(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        sha = item.get("sha")
        commit = item.get("commit") or {}
        committer = commit.get("committer") or {}
        return {
            "id": self._id(target, "commit", sha),
            "sha": sha,
            "repository_id": target.canonical_id,
            "occurred_at": first_timestamp(committer, "date") or first_timestamp(commit.get("author") or {}, "date"),
            "title": str(commit.get("message") or "").splitlines()[0],
            "web_url": item.get("html_url"),
            "_actor": actor_from(item, "author", "committer"),
            "_summary": str(commit.get("message") or "").splitlines()[0] or f"Commit {sha}",
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
            "_summary": item.get("name") or item.get("tag_name") or "Release",
            "_section": "release",
        }
