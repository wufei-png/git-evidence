from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .base import (
    RESOURCE_SOURCES,
    CollectionRequest,
    RepositoryTarget,
    instance_web_base,
    validate_instance,
)
from .catalog import PROVIDER_DESCRIPTORS
from .resource_base import (
    PageSourceRequest,
    RepositorySnapshot,
    ResourceProvider,
    SourceResult,
    actor_from,
    api_error_diagnostics,
    first_timestamp,
    in_window_or_malformed,
    is_valid_native_id,
    merge_diagnostics,
    validate_repository_identity,
)
from .transport import (
    ApiError,
    JsonTransport,
    PageResult,
    ResponseShapeError,
    UrllibTransport,
    is_success_status,
    paginate,
    response_status_error,
)


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
        allow_insecure_loopback: bool = False,
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
        instance = validate_instance(instance)
        if instance == "github.com":
            api_base = "https://api.github.com"
        else:
            host = instance.rstrip("/")
            if not host.startswith(("http://", "https://")):
                host = f"https://{host}"
            api_base = f"{host}/api/v3"
        super().__init__(
            transport
            or UrllibTransport(
                api_base,
                token,
                verify_tls=verify_tls,
                allow_insecure_loopback=allow_insecure_loopback,
                timeout=timeout_seconds,
                max_retries=max_retries,
                retry_backoff=retry_backoff_seconds,
                provider_kind="github",
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
        return f"/repos/{quote(target.owner, safe='')}/{quote(target.name, safe='')}"

    @staticmethod
    def _id(target: RepositoryTarget, kind: str, native_id: Any) -> str:
        if not is_valid_native_id(native_id):
            raise ResponseShapeError(f"{kind} response omitted a stable native id")
        return f"{kind}:github:{target.instance}:{target.owner}/{target.name}:{native_id}"

    def _page(self, path: str, params: dict[str, Any]) -> PageResult:
        return paginate(self.transport, path, params, per_page=100, max_pages=self.max_pages)

    def _scheduled_root_path(self, target: RepositoryTarget) -> str:
        return self._repo_path(target)

    def _scheduled_repository(
        self, target: RepositoryTarget, raw: dict[str, Any]
    ) -> dict[str, Any]:
        validate_repository_identity(raw, target, identity_field="full_name")
        return {
            "id": target.canonical_id,
            "provider_id": f"provider:github:{target.instance}",
            "full_name": raw.get("full_name"),
            "name": raw.get("name"),
            "web_url": raw.get("html_url")
            or f"{instance_web_base(target.instance)}/{quote(target.owner, safe='')}/{quote(target.name, safe='')}",
        }

    def _scheduled_top_level_requests(
        self, target: RepositoryTarget, request: CollectionRequest
    ) -> list[PageSourceRequest]:
        root = self._repo_path(target)
        return [
            PageSourceRequest(
                target,
                "work_items",
                f"{root}/issues",
                {"state": "all", "since": request.window_start},
                lambda item: self._normalize_issue(target, item),
                lambda item: not isinstance(item, dict)
                or (
                    "pull_request" not in item
                    and in_window_or_malformed(item, request, "updated_at", "created_at")
                ),
            ),
            PageSourceRequest(
                target,
                "change_requests",
                f"{root}/pulls",
                {"state": "all", "sort": "updated", "direction": "desc"},
                lambda item: self._normalize_pull(target, item),
                lambda item: self._change_request_in_window(item, request),
            ),
            PageSourceRequest(
                target,
                "commits",
                f"{root}/commits",
                {"since": request.window_start, "until": request.window_end},
                lambda item: self._normalize_commit(target, item),
                lambda item: self._commit_in_window(item, request),
            ),
            PageSourceRequest(
                target,
                "releases",
                f"{root}/releases",
                {},
                lambda item: self._normalize_release(target, item),
                lambda item: in_window_or_malformed(
                    item, request, "published_at", "created_at"
                ),
            ),
        ]

    def _scheduled_interaction_requests(
        self,
        target: RepositoryTarget,
        snapshot: RepositorySnapshot,
        request: CollectionRequest,
    ) -> list[PageSourceRequest]:
        root = self._repo_path(target)
        tasks: list[PageSourceRequest] = []
        issues = snapshot.sources["work_items"].items
        pulls = snapshot.sources["change_requests"].items
        subjects = [
            *(("work_item", item) for item in issues),
            *(("change_request", item) for item in pulls),
        ]
        for subject_type, item in subjects:
            number = item.get("number")
            tasks.append(
                PageSourceRequest(
                    target,
                    "interactions",
                    f"{root}/issues/{number}/comments",
                    {},
                    lambda comment, number=number, subject_type=subject_type: self._normalize_comment(
                        target, comment, number, "issue_comment", subject_type
                    ),
                    lambda comment: in_window_or_malformed(
                        comment, request, "created_at", "submitted_at", "updated_at"
                    ),
                    subject_type,
                    self._id(target, subject_type, number),
                    "issue_comment",
                )
            )
            if subject_type == "change_request":
                for endpoint_kind, endpoint, timestamp_fields in (
                    (
                        "review",
                        f"{root}/pulls/{number}/reviews",
                        ("created_at", "submitted_at", "updated_at"),
                    ),
                    (
                        "review_comment",
                        f"{root}/pulls/{number}/comments",
                        ("created_at", "submitted_at", "updated_at"),
                    ),
                ):
                    tasks.append(
                        PageSourceRequest(
                            target,
                            "interactions",
                            endpoint,
                            {},
                            lambda comment, number=number, kind=endpoint_kind, subject_type=subject_type: self._normalize_comment(
                                target, comment, number, kind, subject_type
                            ),
                            lambda comment, fields=timestamp_fields: in_window_or_malformed(
                                comment, request, *fields
                            ),
                            subject_type,
                            self._id(target, subject_type, number),
                            endpoint_kind,
                        )
                    )
        return tasks

    def _collect_repository(
        self, target: RepositoryTarget, request: CollectionRequest
    ) -> RepositorySnapshot:
        try:
            response = self.transport.get(self._repo_path(target))
            if not is_success_status(response.status_code):
                raise response_status_error(
                    response,
                    redact_url=getattr(self.transport, "_redact_url", None),
                )
            if not isinstance(response.body, dict):
                raise ResponseShapeError(f"expected repository object from {response.url}")
            validate_repository_identity(response.body, target, identity_field="full_name")
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
            "full_name": raw.get("full_name"),
            "name": raw.get("name"),
            "web_url": raw.get("html_url")
            or f"{instance_web_base(target.instance)}/{quote(target.owner, safe='')}/{quote(target.name, safe='')}",
        }

        work_items = self._safe_page(
            "work_items",
            lambda: self._page(
                f"{self._repo_path(target)}/issues",
                {"state": "all", "since": request.window_start},
            ),
        )
        work_items = self._normalize_items(
            work_items,
            "work_items",
            lambda item: self._normalize_issue(target, item),
            target=target,
            filter_item=lambda item: not isinstance(item, dict)
            or ("pull_request" not in item
            and in_window_or_malformed(item, request, "updated_at", "created_at")),
        )

        change_requests = self._safe_page(
            "change_requests",
            lambda: self._page(
                f"{self._repo_path(target)}/pulls",
                {"state": "all", "sort": "updated", "direction": "desc"},
            ),
        )
        change_requests = self._normalize_items(
            change_requests,
            "change_requests",
            lambda item: self._normalize_pull(target, item),
            target=target,
            filter_item=lambda item: self._change_request_in_window(item, request),
        )

        interactions = self._collect_interactions(target, work_items.items, change_requests.items, request)
        commits = self._safe_page(
            "commits",
            lambda: self._page(
                f"{self._repo_path(target)}/commits",
                {"since": request.window_start, "until": request.window_end},
            ),
        )
        commits = self._normalize_items(
            commits,
            "commits",
            lambda item: self._normalize_commit(target, item),
            target=target,
            filter_item=lambda item: self._commit_in_window(item, request),
        )

        releases = self._safe_page(
            "releases",
            lambda: self._page(f"{self._repo_path(target)}/releases", {}),
        )
        releases = self._normalize_items(
            releases,
            "releases",
            lambda item: self._normalize_release(target, item),
            target=target,
            filter_item=lambda item: in_window_or_malformed(item, request, "published_at", "created_at"),
        )
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
        result = self._normalize_items(
            result,
            "activities",
            lambda event: dict(event),
            target=target,
            filter_item=lambda event: in_window_or_malformed(event, request, "created_at"),
        )
        events = result.items
        ref_changes: list[dict[str, Any]] = []
        lossy = False
        association_cache: dict[str, tuple[list[str], SourceResult]] = {}
        association_summary = {"attempted": 0, "complete": 0, "failed": 0}
        association_failure_classes: set[str] = set()
        repository_url = (
            f"{instance_web_base(target.instance)}/"
            f"{quote(target.owner, safe='')}/{quote(target.name, safe='')}"
        )
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
            if not is_valid_native_id(event_id):
                lossy = True
            ref_changes.append(
                {
                    "id": self._id(target, "ref_change", event_id) if is_valid_native_id(event_id) else "",
                    "kind": "push",
                    "repository_id": target.canonical_id,
                    "ref": payload.get("ref"),
                    "occurred_at": first_timestamp(event, "created_at"),
                    "web_url": f"{repository_url}/commit/{head}" if isinstance(head, str) and head else repository_url,
                    "_commit_shas": commit_shas,
                    "_change_request_ids": list(dict.fromkeys(change_request_ids)),
                    "_association_attempted": bool(commit_shas),
                    "_association_complete": association_complete,
                    "_native_id": event_id,
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
        malformed_candidates = 0
        for item in result.items:
            number = item.get("number")
            if not is_valid_native_id(number):
                complete = False
                malformed_candidates += 1
                continue
            candidate_ids.append(self._id(target, "change_request", number))
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
            "_native_id": number,
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
            "_native_id": number,
            "_actor": actor_from(item, "user"),
            "_summary": item.get("title") or f"Pull request #{number}",
            "_section": "release" if merged_at else "change",
        }

    def _normalize_comment(
        self,
        target: RepositoryTarget,
        item: dict[str, Any],
        number: Any,
        kind: str,
        subject_type: str,
    ) -> dict[str, Any]:
        comment_id = item.get("id")
        return {
            "id": self._id(target, "interaction", f"{kind}:{comment_id}"),
            "kind": kind,
            "repository_id": target.canonical_id,
            "subject_type": subject_type,
            "subject_id": self._id(target, subject_type, number),
            "subject_number": number,
            "occurred_at": first_timestamp(item, "created_at", "submitted_at", "updated_at"),
            "body_collected": False,
            "web_url": item.get("html_url") or item.get("pull_request_url"),
            "_native_id": comment_id,
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
        subjects = [
            *(("work_item", item) for item in issues),
            *(("change_request", item) for item in pulls),
        ]
        for subject_type, item in subjects:
            number = item.get("number")
            result = self._safe_page(
                "interactions",
                lambda number=number: self._page(
                    f"{self._repo_path(target)}/issues/{number}/comments", {}
                ),
            )
            result = self._normalize_items(
                result,
                "interactions",
                lambda comment, number=number, subject_type=subject_type: self._normalize_comment(
                    target, comment, number, "issue_comment", subject_type
                ),
                target=target,
                filter_item=lambda comment: in_window_or_malformed(
                    comment, request, "created_at", "submitted_at", "updated_at"
                ),
            )
            merge_diagnostics(diagnostics, result.diagnostics)
            if result.status != "supported":
                complete = False
                notes.append(result.note)
            records.extend(result.items)
            if number in pull_numbers:
                for endpoint, kind, timestamp_fields in (
                    (
                        f"{self._repo_path(target)}/pulls/{number}/reviews",
                        "review",
                        ("created_at", "submitted_at", "updated_at"),
                    ),
                    (
                        f"{self._repo_path(target)}/pulls/{number}/comments",
                        "review_comment",
                        ("created_at", "submitted_at", "updated_at"),
                    ),
                ):
                    result = self._safe_page("interactions", lambda endpoint=endpoint: self._page(endpoint, {}))
                    result = self._normalize_items(
                        result,
                        "interactions",
                        lambda comment, number=number, kind=kind, subject_type=subject_type: self._normalize_comment(
                            target, comment, number, kind, subject_type
                        ),
                        target=target,
                        filter_item=lambda comment, timestamp_fields=timestamp_fields: in_window_or_malformed(
                            comment, request, *timestamp_fields
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

    @staticmethod
    def _commit_in_window(item: dict[str, Any], request: CollectionRequest) -> bool:
        if not isinstance(item, dict):
            return True
        commit = item.get("commit") or {}
        occurred_at = first_timestamp(commit.get("committer") or {}, "date") or first_timestamp(
            commit.get("author") or {}, "date"
        )
        if occurred_at is None:
            return True
        return in_window_or_malformed({"timestamp": occurred_at}, request, "timestamp")

    def _normalize_commit(self, target: RepositoryTarget, item: dict[str, Any]) -> dict[str, Any]:
        sha = item.get("sha")
        commit = item.get("commit")
        if not isinstance(commit, dict):
            raise ResponseShapeError(f"commit {sha} has no commit object")
        message = commit.get("message")
        if not isinstance(message, str) or not message.strip():
            raise ResponseShapeError(f"commit {sha} has no commit message")
        committer = commit.get("committer") if isinstance(commit.get("committer"), dict) else {}
        author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
        title = message.splitlines()[0].strip()
        return {
            "id": self._id(target, "commit", sha),
            "sha": sha,
            "repository_id": target.canonical_id,
            "occurred_at": first_timestamp(committer, "date") or first_timestamp(author, "date"),
            "title": title,
            "web_url": item.get("html_url"),
            "_native_id": sha,
            "_actor": actor_from(item, "author", "committer"),
            "_summary": title or f"Commit {sha}",
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
