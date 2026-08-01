from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from .base import (
    ACTIVITY_SOURCES,
    RESOURCE_SOURCES,
    CollectionRequest,
    ProviderDescriptor,
    ProviderNotReady,
    RepositoryTarget,
)
from .transport import (
    ApiError,
    JsonTransport,
    PageResult,
    ResponseShapeError,
    failure_class_for_status,
)


@dataclass
class SourceResult:
    items: list[dict[str, Any]] = field(default_factory=list)
    status: str = "supported"
    note: str = ""
    diagnostics: dict[str, Any] = field(default_factory=dict)


@dataclass
class RepositorySnapshot:
    repository: dict[str, Any] | None = None
    sources: dict[str, SourceResult] = field(default_factory=dict)


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def in_window(value: Any, request: CollectionRequest) -> bool:
    timestamp = parse_timestamp(value)
    start = parse_timestamp(request.window_start)
    end = parse_timestamp(request.window_end)
    if timestamp is None or start is None or end is None:
        return False
    return start <= timestamp.astimezone(start.tzinfo) < end.astimezone(start.tzinfo)


def first_timestamp(item: dict[str, Any], *fields: str) -> str | None:
    for field in fields:
        value = item.get(field)
        if isinstance(value, str) and value:
            return value
    return None


def actor_from(item: dict[str, Any], *fields: str) -> dict[str, Any] | None:
    for field in fields:
        value = item.get(field)
        if isinstance(value, dict):
            source_id = value.get("id") or value.get("node_id") or value.get("login") or value.get("username")
            if source_id is not None:
                return {
                    "source_id": str(source_id),
                    "handle": value.get("login") or value.get("username") or value.get("name"),
                }
    return None


def page_result_to_source(result: PageResult, source: str) -> SourceResult:
    if result.complete:
        return SourceResult(result.items, "supported", f"{result.pages} page(s)", result.diagnostics or {})
    return SourceResult(
        result.items,
        "incomplete",
        f"{source} pagination reached the configured page limit",
        result.diagnostics or {},
    )


def api_error_diagnostics(error: ApiError) -> dict[str, Any]:
    diagnostics: dict[str, Any] = {
        "attempts": error.attempts,
        "retryable": error.retryable,
    }
    failure_class = error.failure_class
    if failure_class is None:
        if isinstance(error, ResponseShapeError):
            failure_class = "malformed_response"
        elif error.status_code is not None:
            failure_class = failure_class_for_status(error.status_code)
        else:
            failure_class = "transport_error"
    diagnostics["failure_class"] = failure_class
    if error.status_code is not None:
        diagnostics["status_code"] = error.status_code
    if error.retry_after is not None:
        diagnostics["retry_after_seconds"] = error.retry_after
    if error.rate_limit:
        diagnostics["rate_limit"] = dict(error.rate_limit)
    return diagnostics


def merge_diagnostics(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Merge child-request diagnostics without losing distinct failure causes."""
    if not incoming:
        return

    def classes(value: Any) -> set[str]:
        if isinstance(value, str) and value:
            return {value}
        if isinstance(value, (list, tuple, set)):
            return {item for item in value if isinstance(item, str) and item}
        return set()

    failure_classes = (
        classes(target.get("failure_class"))
        | classes(target.get("failure_classes"))
        | classes(incoming.get("failure_class"))
        | classes(incoming.get("failure_classes"))
    )
    target.update(incoming)
    if len(failure_classes) == 1:
        target["failure_class"] = next(iter(failure_classes))
        target.pop("failure_classes", None)
    elif failure_classes:
        target.pop("failure_class", None)
        target["failure_classes"] = sorted(failure_classes)


class BundleBuilder:
    def __init__(self, request: CollectionRequest, descriptor: ProviderDescriptor) -> None:
        self.request = request
        self.descriptor = descriptor
        self.provider_id = f"provider:{descriptor.kind}:{request.instance}"
        self.bundle: dict[str, Any] = {
            "schema_version": "0.1",
            "run": {
                "run_id": f"run:{descriptor.kind}:{request.instance}",
                "window": {
                    "start": request.window_start,
                    "end": request.window_end,
                    "timezone": request.timezone,
                },
                "scope": {"repositories": list(request.repository_ids), "actors": list(request.actor_ids)},
            },
            "providers": [{
                "id": self.provider_id,
                "kind": descriptor.kind,
                "instance": request.instance,
                "capabilities": {},
            }],
            "repositories": [],
            "actors": [],
            "work_items": [],
            "change_requests": [],
            "interactions": [],
            "commits": [],
            "ref_changes": [],
            "releases": [],
            "evidence": [],
            "facts": [],
            "coverage": {
                "required_sources": list(RESOURCE_SOURCES),
                "observations": [],
                "fatal": [],
                "allow_publish": True,
            },
        }
        self._seen: dict[str, set[str]] = {key: set() for key in self.bundle if isinstance(self.bundle[key], list)}
        self._actor_ids: dict[str, str] = {}
        self._commit_ids_by_sha: dict[tuple[str, str], set[str]] = {}
        self._change_request_ids_by_sha: dict[tuple[str, str], set[str]] = {}

    def add_coverage(self, source: str, target: RepositoryTarget, result: SourceResult) -> None:
        observation = {
            "source": source,
            "provider_id": self.provider_id,
            "repository_id": target.canonical_id,
            "status": result.status,
        }
        if result.note:
            observation["note"] = result.note
        if result.diagnostics:
            observation["diagnostics"] = result.diagnostics
        self.bundle["coverage"]["observations"].append(observation)
        self.bundle["providers"][0]["capabilities"][source] = result.status
        if source in RESOURCE_SOURCES and result.status != "supported":
            self.bundle["coverage"]["allow_publish"] = False
            self.bundle["coverage"]["fatal"].append(
                f"{target.canonical_id}:{source}:{result.status}:{result.note}"
            )

    def add_repository(self, record: dict[str, Any]) -> None:
        self._add_entity("repositories", record)

    def add_records(
        self,
        category: str,
        records: list[dict[str, Any]],
        *,
        target: RepositoryTarget,
        fact_kind: str,
        default_section: str,
        evidence_source: str = "resource_api",
    ) -> None:
        for raw in records:
            record = dict(raw)
            actor = record.pop("_actor", None)
            summary = record.pop("_summary", None)
            section = record.pop("_section", default_section)
            association_shas = self._unique_strings(record.pop("_association_shas", []))
            commit_shas = self._unique_strings(record.pop("_commit_shas", []))
            explicit_change_request_ids = self._unique_strings(record.pop("_change_request_ids", []))
            association_attempted = bool(record.pop("_association_attempted", False))
            association_complete = bool(record.pop("_association_complete", False))
            occurred_at = record.get("occurred_at")
            entity_id = record.get("id")
            if not isinstance(entity_id, str) or not entity_id:
                continue
            actor_id = self._actor_id(actor)
            if self.request.actor_ids and actor is not None and actor_id not in self.request.actor_ids:
                continue
            if category == "change_requests":
                for sha in association_shas:
                    self._change_request_ids_by_sha.setdefault((target.canonical_id, sha), set()).add(entity_id)
            elif category == "commits":
                sha = record.get("sha")
                if isinstance(sha, str) and sha:
                    self._commit_ids_by_sha.setdefault((target.canonical_id, sha), set()).add(entity_id)
            elif category == "ref_changes":
                known_change_request_ids = [
                    change_request_id
                    for change_request_id in explicit_change_request_ids
                    if change_request_id in self._seen.get("change_requests", set())
                ]
                if association_attempted and len(known_change_request_ids) != len(explicit_change_request_ids):
                    association_complete = False
                if known_change_request_ids:
                    record["change_request_ids"] = known_change_request_ids
                if commit_shas:
                    record["commit_shas"] = commit_shas
                    commit_ids = sorted(
                        {
                            commit_id
                            for sha in commit_shas
                            for commit_id in self._commit_ids_by_sha.get((target.canonical_id, sha), set())
                        }
                    )
                    if commit_ids:
                        record["commit_ids"] = commit_ids
                record["change_association"] = self._associate_ref_change(
                    target,
                    commit_shas,
                    known_change_request_ids,
                    association_attempted=association_attempted,
                    association_complete=association_complete,
                )
            if actor_id:
                self._add_actor(actor)
            if actor_id:
                record["actor_id"] = actor_id
            self._add_entity(category, record)
            evidence_id = f"evidence:{category}:{entity_id}"
            evidence = {
                "id": evidence_id,
                "provider_id": self.provider_id,
                "subject_type": category[:-1] if category.endswith("s") else category,
                "subject_id": entity_id,
                "source": evidence_source,
            }
            if record.get("web_url"):
                evidence["url"] = record["web_url"]
            else:
                evidence["source_ref"] = f"{self.provider_id}:{category}:{entity_id}"
            self._add_entity("evidence", evidence)
            fact = {
                "id": f"fact:{category}:{entity_id}",
                "kind": fact_kind,
                "section": section,
                "repository_id": target.canonical_id,
                "occurred_at": occurred_at,
                "summary": summary or record.get("title") or record.get("name") or entity_id,
                "evidence_ids": [evidence_id],
            }
            if actor_id:
                fact["actor_id"] = actor_id
            self._add_entity("facts", fact)

    @staticmethod
    def _unique_strings(values: Any) -> list[str]:
        if not isinstance(values, (list, tuple, set)):
            return []
        return list(dict.fromkeys(value for value in values if isinstance(value, str) and value))

    def _associate_ref_change(
        self,
        target: RepositoryTarget,
        commit_shas: list[str],
        explicit_change_request_ids: list[str],
        *,
        association_attempted: bool = False,
        association_complete: bool = False,
    ) -> str:
        if association_attempted:
            if not commit_shas or not association_complete:
                return "unknown"
            if explicit_change_request_ids:
                return "linked" if len(explicit_change_request_ids) == 1 else "ambiguous"
            return "unlinked"
        if explicit_change_request_ids:
            return "linked" if len(explicit_change_request_ids) == 1 else "ambiguous"
        if not commit_shas:
            return "unknown"
        candidates: set[str] = set()
        unresolved = False
        for sha in commit_shas:
            matches = self._change_request_ids_by_sha.get((target.canonical_id, sha), set())
            if len(matches) > 1:
                return "ambiguous"
            if not matches:
                unresolved = True
            candidates.update(matches)
        if len(candidates) > 1:
            return "ambiguous"
        if unresolved or not candidates:
            return "unknown"
        return "linked"

    def _actor_id(self, actor: dict[str, Any] | None) -> str | None:
        if not isinstance(actor, dict) or actor.get("source_id") is None:
            return None
        source_id = str(actor["source_id"])
        return f"actor:{self.descriptor.kind}:{self.request.instance}:{source_id}"

    def _add_actor(self, actor: dict[str, Any] | None) -> str | None:
        actor_id = self._actor_id(actor)
        if actor_id is None:
            return None
        source_id = str(actor["source_id"])
        self._actor_ids.setdefault(
            source_id, f"actor:{self.descriptor.kind}:{self.request.instance}:{source_id}"
        )
        if actor_id not in self._seen["actors"]:
            self._add_entity(
                "actors",
                {
                    "id": actor_id,
                    "provider_id": self.provider_id,
                    "source_id": source_id,
                    "handle": actor.get("handle"),
                },
            )
        return actor_id

    def _add_entity(self, category: str, record: dict[str, Any]) -> None:
        entity_id = record.get("id")
        if not isinstance(entity_id, str) or not entity_id:
            return
        if entity_id in self._seen.setdefault(category, set()):
            return
        self._seen[category].add(entity_id)
        self.bundle[category].append(record)

    def finish(self) -> dict[str, Any]:
        return self.bundle


class ResourceProvider:
    descriptor: ProviderDescriptor

    def __init__(self, transport: JsonTransport, instance: str) -> None:
        self.transport = transport
        self.instance = instance

    def probe(self) -> dict[str, Any]:
        """Describe the adapter without turning implementation status into coverage."""
        return {
            **self.descriptor.as_dict(),
            "instance": self.instance,
        }

    def collect(self, request: CollectionRequest) -> dict[str, Any]:
        if request.provider_kind != self.descriptor.kind:
            raise ValueError(
                f"request provider {request.provider_kind!r} does not match {self.descriptor.kind!r}"
            )
        builder = BundleBuilder(request, self.descriptor)
        for target in request.repositories:
            snapshot = self._collect_repository(target, request)
            if snapshot.repository:
                builder.add_repository(snapshot.repository)
            for source in RESOURCE_SOURCES:
                if source == "repositories" and source not in snapshot.sources:
                    result = SourceResult(
                        [snapshot.repository] if snapshot.repository else [],
                        "supported" if snapshot.repository else "unavailable",
                        "repository resource observed" if snapshot.repository else "repository resource unavailable",
                    )
                else:
                    result = snapshot.sources.get(
                        source,
                        SourceResult([], "unavailable", "provider did not return this resource source"),
                    )
                builder.add_coverage(source, target, result)
                if source == "work_items":
                    builder.add_records("work_items", result.items, target=target, fact_kind="work_item_observed", default_section="project")
                elif source == "change_requests":
                    builder.add_records("change_requests", result.items, target=target, fact_kind="change_request_observed", default_section="change")
                elif source == "interactions":
                    builder.add_records("interactions", result.items, target=target, fact_kind="interaction_observed", default_section="project")
                elif source == "commits":
                    builder.add_records("commits", result.items, target=target, fact_kind="commit_observed", default_section="change")
                elif source == "releases":
                    builder.add_records("releases", result.items, target=target, fact_kind="release_observed", default_section="release")
            if request.include_activity_api:
                activity_sources = self._collect_activity(target, request)
            else:
                activity_sources = {
                    source: SourceResult([], "unavailable", "activity API disabled; push/ref completeness is not claimed")
                    for source in ACTIVITY_SOURCES
                }
            for source in ACTIVITY_SOURCES:
                result = activity_sources.get(
                    source,
                    SourceResult([], "unsupported", "provider did not return this activity source"),
                )
                builder.add_coverage(source, target, result)
                if source == "ref_changes":
                    builder.add_records(
                        "ref_changes",
                        result.items,
                        target=target,
                        fact_kind="ref_change_observed",
                        default_section="change",
                        evidence_source="activity_api",
                    )
        return builder.finish()

    def _normalize_items(
        self,
        result: SourceResult,
        source: str,
        normalizer: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> SourceResult:
        """Normalize valid records while turning malformed items into diagnostics."""
        normalized: list[dict[str, Any]] = []
        malformed_count = 0
        for item in result.items:
            try:
                normalized.append(normalizer(item))
            except (AttributeError, IndexError, KeyError, TypeError, ValueError, ResponseShapeError):
                malformed_count += 1
        result.items = normalized
        if malformed_count:
            result.status = "incomplete"
            note = f"{source} response contained {malformed_count} malformed item(s)"
            result.note = f"{result.note}; {note}" if result.note else note
            merge_diagnostics(
                result.diagnostics,
                {"failure_class": "malformed_response", "malformed_items": malformed_count},
            )
        return result

    def _safe_page(
        self,
        source: str,
        fetch: Callable[[], PageResult],
    ) -> SourceResult:
        try:
            result = fetch()
        except ApiError as exc:
            return SourceResult([], "incomplete", str(exc), api_error_diagnostics(exc))
        return SourceResult(
            result.items,
            "supported" if result.complete else "incomplete",
            f"{result.pages} page(s)" if result.complete else f"{source} pagination reached the configured page limit",
            result.diagnostics or {},
        )

    def _collect_repository(
        self, target: RepositoryTarget, request: CollectionRequest
    ) -> RepositorySnapshot:
        raise ProviderNotReady(f"{self.descriptor.kind} resource collector is not implemented")

    def _collect_activity(
        self, target: RepositoryTarget, request: CollectionRequest
    ) -> dict[str, SourceResult]:
        return {
            source: SourceResult([], "unsupported", "activity/ref collection is not implemented for this provider")
            for source in ACTIVITY_SOURCES
        }
