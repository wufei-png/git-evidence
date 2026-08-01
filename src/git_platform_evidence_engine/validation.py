from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable
from urllib.parse import urlparse

from .model import COLLECTION_KEYS, collection

CAPABILITY_STATES = {"supported", "unsupported", "unavailable", "incomplete"}
ASSOCIATION_STATES = {"linked", "unlinked", "ambiguous", "unknown"}
FAILURE_CLASSES = {
    "permission_denied",
    "rate_limited",
    "service_error",
    "not_found",
    "request_rejected",
    "malformed_response",
    "network_error",
    "transport_error",
    "fixture_missing",
    "http_error",
}


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str


def _issue(issues: list[ValidationIssue], code: str, message: str) -> None:
    issues.append(ValidationIssue(code, message))


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _validate_ids(
    bundle: dict[str, Any], issues: list[ValidationIssue]
) -> dict[str, dict[str, dict[str, Any]]]:
    indexes: dict[str, dict[str, dict[str, Any]]] = {}
    for key in COLLECTION_KEYS:
        value = bundle.get(key)
        if not isinstance(value, list):
            _issue(issues, "collection.shape", f"{key} must be an array")
            indexes[key] = {}
            continue
        index: dict[str, dict[str, Any]] = {}
        for position, item in enumerate(value):
            if not isinstance(item, dict):
                _issue(issues, "entity.shape", f"{key}[{position}] must be an object")
                continue
            entity_id = item.get("id")
            if not isinstance(entity_id, str) or not entity_id:
                _issue(issues, "entity.id", f"{key}[{position}] is missing a non-empty id")
                continue
            if entity_id in index:
                _issue(issues, "entity.duplicate_id", f"duplicate {key} id: {entity_id}")
                continue
            index[entity_id] = item
        indexes[key] = index
    return indexes


def _validate_run(bundle: dict[str, Any], issues: list[ValidationIssue]) -> set[str]:
    run = bundle.get("run")
    if not isinstance(run, dict):
        _issue(issues, "run.missing", "run must be an object")
        return set()
    window = run.get("window")
    if not isinstance(window, dict):
        _issue(issues, "window.missing", "run.window must be an object")
    else:
        start = _parse_timestamp(window.get("start"))
        end = _parse_timestamp(window.get("end"))
        if start is None or end is None:
            _issue(issues, "window.timestamp", "window start/end must be timezone-aware ISO timestamps")
        elif start >= end:
            _issue(issues, "window.order", "window start must be before end")
        if not isinstance(window.get("timezone"), str) or not window["timezone"]:
            _issue(issues, "window.timezone", "window.timezone must be non-empty")
    scope = run.get("scope")
    if not isinstance(scope, dict):
        _issue(issues, "scope.missing", "run.scope must be an object")
        return set()
    repositories = scope.get("repositories")
    if not isinstance(repositories, list) or not repositories or not all(
        isinstance(value, str) and value for value in repositories
    ):
        _issue(issues, "scope.repositories", "run.scope.repositories must be a non-empty id allowlist")
        return set()
    return set(repositories)


def _validate_evidence(
    indexes: dict[str, dict[str, dict[str, Any]]], issues: list[ValidationIssue]
) -> None:
    evidence = indexes.get("evidence", {})
    for evidence_id, item in evidence.items():
        url = item.get("url")
        source_ref = item.get("source_ref")
        if not url and not source_ref:
            _issue(issues, "evidence.reference", f"evidence {evidence_id} has no url or source_ref")
        if url:
            parsed = urlparse(str(url))
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                _issue(issues, "evidence.url", f"evidence {evidence_id} has an invalid URL")
    for fact_id, fact in indexes.get("facts", {}).items():
        evidence_ids = fact.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids:
            _issue(issues, "fact.evidence", f"fact {fact_id} has no evidence_ids")
            continue
        for evidence_id in evidence_ids:
            if evidence_id not in evidence:
                _issue(issues, "fact.evidence_ref", f"fact {fact_id} references missing evidence {evidence_id}")
    commits = indexes.get("commits", {})
    change_requests = indexes.get("change_requests", {})
    for ref_change_id, ref_change in indexes.get("ref_changes", {}).items():
        change_request_ids = ref_change.get("change_request_ids")
        if change_request_ids is not None:
            if not isinstance(change_request_ids, list) or not all(
                isinstance(value, str) for value in change_request_ids
            ):
                _issue(
                    issues,
                    "ref_change.change_request_ids",
                    f"ref_change {ref_change_id} has invalid change_request_ids",
                )
            else:
                for change_request_id in change_request_ids:
                    if change_request_id not in change_requests:
                        _issue(
                            issues,
                            "ref_change.change_request_ref",
                            f"ref_change {ref_change_id} references missing change request {change_request_id}",
                        )
        commit_ids = ref_change.get("commit_ids")
        if commit_ids is None:
            continue
        if not isinstance(commit_ids, list) or not all(isinstance(value, str) for value in commit_ids):
            _issue(issues, "ref_change.commit_ids", f"ref_change {ref_change_id} has invalid commit_ids")
            continue
        for commit_id in commit_ids:
            if commit_id not in commits:
                _issue(
                    issues,
                    "ref_change.commit_ref",
                    f"ref_change {ref_change_id} references missing commit {commit_id}",
                )


def _validate_scope(
    indexes: dict[str, dict[str, dict[str, Any]]],
    scope_repository_ids: set[str],
    issues: list[ValidationIssue],
) -> None:
    repositories = indexes.get("repositories", {})
    missing = scope_repository_ids - set(repositories)
    for repository_id in sorted(missing):
        _issue(issues, "scope.repository_missing", f"allowlisted repository is not in bundle: {repository_id}")
    for key in (
        "work_items",
        "change_requests",
        "interactions",
        "commits",
        "ref_changes",
        "releases",
        "facts",
    ):
        for entity_id, item in indexes.get(key, {}).items():
            repository_id = item.get("repository_id")
            if repository_id and repository_id not in scope_repository_ids:
                _issue(issues, "scope.entity_outside", f"{key} {entity_id} is outside the repository allowlist")


def _validate_coverage(
    bundle: dict[str, Any],
    scope_repository_ids: set[str],
    issues: list[ValidationIssue],
) -> None:
    coverage = bundle.get("coverage")
    if not isinstance(coverage, dict):
        _issue(issues, "coverage.missing", "coverage must be an object")
        return
    required_sources = coverage.get("required_sources")
    observations = coverage.get("observations")
    if not isinstance(required_sources, list) or not all(isinstance(value, str) for value in required_sources):
        _issue(issues, "coverage.required_sources", "coverage.required_sources must be an array of strings")
        required_sources = []
    if not isinstance(observations, list):
        _issue(issues, "coverage.observations", "coverage.observations must be an array")
        observations = []
    by_source_repository: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for position, observation in enumerate(observations):
        if not isinstance(observation, dict):
            _issue(issues, "coverage.observation_shape", f"coverage.observations[{position}] must be an object")
            continue
        source = observation.get("source")
        state = observation.get("status")
        if not isinstance(source, str) or not source:
            _issue(issues, "coverage.observation_source", f"coverage observation {position} has no source")
            continue
        if state not in CAPABILITY_STATES:
            _issue(issues, "coverage.observation_status", f"coverage {source} has invalid status: {state!r}")
        diagnostics = observation.get("diagnostics")
        if diagnostics is not None:
            if not isinstance(diagnostics, dict):
                _issue(issues, "coverage.diagnostics_shape", f"coverage {source} diagnostics must be an object")
            else:
                failure_class = diagnostics.get("failure_class")
                if failure_class is not None and failure_class not in FAILURE_CLASSES:
                    _issue(
                        issues,
                        "coverage.failure_class",
                        f"coverage {source} has invalid failure_class: {failure_class!r}",
                    )
                failure_classes = diagnostics.get("failure_classes")
                if failure_classes is not None and (
                    not isinstance(failure_classes, list)
                    or not failure_classes
                    or any(value not in FAILURE_CLASSES for value in failure_classes)
                ):
                    _issue(
                        issues,
                        "coverage.failure_classes",
                        f"coverage {source} has invalid failure_classes: {failure_classes!r}",
                    )
        repository_id = observation.get("repository_id")
        if repository_id is not None and repository_id not in scope_repository_ids:
            _issue(
                issues,
                "coverage.repository_outside",
                f"coverage {source} references repository outside the allowlist: {repository_id}",
            )
        if isinstance(repository_id, str) and repository_id:
            by_source_repository.setdefault((source, repository_id), []).append(observation)
    for source in required_sources:
        for repository_id in sorted(scope_repository_ids):
            matches = by_source_repository.get((source, repository_id), [])
            if not matches:
                _issue(
                    issues,
                    "coverage.required_missing",
                    f"required source has no observation: {source} for {repository_id}",
                )
                continue
            for observation in matches:
                if observation.get("status") != "supported":
                    _issue(
                        issues,
                        "coverage.required_incomplete",
                        f"required source is not supported: {source} for {repository_id}={observation.get('status')}",
                    )
    fatal = coverage.get("fatal")
    if not isinstance(fatal, list):
        _issue(issues, "coverage.fatal_shape", "coverage.fatal must be an array")
    elif fatal:
        _issue(issues, "coverage.fatal", f"coverage contains fatal observations: {len(fatal)}")
    if coverage.get("allow_publish") is not True:
        _issue(issues, "coverage.publish_blocked", "coverage.allow_publish is not true")


def validate_bundle(bundle: dict[str, Any]) -> list[ValidationIssue]:
    """Validate deterministic invariants; an empty list means publishable."""
    issues: list[ValidationIssue] = []
    if bundle.get("schema_version") != "0.1":
        _issue(issues, "schema.version", "schema_version must be '0.1'")
    indexes = _validate_ids(bundle, issues)
    scope_repository_ids = _validate_run(bundle, issues)
    _validate_scope(indexes, scope_repository_ids, issues)
    _validate_evidence(indexes, issues)
    _validate_coverage(bundle, scope_repository_ids, issues)
    for key in ("work_items", "change_requests", "interactions", "commits", "ref_changes", "releases", "facts"):
        for entity_id, item in indexes.get(key, {}).items():
            occurred_at = item.get("occurred_at")
            if occurred_at is not None and _parse_timestamp(occurred_at) is None:
                _issue(issues, "entity.timestamp", f"{key} {entity_id} has an invalid occurred_at")
    for entity_id, item in indexes.get("ref_changes", {}).items():
        association = item.get("change_association")
        if association not in ASSOCIATION_STATES:
            _issue(issues, "association.state", f"ref_change {entity_id} has invalid change_association")
    return issues


def format_issues(issues: Iterable[ValidationIssue]) -> str:
    return "\n".join(f"ERROR: {item.code}: {item.message}" for item in issues)
