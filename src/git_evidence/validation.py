from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from importlib.resources import files
from typing import Any, Iterable
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from .model import COLLECTION_KEYS, collection
from .providers.base import ACTIVITY_SOURCES, RESOURCE_SOURCES

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
    "provider_not_ready",
    "unexpected_error",
    "unexpected_normalizer_error",
    "budget_exhausted",
}
KNOWN_COVERAGE_SOURCES = frozenset((*RESOURCE_SOURCES, *ACTIVITY_SOURCES))
SUBJECT_COLLECTIONS = {
    "provider": "providers",
    "repository": "repositories",
    "actor": "actors",
    "work_item": "work_items",
    "change_request": "change_requests",
    "interaction": "interactions",
    "commit": "commits",
    "ref_change": "ref_changes",
    "release": "releases",
}
FACT_SUBJECT_TYPES = tuple(SUBJECT_COLLECTIONS)
SCHEMA_RESOURCE = "schemas/evidence-bundle-0.1.schema.json"
RFC3339_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str


def _issue(issues: list[ValidationIssue], code: str, message: str) -> None:
    issues.append(ValidationIssue(code, message))


@lru_cache(maxsize=1)
def _schema_validator() -> Draft202012Validator:
    resource = files("git_evidence").joinpath(SCHEMA_RESOURCE)
    schema = json.loads(resource.read_text(encoding="utf-8"))
    checker = FormatChecker()

    @checker.checks("date-time")
    def _check_date_time(value: Any) -> bool:
        return (
            isinstance(value, str)
            and RFC3339_DATE_TIME.fullmatch(value) is not None
            and _parse_timestamp(value) is not None
        )

    @checker.checks("uri")
    def _check_uri(value: Any) -> bool:
        if not isinstance(value, str) or not value or any(character.isspace() for character in value):
            return False
        return bool(urlparse(value).scheme)

    return Draft202012Validator(schema, format_checker=checker)


def _schema_path(path: Iterable[Any]) -> str:
    rendered = "$"
    for part in path:
        if isinstance(part, int):
            rendered += f"[{part}]"
        else:
            rendered += f".{part}"
    return rendered


def _validate_schema(value: Any, issues: list[ValidationIssue]) -> None:
    try:
        validator = _schema_validator()
    except (OSError, json.JSONDecodeError, SchemaError) as exc:
        _issue(issues, "schema.load", f"cannot load canonical bundle schema: {exc}")
        return
    errors = sorted(
        validator.iter_errors(value),
        key=lambda error: (
            tuple(str(part) for part in error.absolute_path),
            str(error.validator),
            error.message,
        ),
    )
    for error in errors:
        _issue(
            issues,
            f"schema.{error.validator}",
            f"{_schema_path(error.absolute_path)}: {error.message}",
        )


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


def _validate_run(
    bundle: dict[str, Any], issues: list[ValidationIssue]
) -> tuple[set[str], set[str] | None]:
    run = bundle.get("run")
    if not isinstance(run, dict):
        _issue(issues, "run.missing", "run must be an object")
        return set(), None
    run_id = run.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        _issue(issues, "run.run_id", "run.run_id must be a non-empty string")
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
        return set(), None
    repositories = scope.get("repositories")
    if not isinstance(repositories, list) or not repositories or not all(
        isinstance(value, str) and value for value in repositories
    ):
        _issue(issues, "scope.repositories", "run.scope.repositories must be a non-empty id allowlist")
        return set(), None
    if len(repositories) != len(set(repositories)):
        _issue(issues, "scope.repositories_duplicate", "run.scope.repositories must not contain duplicate IDs")
    actors = scope.get("actors", [])
    if not isinstance(actors, list) or not all(isinstance(value, str) and value for value in actors):
        _issue(issues, "scope.actors", "run.scope.actors must be an array of non-empty actor IDs")
        actor_ids: set[str] | None = None
    elif len(actors) != len(set(actors)):
        _issue(issues, "scope.actors_duplicate", "run.scope.actors must not contain duplicate IDs")
        actor_ids = set(actors)
    else:
        actor_ids = set(actors)
    return set(repositories), actor_ids


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
            if not isinstance(evidence_id, str) or evidence_id not in evidence:
                _issue(issues, "fact.evidence_ref", f"fact {fact_id} references missing evidence {evidence_id}")
                continue
            _validate_fact_evidence_subject(
                fact_id,
                fact,
                evidence[evidence_id],
                indexes,
                issues,
            )
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
            if not isinstance(commit_id, str) or commit_id not in commits:
                _issue(
                    issues,
                    "ref_change.commit_ref",
                    f"ref_change {ref_change_id} references missing commit {commit_id}",
                )


def _inferred_fact_subject_type(fact: dict[str, Any]) -> str | None:
    explicit_type = fact.get("subject_type")
    if explicit_type is not None:
        return explicit_type if isinstance(explicit_type, str) else None
    kind = fact.get("kind")
    if not isinstance(kind, str):
        return None
    for subject_type in sorted(FACT_SUBJECT_TYPES, key=len, reverse=True):
        if kind == subject_type or kind.startswith(f"{subject_type}_"):
            return subject_type
    return None


def _validate_fact_evidence_subject(
    fact_id: str,
    fact: dict[str, Any],
    evidence: dict[str, Any],
    indexes: dict[str, dict[str, dict[str, Any]]],
    issues: list[ValidationIssue],
) -> None:
    fact_subject_type = fact.get("subject_type")
    fact_subject_id = fact.get("subject_id")
    if (fact_subject_type is None) != (fact_subject_id is None):
        _issue(
            issues,
            "fact.subject",
            f"fact {fact_id} must provide both subject_type and subject_id",
        )
    if fact_subject_type is not None and (
        not isinstance(fact_subject_type, str) or not fact_subject_type
    ):
        _issue(issues, "fact.subject", f"fact {fact_id} has an invalid subject_type")
    if fact_subject_id is not None and (
        not isinstance(fact_subject_id, str) or not fact_subject_id
    ):
        _issue(issues, "fact.subject", f"fact {fact_id} has an invalid subject_id")

    expected_type = _inferred_fact_subject_type(fact)
    expected_id = fact_subject_id if isinstance(fact_subject_id, str) and fact_subject_id else None
    subject_type = evidence.get("subject_type")
    subject_id = evidence.get("subject_id")
    if subject_type is None and subject_id is None:
        return
    if not isinstance(subject_type, str) or not subject_type:
        _issue(
            issues,
            "fact.evidence_subject",
            f"fact {fact_id} evidence {evidence.get('id')} has an invalid subject_type",
        )
        return
    if not isinstance(subject_id, str) or not subject_id:
        _issue(
            issues,
            "fact.evidence_subject",
            f"fact {fact_id} evidence {evidence.get('id')} has an invalid subject_id",
        )
        return
    if expected_type is not None and subject_type != expected_type:
        _issue(
            issues,
            "fact.evidence_subject",
            f"fact {fact_id} evidence {evidence.get('id')} subject_type "
            f"{subject_type!r} does not match {expected_type!r}",
        )
    if expected_id is not None and subject_id != expected_id:
        _issue(
            issues,
            "fact.evidence_subject",
            f"fact {fact_id} evidence {evidence.get('id')} subject_id "
            f"{subject_id!r} does not match {expected_id!r}",
        )

    collection_key = SUBJECT_COLLECTIONS.get(subject_type)
    if collection_key is None:
        _issue(
            issues,
            "fact.evidence_subject",
            f"fact {fact_id} evidence {evidence.get('id')} has unknown subject_type {subject_type!r}",
        )
        return
    subject = indexes.get(collection_key, {}).get(subject_id)
    if subject is None:
        _issue(
            issues,
            "fact.evidence_subject_ref",
            f"fact {fact_id} evidence {evidence.get('id')} references missing "
            f"{subject_type} {subject_id}",
        )
        return

    fact_repository_id = fact.get("repository_id")
    subject_repository_id = subject.get("repository_id")
    if isinstance(fact_repository_id, str) and fact_repository_id:
        if subject_type == "repository":
            repository_matches = subject_id == fact_repository_id
        else:
            repository_matches = subject_repository_id == fact_repository_id
        if not repository_matches:
            _issue(
                issues,
                "fact.evidence_repository",
                f"fact {fact_id} evidence {evidence.get('id')} subject is outside "
                f"the fact repository {fact_repository_id}",
            )


def _validate_scope(
    indexes: dict[str, dict[str, dict[str, Any]]],
    scope_repository_ids: set[str],
    scope_actor_ids: set[str] | None,
    issues: list[ValidationIssue],
) -> None:
    repositories = indexes.get("repositories", {})
    for repository_id in sorted(set(repositories) - scope_repository_ids):
        _issue(issues, "scope.entity_outside", f"repositories {repository_id} is outside the repository allowlist")
    missing = scope_repository_ids - set(repositories)
    for repository_id in sorted(missing):
        _issue(issues, "scope.repository_missing", f"allowlisted repository is not in bundle: {repository_id}")
    actors = indexes.get("actors", {})
    if scope_actor_ids:
        for actor_id in sorted(set(actors) - scope_actor_ids):
            _issue(issues, "scope.actor_outside", f"actor {actor_id} is outside the actor allowlist")
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
            if not isinstance(repository_id, str) or not repository_id:
                _issue(issues, "scope.entity_repository_missing", f"{key} {entity_id} has no repository_id")
            elif repository_id not in scope_repository_ids:
                _issue(issues, "scope.entity_outside", f"{key} {entity_id} is outside the repository allowlist")
            actor_id = item.get("actor_id")
            if actor_id is None:
                continue
            if not isinstance(actor_id, str) or not actor_id:
                _issue(issues, "scope.actor_ref_invalid", f"{key} {entity_id} has an invalid actor_id")
            else:
                if actor_id not in actors:
                    _issue(issues, "scope.actor_ref_missing", f"{key} {entity_id} references missing actor {actor_id}")
                if scope_actor_ids and actor_id not in scope_actor_ids:
                    _issue(issues, "scope.actor_outside", f"{key} {entity_id} has an actor outside the actor allowlist")


def _validate_coverage(
    bundle: dict[str, Any],
    scope_repository_ids: set[str],
    issues: list[ValidationIssue],
    required_sources_contract: Iterable[str],
) -> None:
    coverage = bundle.get("coverage")
    if not isinstance(coverage, dict):
        _issue(issues, "coverage.missing", "coverage must be an object")
        return
    required_sources = coverage.get("required_sources")
    observations = coverage.get("observations")
    if not isinstance(required_sources, list) or not all(
        isinstance(value, str) and value for value in required_sources
    ):
        _issue(issues, "coverage.required_sources", "coverage.required_sources must be an array of strings")
        required_sources = []
    else:
        if not required_sources:
            _issue(issues, "coverage.required_sources_empty", "coverage.required_sources must not be empty")
        if len(required_sources) != len(set(required_sources)):
            _issue(issues, "coverage.required_sources_duplicate", "coverage.required_sources must not contain duplicates")
        unknown_sources = sorted(set(required_sources) - KNOWN_COVERAGE_SOURCES)
        if unknown_sources:
            _issue(
                issues,
                "coverage.required_source_unknown",
                "coverage.required_sources contains unknown sources: " + ", ".join(unknown_sources),
            )
            required_sources = [source for source in required_sources if source in KNOWN_COVERAGE_SOURCES]
        missing_contract_sources = sorted(
            set(required_sources_contract) - set(required_sources)
        )
        if missing_contract_sources:
            _issue(
                issues,
                "coverage.required_source_contract",
                "coverage.required_sources omits required contract sources: "
                + ", ".join(missing_contract_sources),
            )
    if not isinstance(observations, list):
        _issue(issues, "coverage.observations", "coverage.observations must be an array")
        observations = []
    group_failures = coverage.get("group_failures", [])
    if not isinstance(group_failures, list):
        _issue(issues, "coverage.group_failures_shape", "coverage.group_failures must be an array")
        group_failures = []
    for position, failure in enumerate(group_failures):
        if not isinstance(failure, dict):
            _issue(issues, "coverage.group_failure_shape", f"coverage.group_failures[{position}] must be an object")
            continue
        for field in ("provider", "instance", "repository", "source", "failure_class"):
            if not isinstance(failure.get(field), str) or not failure[field]:
                _issue(
                    issues,
                    "coverage.group_failure_field",
                    f"coverage.group_failures[{position}].{field} must be a non-empty string",
                )
        if failure.get("failure_class") not in FAILURE_CLASSES:
            _issue(
                issues,
                "coverage.group_failure_class",
                f"coverage.group_failures[{position}] has invalid failure_class: {failure.get('failure_class')!r}",
            )
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
                if failure_class is not None and (
                    not isinstance(failure_class, str) or failure_class not in FAILURE_CLASSES
                ):
                    _issue(
                        issues,
                        "coverage.failure_class",
                        f"coverage {source} has invalid failure_class: {failure_class!r}",
                    )
                failure_classes = diagnostics.get("failure_classes")
                if failure_classes is not None and (
                    not isinstance(failure_classes, list)
                    or not failure_classes
                    or any(
                        not isinstance(value, str) or value not in FAILURE_CLASSES
                        for value in failure_classes
                    )
                ):
                    _issue(
                        issues,
                        "coverage.failure_classes",
                        f"coverage {source} has invalid failure_classes: {failure_classes!r}",
                    )
        repository_id = observation.get("repository_id")
        if repository_id is not None and (
            not isinstance(repository_id, str) or repository_id not in scope_repository_ids
        ):
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


def validate_bundle(
    bundle: dict[str, Any],
    *,
    required_sources_contract: Iterable[str] | None = None,
) -> list[ValidationIssue]:
    """Validate deterministic invariants; an empty list means publishable."""
    issues: list[ValidationIssue] = []
    _validate_schema(bundle, issues)
    if not isinstance(bundle, dict):
        return issues
    if bundle.get("schema_version") != "0.1":
        _issue(issues, "schema.version", "schema_version must be '0.1'")
    indexes = _validate_ids(bundle, issues)
    scope_repository_ids, scope_actor_ids = _validate_run(bundle, issues)
    _validate_scope(indexes, scope_repository_ids, scope_actor_ids, issues)
    _validate_evidence(indexes, issues)
    contract = (
        tuple(RESOURCE_SOURCES)
        if required_sources_contract is None
        else tuple(required_sources_contract)
    )
    _validate_coverage(bundle, scope_repository_ids, issues, contract)
    run = bundle.get("run")
    window = run.get("window") if isinstance(run, dict) else None
    window_start = _parse_timestamp(window.get("start")) if isinstance(window, dict) else None
    window_end = _parse_timestamp(window.get("end")) if isinstance(window, dict) else None
    for key in COLLECTION_KEYS:
        for entity_id, item in indexes.get(key, {}).items():
            if "occurred_at" not in item:
                continue
            occurred_at = item.get("occurred_at")
            parsed_at = _parse_timestamp(occurred_at)
            if parsed_at is None:
                _issue(issues, "entity.timestamp", f"{key} {entity_id} has an invalid occurred_at")
            elif (
                window_start is not None
                and window_end is not None
                and not window_start <= parsed_at < window_end
            ):
                _issue(
                    issues,
                    "entity.timestamp_window",
                    f"{key} {entity_id} occurred_at must be within "
                    f"[{window.get('start')}, {window.get('end')})",
                )
    for entity_id, item in indexes.get("ref_changes", {}).items():
        association = item.get("change_association")
        if not isinstance(association, str) or association not in ASSOCIATION_STATES:
            _issue(issues, "association.state", f"ref_change {entity_id} has invalid change_association")
    return issues


def format_issues(issues: Iterable[ValidationIssue]) -> str:
    return "\n".join(f"ERROR: {item.code}: {item.message}" for item in issues)
