from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from importlib.resources import files
from typing import Any, cast
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from .identity import (
    IdentityError,
    compute_bundle_digest,
    compute_plan_id,
    normalize_plan,
)
from .model import COLLECTION_KEYS
from .privacy import iter_privacy_violations, iter_privacy_warnings
from .providers.base import (
    ACTIVITY_SOURCES,
    OPERATIONAL_FAILURE_CLASSES,
    OPTIONAL_COVERAGE_WARNING_CODE,
    RESOURCE_SOURCES,
    RepositoryTarget,
    canonical_warning_message,
    git_object_id_algorithm,
    is_verifiable_sha,
    merge_capability_status,
    validate_instance,
    validate_timezone,
)
from .providers.resource_base import repository_url_matches_target
from .time import TimeValueError, parse_instant

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
    "budget_exhausted",
    "insecure_transport",
    "limit_exceeded",
    "privacy_violation",
}
KNOWN_COVERAGE_SOURCES = frozenset((*RESOURCE_SOURCES, *ACTIVITY_SOURCES))
BLOCKER_CODES = {
    "aggregate_record_failure",
    "duplicate_records",
    "privacy_violation",
    "required_source_failure",
    "required_source_incomplete",
}
PAGINATION_OUTCOMES = {
    "cursor_exhausted": True,
    "link_exhausted": True,
    "documented_short_page": True,
    "date_boundary_reached": True,
    "max_pages_reached": False,
    "cycle_detected": False,
}
PAGINATED_COVERAGE_SOURCES = frozenset(RESOURCE_SOURCES) - {"repositories"}
PROVIDER_PAGINATION_OUTCOMES = {
    "github": "link_exhausted",
    "gitee": "link_exhausted",
    "gitlab": "cursor_exhausted",
}
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
SCHEMA_RESOURCES = {
    "0.3": "schemas/evidence-bundle-0.3.schema.json",
}
RFC3339_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def _diagnostic_failure_classes(value: Any) -> set[str]:
    classes: set[str] = set()
    if isinstance(value, dict):
        failure_class = value.get("failure_class")
        if isinstance(failure_class, str) and failure_class:
            classes.add(failure_class)
        failure_classes = value.get("failure_classes")
        if isinstance(failure_classes, (list, tuple, set)):
            classes.update(
                item for item in failure_classes if isinstance(item, str) and item
            )
        for child in value.values():
            classes.update(_diagnostic_failure_classes(child))
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            classes.update(_diagnostic_failure_classes(child))
    return classes


def _required_core_coverage_missing(
    coverage: dict[str, Any],
    *,
    repository_ids: Iterable[str] | None = None,
    provider_ids_by_repository: Mapping[str, str] | None = None,
) -> bool:
    required_sources = coverage.get("required_sources")
    if not isinstance(required_sources, list) or any(
        source not in required_sources for source in RESOURCE_SOURCES
    ):
        return True
    observations = coverage.get("observations")
    if not isinstance(observations, list):
        return True
    if repository_ids is None:
        return any(
            not any(
                isinstance(observation, dict) and observation.get("source") == source
                for observation in observations
            )
            for source in RESOURCE_SOURCES
        )
    for repository_id in repository_ids:
        expected_provider_id = (
            provider_ids_by_repository.get(repository_id)
            if provider_ids_by_repository is not None
            else None
        )
        for source in RESOURCE_SOURCES:
            if not any(
                isinstance(observation, dict)
                and observation.get("source") == source
                and observation.get("repository_id") == repository_id
                and (
                    expected_provider_id is None
                    or observation.get("provider_id") == expected_provider_id
                )
                and observation.get("status") == "supported"
                for observation in observations
            ):
                return True
    return False


def has_blocking_core_coverage(
    coverage: Any,
    *,
    repository_ids: Iterable[str] | None = None,
    provider_ids_by_repository: Mapping[str, str] | None = None,
) -> bool:
    """Return whether required core coverage is missing or failed closed."""
    if not isinstance(coverage, dict):
        return True
    if _required_core_coverage_missing(
        coverage,
        repository_ids=repository_ids,
        provider_ids_by_repository=provider_ids_by_repository,
    ):
        return True
    fatal = coverage.get("fatal")
    if isinstance(fatal, list) and fatal:
        return True
    for observation in coverage.get("observations", []):
        if (
            isinstance(observation, dict)
            and observation.get("source") in (*RESOURCE_SOURCES, *ACTIVITY_SOURCES)
            and (
                (
                    observation.get("source") in RESOURCE_SOURCES
                    and (
                        observation.get("status") != "supported"
                        or bool(
                            _diagnostic_failure_classes(observation.get("diagnostics"))
                            & OPERATIONAL_FAILURE_CLASSES
                        )
                    )
                )
                or (
                    observation.get("source") in ACTIVITY_SOURCES
                    and "privacy_violation"
                    in _diagnostic_failure_classes(observation.get("diagnostics"))
                )
            )
        ):
            return True
    for failure in coverage.get("group_failures", []):
        if isinstance(failure, dict) and failure.get("source") in RESOURCE_SOURCES:
            return True
    return False


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str
    severity: str
    path: str
    scope: str
    remediation: str

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "path": self.path,
            "scope": self.scope,
            "message": self.message,
            "remediation": self.remediation,
        }


def _issue(
    issues: list[ValidationIssue],
    code: str,
    message: str,
    *,
    severity: str = "error",
    path: str | None = None,
    scope: str | None = None,
    remediation: str | None = None,
) -> None:
    area = code.split(".", 1)[0]
    default_paths = {
        "schema": "$",
        "run": "$.run",
        "window": "$.run.window",
        "scope": "$.run.scope",
        "coverage": "$.coverage",
        "privacy": "$.privacy",
        "collection": "$.collection",
        "commit": "$.commits",
        "interaction": "$.interactions",
        "association": "$.ref_changes",
        "evidence": "$.evidence",
        "entity": "$",
        "provenance": "$",
    }
    issues.append(
        ValidationIssue(
            code=code,
            message=message,
            severity=severity,
            path=path or default_paths.get(area, "$"),
            scope=scope or area,
            remediation=remediation
            or "Correct the referenced bundle field and regenerate the evidence bundle.",
        )
    )


@lru_cache(maxsize=len(SCHEMA_RESOURCES))
def _schema_validator(schema_version: str) -> Draft202012Validator:
    resource_name = SCHEMA_RESOURCES.get(schema_version)
    if resource_name is None:
        raise ValueError(f"unsupported schema_version: {schema_version!r}")
    resource = files("git_evidence").joinpath(resource_name)
    schema = json.loads(resource.read_text(encoding="utf-8"))
    checker = FormatChecker()

    @checker.checks("date-time")
    def _check_date_time(value: Any) -> bool:
        if not isinstance(value, str):
            return True
        return (
            RFC3339_DATE_TIME.fullmatch(value) is not None
            and _parse_timestamp(value) is not None
        )

    @checker.checks("uri")
    def _check_uri(value: Any) -> bool:
        if not isinstance(value, str):
            return True
        if not value or any(character.isspace() for character in value):
            return False
        return bool(urlparse(value).scheme)

    return Draft202012Validator(schema, format_checker=checker)


@lru_cache(maxsize=1)
def _provider_fragment_schema_validator() -> Draft202012Validator:
    """Project the canonical 0.3 record schemas onto the internal fragment."""
    canonical = _schema_validator("0.3")
    canonical_schema = cast(dict[str, Any], canonical.schema)
    canonical_properties = canonical_schema["properties"]
    fragment_properties = {
        "fragment_version": {"const": "0.3"},
        "window": canonical_schema["$defs"]["window"],
        "scope": canonical_schema["$defs"]["scope"],
        **{
            key: canonical_properties[key]
            for key in (*COLLECTION_KEYS, "retrievals", "assertions")
        },
        "collection": canonical_properties["collection"],
        "privacy": canonical_properties["privacy"],
        "coverage": canonical_properties["coverage"],
    }
    fragment_schema = {
        "$schema": canonical_schema["$schema"],
        "type": "object",
        "additionalProperties": False,
        "required": [key for key in fragment_properties if key != "privacy"],
        "properties": fragment_properties,
        "$defs": canonical_schema["$defs"],
    }
    return cast(Draft202012Validator, canonical.evolve(schema=fragment_schema))


def _schema_path(path: Iterable[Any]) -> str:
    rendered = "$"
    for part in path:
        if isinstance(part, int):
            rendered += f"[{part}]"
        else:
            rendered += f".{part}"
    return rendered


def _validate_schema(
    value: Any,
    issues: list[ValidationIssue],
    *,
    schema_version: str,
) -> None:
    try:
        validator = _schema_validator(schema_version)
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
            path=_schema_path(error.absolute_path),
            remediation="Emit a bundle that conforms to the canonical JSON Schema.",
        )


def _validate_provider_fragment_schema(
    value: Any, issues: list[ValidationIssue]
) -> None:
    try:
        validator = _provider_fragment_schema_validator()
    except (OSError, json.JSONDecodeError, SchemaError, KeyError) as exc:
        _issue(issues, "schema.load", f"cannot load provider fragment schema: {exc}")
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
            path=_schema_path(error.absolute_path),
            remediation="Emit a provider fragment that conforms to Schema 0.3 record shapes.",
        )


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return parse_instant(value)
    except TimeValueError:
        return None


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
                _issue(
                    issues, "entity.id", f"{key}[{position}] is missing a non-empty id"
                )
                continue
            if entity_id in index:
                _issue(
                    issues, "entity.duplicate_id", f"duplicate {key} id: {entity_id}"
                )
                continue
            index[entity_id] = item
        indexes[key] = index
    return indexes


def _validate_plan_scope(
    bundle: dict[str, Any], issues: list[ValidationIssue]
) -> tuple[set[str], set[str] | None]:
    plan = bundle.get("plan")
    if not isinstance(plan, dict):
        _issue(issues, "plan.missing", "plan must be an object", path="$.plan")
        return set(), None
    window = plan.get("window")
    if not isinstance(window, dict):
        _issue(
            issues,
            "window.missing",
            "plan.window must be an object",
            path="$.plan.window",
        )
    else:
        start = _parse_timestamp(window.get("start"))
        end = _parse_timestamp(window.get("end"))
        if start is None or end is None:
            _issue(
                issues,
                "window.timestamp",
                "window start/end must be timezone-aware ISO timestamps",
            )
        elif start >= end:
            _issue(issues, "window.order", "window start must be before end")
        try:
            validate_timezone(window.get("timezone"))
        except ValueError as exc:
            _issue(issues, "window.timezone", str(exc), path="$.plan.window.timezone")
    scope = plan.get("scope")
    if not isinstance(scope, dict):
        _issue(
            issues, "scope.missing", "plan.scope must be an object", path="$.plan.scope"
        )
        return set(), None
    repositories = scope.get("repositories")
    if (
        not isinstance(repositories, list)
        or not repositories
        or not all(isinstance(value, str) and value for value in repositories)
    ):
        _issue(
            issues,
            "scope.repositories",
            "plan.scope.repositories must be a non-empty id allowlist",
        )
        return set(), None
    if len(repositories) != len(set(repositories)):
        _issue(
            issues,
            "scope.repositories_duplicate",
            "run.scope.repositories must not contain duplicate IDs",
        )
    actors = scope.get("actors", [])
    if not isinstance(actors, list) or not all(
        isinstance(value, str) and value for value in actors
    ):
        _issue(
            issues,
            "scope.actors",
            "run.scope.actors must be an array of non-empty actor IDs",
        )
        actor_ids: set[str] | None = None
    elif len(actors) != len(set(actors)):
        _issue(
            issues,
            "scope.actors_duplicate",
            "run.scope.actors must not contain duplicate IDs",
        )
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
            _issue(
                issues,
                "evidence.reference",
                f"evidence {evidence_id} has no url or source_ref",
            )
        if url:
            parsed = urlparse(str(url))
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                _issue(
                    issues, "evidence.url", f"evidence {evidence_id} has an invalid URL"
                )
        if item.get("subject_type") == "commit":
            subject_id = item.get("subject_id")
            commit = (
                indexes.get("commits", {}).get(subject_id)
                if isinstance(subject_id, str)
                else None
            )
            native_identity = item.get("native_identity")
            if isinstance(commit, dict) and (
                not isinstance(native_identity, dict)
                or native_identity.get("state") != "known"
                or native_identity.get("value") != commit.get("sha")
            ):
                _issue(
                    issues,
                    "evidence.commit_native_identity",
                    f"evidence {evidence_id} native identity does not match its commit SHA",
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
        if not isinstance(commit_ids, list) or not all(
            isinstance(value, str) for value in commit_ids
        ):
            _issue(
                issues,
                "ref_change.commit_ids",
                f"ref_change {ref_change_id} has invalid commit_ids",
            )
            continue
        for commit_id in commit_ids:
            if not isinstance(commit_id, str) or commit_id not in commits:
                _issue(
                    issues,
                    "ref_change.commit_ref",
                    f"ref_change {ref_change_id} references missing commit {commit_id}",
                )


def _provider_id_from_entity_id(
    collection_key: str,
    item: dict[str, Any],
    provider_index: dict[str, dict[str, Any]],
) -> str | None:
    entity_id = item.get("id")
    if not isinstance(entity_id, str) or not entity_id:
        return None
    singular = {
        "repositories": "repo",
        "work_items": "work_item",
        "change_requests": "change_request",
        "ref_changes": "ref_change",
    }.get(collection_key, collection_key.rstrip("s"))
    for provider_id, provider in provider_index.items():
        kind = provider.get("kind")
        instance = provider.get("instance")
        if (
            isinstance(kind, str)
            and isinstance(instance, str)
            and entity_id.startswith(f"{singular}:{kind}:{instance}:")
        ):
            return provider_id
    return None


def _canonical_repository_prefix(
    collection_key: str,
    repository_id: str,
    provider: dict[str, Any],
) -> str | None:
    """Build an entity prefix from the complete canonical repository ID."""
    kind = provider.get("kind")
    instance = provider.get("instance")
    if not isinstance(kind, str) or not isinstance(instance, str):
        return None
    provider_repository_prefix = f"repo:{kind}:{instance}:"
    if not repository_id.startswith(provider_repository_prefix):
        return None
    repository_segment = repository_id[len(provider_repository_prefix) :]
    if not repository_segment:
        return None
    singular = {
        "work_items": "work_item",
        "change_requests": "change_request",
        "ref_changes": "ref_change",
    }.get(collection_key, collection_key.rstrip("s"))
    return f"{singular}:{kind}:{instance}:{repository_segment}:"


def _repository_target_from_id(
    repository_id: str,
    provider: dict[str, Any],
) -> RepositoryTarget | None:
    kind = provider.get("kind")
    instance = provider.get("instance")
    if not isinstance(kind, str) or not isinstance(instance, str):
        return None
    prefix = f"repo:{kind}:{instance}:"
    if not repository_id.startswith(prefix):
        return None
    repository_segment = repository_id[len(prefix) :]
    if "/" not in repository_segment:
        return None
    owner, name = repository_segment.rsplit("/", 1)
    if not owner or not name:
        return None
    try:
        return RepositoryTarget(kind, instance, owner, name)
    except ValueError:
        return None


def _canonical_repository_url_values(repository: dict[str, Any]) -> list[Any]:
    values: list[Any] = []
    for field in (
        "web_url",
        "html_url",
        "repository_url",
        "repo_url",
        "project_url",
        "api_url",
        "url",
    ):
        if field in repository and repository[field] is not None:
            values.append(repository[field])
    links = repository.get("_links")
    if isinstance(links, dict):
        values.extend(value for value in links.values() if value is not None)
    return values


def _validate_canonical_repository_identity(
    repository_id: str,
    repository: dict[str, Any],
    provider: dict[str, Any],
    issues: list[ValidationIssue],
) -> None:
    target = _repository_target_from_id(repository_id, provider)
    if target is None:
        return
    expected_full_name = f"{target.owner}/{target.name}"
    identity_values = [
        repository[field]
        for field in ("full_name", "path_with_namespace")
        if field in repository
    ]
    if not identity_values or any(
        not isinstance(value, str) or value.strip() != expected_full_name
        for value in identity_values
    ):
        _issue(
            issues,
            "repository.identity",
            f"repository {repository_id} full_name/path identity does not match its canonical target",
        )
    if "name" in repository and (
        not isinstance(repository["name"], str)
        or repository["name"].strip() != target.name
    ):
        _issue(
            issues,
            "repository.identity",
            f"repository {repository_id} name does not match its canonical target",
        )
    url_values = _canonical_repository_url_values(repository)
    if not url_values:
        _issue(
            issues,
            "repository.url_missing",
            f"repository {repository_id} has no verifiable canonical URL",
        )
    for value in url_values:
        if not isinstance(value, str) or not repository_url_matches_target(
            value, target
        ):
            _issue(
                issues,
                "repository.url_identity",
                f"repository {repository_id} URL does not match its canonical target",
            )


def _entity_provider_id(
    subject_type: str,
    item: dict[str, Any],
    indexes: dict[str, dict[str, dict[str, Any]]],
) -> str | None:
    explicit = item.get("provider_id")
    if isinstance(explicit, str) and explicit:
        return explicit
    if subject_type == "provider":
        return item.get("id") if isinstance(item.get("id"), str) else None
    repository_id = item.get("repository_id")
    if subject_type == "repository":
        repository_id = item.get("id")
    if isinstance(repository_id, str):
        repository = indexes.get("repositories", {}).get(repository_id)
        if isinstance(repository, dict):
            provider_id = repository.get("provider_id")
            if isinstance(provider_id, str) and provider_id:
                return provider_id
    collection_key = SUBJECT_COLLECTIONS.get(subject_type, f"{subject_type}s")
    return _provider_id_from_entity_id(
        collection_key, item, indexes.get("providers", {})
    )


def _validate_provenance(
    indexes: dict[str, dict[str, dict[str, Any]]],
    issues: list[ValidationIssue],
) -> None:
    """Align provider, repository, subject, and coverage provenance."""
    providers = indexes.get("providers", {})
    for provider_id, provider in providers.items():
        kind = provider.get("kind")
        instance = provider.get("instance")
        if (
            not isinstance(kind, str)
            or not kind
            or not isinstance(instance, str)
            or not instance
        ):
            _issue(
                issues,
                "provider.provenance",
                f"provider {provider_id} must declare kind and instance",
            )
            continue
        if re.fullmatch(r"[a-z][a-z0-9_-]*", kind) is None:
            _issue(
                issues,
                "provider.kind",
                f"provider {provider_id} has an invalid embedded namespace",
            )
        try:
            canonical_instance = validate_instance(instance)
        except ValueError:
            canonical_instance = None
        if canonical_instance != instance:
            _issue(
                issues,
                "provider.instance",
                f"provider {provider_id} has a non-canonical embedded instance",
            )
        expected_id = f"provider:{kind}:{instance}"
        if provider_id != expected_id:
            _issue(
                issues,
                "provider.provenance",
                f"provider id {provider_id} does not match kind/instance {kind}:{instance}",
            )

    repositories = indexes.get("repositories", {})
    for repository_id, repository in repositories.items():
        explicit_provider_id = repository.get("provider_id")
        inferred_provider_id = _provider_id_from_entity_id(
            "repositories",
            repository,
            providers,
        )
        provider_id = (
            explicit_provider_id
            if isinstance(explicit_provider_id, str) and explicit_provider_id
            else inferred_provider_id
        )
        provider = providers.get(provider_id) if isinstance(provider_id, str) else None
        if not isinstance(provider_id, str) or not provider_id or provider is None:
            _issue(
                issues,
                "repository.provenance",
                f"repository {repository_id} references an unknown provider",
            )
            continue
        if (
            explicit_provider_id is not None
            and explicit_provider_id != inferred_provider_id
        ):
            _issue(
                issues,
                "repository.provenance",
                f"repository {repository_id} provider does not match its canonical id",
            )
        kind = provider.get("kind")
        instance = provider.get("instance")
        expected_prefix = f"repo:{kind}:{instance}:"
        if not repository_id.startswith(expected_prefix):
            _issue(
                issues,
                "repository.provenance",
                f"repository {repository_id} does not match provider {provider_id}",
            )
        _validate_canonical_repository_identity(
            repository_id, repository, provider, issues
        )

    entity_collections = tuple(
        key
        for key in COLLECTION_KEYS
        if key not in {"providers", "repositories", "evidence"}
    )
    for collection_key in entity_collections:
        singular = {
            "work_items": "work_item",
            "change_requests": "change_request",
            "ref_changes": "ref_change",
        }.get(collection_key, collection_key.rstrip("s"))
        for entity_id, item in indexes.get(collection_key, {}).items():
            explicit_provider_id = item.get("provider_id")
            repository_id = item.get("repository_id")
            repository = (
                repositories.get(repository_id)
                if isinstance(repository_id, str)
                else None
            )
            repository_provider_id = (
                repository.get("provider_id") if isinstance(repository, dict) else None
            )
            if explicit_provider_id is not None and (
                not isinstance(explicit_provider_id, str)
                or explicit_provider_id not in providers
            ):
                _issue(
                    issues,
                    "entity.provenance",
                    f"{collection_key} {entity_id} references an unknown provider",
                )
            if (
                isinstance(explicit_provider_id, str)
                and isinstance(repository_provider_id, str)
                and explicit_provider_id != repository_provider_id
            ):
                _issue(
                    issues,
                    "entity.provenance",
                    f"{collection_key} {entity_id} provider does not match its repository",
                )
            provider_id = _entity_provider_id(
                singular,
                item,
                indexes,
            )
            if provider_id is None:
                continue
            provider = providers.get(provider_id)
            if provider is None:
                _issue(
                    issues,
                    "entity.provenance",
                    f"{collection_key} {entity_id} has unknown provider provenance",
                )
                continue
            kind = provider.get("kind")
            instance = provider.get("instance")
            if not entity_id.startswith(f"{singular}:{kind}:{instance}:"):
                _issue(
                    issues,
                    "entity.provenance",
                    f"{collection_key} {entity_id} id does not match provider {provider_id}",
                )
            expected_repository_prefix = (
                _canonical_repository_prefix(
                    collection_key,
                    repository_id,
                    provider,
                )
                if isinstance(repository_id, str)
                else None
            )
            if expected_repository_prefix and not entity_id.startswith(
                expected_repository_prefix
            ):
                _issue(
                    issues,
                    "entity.repository_binding",
                    f"{collection_key} {entity_id} canonical repository does not match {repository_id}",
                )

    for evidence_id, evidence in indexes.get("evidence", {}).items():
        provider_id = evidence.get("provider_id")
        subject_type = evidence.get("subject_type")
        subject_id = evidence.get("subject_id")
        if provider_id is not None and (
            not isinstance(provider_id, str) or provider_id not in providers
        ):
            _issue(
                issues,
                "evidence.provenance",
                f"evidence {evidence_id} references an unknown provider",
            )
        if isinstance(subject_type, str) and isinstance(subject_id, str):
            subject_collection = SUBJECT_COLLECTIONS.get(subject_type)
            subject = indexes.get(subject_collection or "", {}).get(subject_id)
            if subject is None:
                continue
            subject_provider_id = _entity_provider_id(subject_type, subject, indexes)
            if subject_provider_id and provider_id != subject_provider_id:
                _issue(
                    issues,
                    "evidence.provenance",
                    f"evidence {evidence_id} provider does not match its subject",
                )


def _validate_scope(
    indexes: dict[str, dict[str, dict[str, Any]]],
    scope_repository_ids: set[str],
    scope_actor_ids: set[str] | None,
    issues: list[ValidationIssue],
) -> None:
    repositories = indexes.get("repositories", {})
    for repository_id in sorted(set(repositories) - scope_repository_ids):
        _issue(
            issues,
            "scope.entity_outside",
            f"repositories {repository_id} is outside the repository allowlist",
        )
    missing = scope_repository_ids - set(repositories)
    for repository_id in sorted(missing):
        _issue(
            issues,
            "scope.repository_missing",
            f"allowlisted repository is not in bundle: {repository_id}",
        )
    actors = indexes.get("actors", {})
    if scope_actor_ids:
        for actor_id in sorted(set(actors) - scope_actor_ids):
            _issue(
                issues,
                "scope.actor_outside",
                f"actor {actor_id} is outside the actor allowlist",
            )
    for key in (
        "work_items",
        "change_requests",
        "interactions",
        "commits",
        "ref_changes",
        "releases",
    ):
        for entity_id, item in indexes.get(key, {}).items():
            repository_id = item.get("repository_id")
            if not isinstance(repository_id, str) or not repository_id:
                _issue(
                    issues,
                    "scope.entity_repository_missing",
                    f"{key} {entity_id} has no repository_id",
                )
            elif repository_id not in scope_repository_ids:
                _issue(
                    issues,
                    "scope.entity_outside",
                    f"{key} {entity_id} is outside the repository allowlist",
                )
            actor_id = item.get("actor_id")
            if actor_id is None:
                continue
            if not isinstance(actor_id, str) or not actor_id:
                _issue(
                    issues,
                    "scope.actor_ref_invalid",
                    f"{key} {entity_id} has an invalid actor_id",
                )
            else:
                if actor_id not in actors:
                    _issue(
                        issues,
                        "scope.actor_ref_missing",
                        f"{key} {entity_id} references missing actor {actor_id}",
                    )
                if scope_actor_ids and actor_id not in scope_actor_ids:
                    _issue(
                        issues,
                        "scope.actor_outside",
                        f"{key} {entity_id} has an actor outside the actor allowlist",
                    )


def _validate_interactions(
    indexes: dict[str, dict[str, dict[str, Any]]],
    issues: list[ValidationIssue],
) -> None:
    subject_collections = {
        "work_item": "work_items",
        "change_request": "change_requests",
    }
    for interaction_id, interaction in indexes.get("interactions", {}).items():
        subject_type = interaction.get("subject_type")
        subject_id = interaction.get("subject_id")
        collection_key = subject_collections.get(subject_type)
        if collection_key is None:
            _issue(
                issues,
                "interaction.subject_type",
                f"interaction {interaction_id} has an invalid subject_type",
                path="$.interactions",
            )
            continue
        if not isinstance(subject_id, str) or not subject_id:
            _issue(
                issues,
                "interaction.subject_id",
                f"interaction {interaction_id} has no subject_id",
                path="$.interactions",
            )
            continue
        subject = indexes.get(collection_key, {}).get(subject_id)
        if not isinstance(subject, dict):
            _issue(
                issues,
                "interaction.subject_missing",
                f"interaction {interaction_id} references missing {subject_type} {subject_id}",
                path="$.interactions",
            )
            continue
        if subject.get("repository_id") != interaction.get("repository_id"):
            _issue(
                issues,
                "interaction.subject_repository",
                f"interaction {interaction_id} and its subject belong to different repositories",
                path="$.interactions",
            )


def _validate_coverage(
    bundle: dict[str, Any],
    indexes: dict[str, dict[str, dict[str, Any]]],
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
        _issue(
            issues,
            "coverage.required_sources",
            "coverage.required_sources must be an array of strings",
        )
        required_sources = []
    else:
        if not required_sources:
            _issue(
                issues,
                "coverage.required_sources_empty",
                "coverage.required_sources must not be empty",
            )
        if len(required_sources) != len(set(required_sources)):
            _issue(
                issues,
                "coverage.required_sources_duplicate",
                "coverage.required_sources must not contain duplicates",
            )
        unknown_sources = sorted(set(required_sources) - KNOWN_COVERAGE_SOURCES)
        if unknown_sources:
            _issue(
                issues,
                "coverage.required_source_unknown",
                "coverage.required_sources contains unknown sources: "
                + ", ".join(unknown_sources),
            )
            required_sources = [
                source
                for source in required_sources
                if source in KNOWN_COVERAGE_SOURCES
            ]
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
        _issue(
            issues, "coverage.observations", "coverage.observations must be an array"
        )
        observations = []
    group_failures = coverage.get("group_failures", [])
    if not isinstance(group_failures, list):
        _issue(
            issues,
            "coverage.group_failures_shape",
            "coverage.group_failures must be an array",
        )
        group_failures = []
    for position, failure in enumerate(group_failures):
        if not isinstance(failure, dict):
            _issue(
                issues,
                "coverage.group_failure_shape",
                f"coverage.group_failures[{position}] must be an object",
            )
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
    warnings = coverage.get("warnings", [])
    if not isinstance(warnings, list):
        _issue(issues, "coverage.warnings_shape", "coverage.warnings must be an array")
        warnings = []
    warning_groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for position, warning in enumerate(warnings):
        if not isinstance(warning, dict):
            _issue(
                issues,
                "coverage.warning_shape",
                f"coverage.warnings[{position}] must be an object",
            )
            continue
        if warning.get("code") != OPTIONAL_COVERAGE_WARNING_CODE:
            _issue(
                issues,
                "coverage.warning_code",
                f"coverage.warnings[{position}] has invalid code: {warning.get('code')!r}",
            )
        source = warning.get("source")
        if source not in ACTIVITY_SOURCES:
            _issue(
                issues,
                "coverage.warning_source",
                f"coverage.warnings[{position}] must reference an optional activity/ref source",
            )
        status = warning.get("status")
        if status not in {"unsupported", "unavailable", "incomplete"}:
            _issue(
                issues,
                "coverage.warning_status",
                f"coverage.warnings[{position}] has invalid status: {status!r}",
            )
        provider_id = warning.get("provider_id")
        repository_id = warning.get("repository_id")
        if not isinstance(provider_id, str) or not provider_id.strip():
            _issue(
                issues,
                "coverage.warning_provider_required",
                f"coverage.warnings[{position}] must declare a provider_id",
            )
        elif provider_id not in indexes.get("providers", {}):
            _issue(
                issues,
                "coverage.warning_provider_unknown",
                f"coverage.warnings[{position}] references unknown provider: {provider_id}",
            )
        if not isinstance(repository_id, str) or not repository_id.strip():
            _issue(
                issues,
                "coverage.warning_repository_required",
                f"coverage.warnings[{position}] must declare a repository_id",
            )
        elif repository_id not in scope_repository_ids:
            _issue(
                issues,
                "coverage.warning_repository_outside",
                f"coverage.warnings[{position}] references repository outside the allowlist: {repository_id}",
            )
        message = warning.get("message")
        if message is not None and (
            not isinstance(message, str) or not message.strip()
        ):
            _issue(
                issues,
                "coverage.warning_message",
                f"coverage.warnings[{position}].message must be a non-empty string when present",
            )
        failure_class = warning.get("failure_class")
        if failure_class is not None and (
            not isinstance(failure_class, str) or failure_class not in FAILURE_CLASSES
        ):
            _issue(
                issues,
                "coverage.warning_failure_class",
                f"coverage.warnings[{position}] has invalid failure_class: {failure_class!r}",
            )
        failure_classes = warning.get("failure_classes")
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
                "coverage.warning_failure_classes",
                f"coverage.warnings[{position}] has invalid failure_classes: {failure_classes!r}",
            )
        if (
            isinstance(source, str)
            and source in ACTIVITY_SOURCES
            and isinstance(provider_id, str)
            and provider_id in indexes.get("providers", {})
            and isinstance(repository_id, str)
            and repository_id in scope_repository_ids
        ):
            key = (source, repository_id, provider_id)
            if key in warning_groups:
                _issue(
                    issues,
                    "coverage.warning_duplicate",
                    f"duplicate coverage warning: {key}",
                )
            warning_groups.setdefault(key, []).append(warning)
    by_group: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    optional_privacy_observations: list[dict[str, Any]] = []
    for position, observation in enumerate(observations):
        if not isinstance(observation, dict):
            _issue(
                issues,
                "coverage.observation_shape",
                f"coverage.observations[{position}] must be an object",
            )
            continue
        source = observation.get("source")
        state = observation.get("status")
        if not isinstance(source, str) or not source:
            _issue(
                issues,
                "coverage.observation_source",
                f"coverage observation {position} has no source",
            )
            continue
        if state not in CAPABILITY_STATES:
            _issue(
                issues,
                "coverage.observation_status",
                f"coverage {source} has invalid status: {state!r}",
            )
        diagnostics = observation.get("diagnostics")
        pagination: Any = None
        if diagnostics is not None:
            if not isinstance(diagnostics, dict):
                _issue(
                    issues,
                    "coverage.diagnostics_shape",
                    f"coverage {source} diagnostics must be an object",
                )
            else:
                failure_class = diagnostics.get("failure_class")
                if failure_class is not None and (
                    not isinstance(failure_class, str)
                    or failure_class not in FAILURE_CLASSES
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
                pagination = diagnostics.get("pagination")
                if pagination is not None:
                    if not isinstance(pagination, dict):
                        _issue(
                            issues,
                            "coverage.pagination_shape",
                            f"coverage {source} pagination must be an object",
                        )
                    else:
                        outcome = pagination.get("outcome")
                        complete = pagination.get("complete")
                        if outcome not in PAGINATION_OUTCOMES:
                            _issue(
                                issues,
                                "coverage.pagination_outcome",
                                f"coverage {source} has an unknown pagination outcome",
                            )
                        elif complete is not PAGINATION_OUTCOMES[outcome]:
                            _issue(
                                issues,
                                "coverage.pagination_completion",
                                f"coverage {source} pagination proof contradicts completion",
                            )
                        if state == "supported" and complete is not True:
                            _issue(
                                issues,
                                "coverage.pagination_supported_incomplete",
                                f"coverage {source} is supported without a complete pagination proof",
                            )
                        provider_id = observation.get("provider_id")
                        provider = indexes.get("providers", {}).get(provider_id, {})
                        provider_kind = (
                            provider.get("kind") if isinstance(provider, dict) else None
                        )
                        expected_outcome = PROVIDER_PAGINATION_OUTCOMES.get(
                            provider_kind
                        )
                        if (
                            state == "supported"
                            and expected_outcome is not None
                            and outcome in PAGINATION_OUTCOMES
                            and outcome != expected_outcome
                        ):
                            _issue(
                                issues,
                                "coverage.pagination_provider_outcome",
                                f"coverage {source} uses {outcome!r}, not the documented "
                                f"{provider_kind} terminal outcome {expected_outcome!r}",
                            )
                operational_failures = (
                    _diagnostic_failure_classes(diagnostics)
                    & OPERATIONAL_FAILURE_CLASSES
                )
                if (
                    source in RESOURCE_SOURCES
                    and state == "supported"
                    and operational_failures
                ):
                    _issue(
                        issues,
                        "coverage.supported_operational_failure",
                        f"core coverage {source} is marked supported despite operational failures: "
                        + ", ".join(sorted(operational_failures)),
                    )
                if (
                    source in ACTIVITY_SOURCES
                    and "privacy_violation" in operational_failures
                ):
                    optional_privacy_observations.append(observation)
        if (
            source in PAGINATED_COVERAGE_SOURCES
            and state == "supported"
            and not isinstance(pagination, dict)
        ):
            _issue(
                issues,
                "coverage.pagination_missing",
                f"coverage {source} is supported without a terminal pagination proof",
            )
        repository_id = observation.get("repository_id")
        if not isinstance(repository_id, str) or not repository_id.strip():
            _issue(
                issues,
                "coverage.repository_required",
                f"coverage {source} must declare a repository_id",
            )
        if repository_id is not None and (
            not isinstance(repository_id, str)
            or repository_id not in scope_repository_ids
        ):
            _issue(
                issues,
                "coverage.repository_outside",
                f"coverage {source} references repository outside the allowlist: {repository_id}",
            )
        provider_id = observation.get("provider_id")
        if not isinstance(provider_id, str) or not provider_id.strip():
            _issue(
                issues,
                "coverage.provider_required",
                f"coverage {source} must declare a provider_id",
            )
        elif provider_id not in indexes.get("providers", {}):
            _issue(
                issues,
                "coverage.provider_unknown",
                f"coverage {source} references unknown provider: {provider_id}",
            )
        if (
            isinstance(source, str)
            and isinstance(repository_id, str)
            and repository_id
            and isinstance(provider_id, str)
            and provider_id in indexes.get("providers", {})
        ):
            by_group.setdefault((source, repository_id, provider_id), []).append(
                observation
            )
        repository = (
            indexes.get("repositories", {}).get(repository_id)
            if isinstance(repository_id, str)
            else None
        )
        repository_provider_id = (
            repository.get("provider_id") if isinstance(repository, dict) else None
        )
        if (
            isinstance(provider_id, str)
            and isinstance(repository_provider_id, str)
            and provider_id != repository_provider_id
        ):
            _issue(
                issues,
                "coverage.provenance",
                f"coverage {source} provider does not match repository {repository_id}",
            )
        provider = (
            indexes.get("providers", {}).get(provider_id)
            if isinstance(provider_id, str)
            else None
        )
        if isinstance(repository_id, str) and isinstance(provider, dict):
            kind = provider.get("kind")
            instance = provider.get("instance")
            expected_prefix = f"repo:{kind}:{instance}:"
            if not repository_id.startswith(expected_prefix):
                _issue(
                    issues,
                    "coverage.provenance",
                    f"coverage {source} repository does not match provider {provider_id}",
                )
    for (source, repository_id, provider_id), matches in by_group.items():
        if source not in ACTIVITY_SOURCES:
            continue
        warning_key = (source, repository_id, provider_id)
        for observation in matches:
            if (
                observation.get("status") != "supported"
                and warning_key not in warning_groups
            ):
                _issue(
                    issues,
                    "coverage.warning_missing",
                    f"optional source requires a coverage warning: {source} for {repository_id}",
                )
    for provider_id, provider in indexes.get("providers", {}).items():
        capabilities = provider.get("capabilities")
        if not isinstance(capabilities, dict):
            _issue(
                issues,
                "coverage.capabilities_shape",
                f"provider {provider_id} capabilities must be an object",
                path="$.providers",
            )
            continue
        for source, state in capabilities.items():
            if source not in KNOWN_COVERAGE_SOURCES:
                _issue(
                    issues,
                    "coverage.capability_source",
                    f"provider {provider_id} has an unknown capability source",
                    path="$.providers",
                )
            if state not in CAPABILITY_STATES:
                _issue(
                    issues,
                    "coverage.capability_status",
                    f"provider {provider_id} capability {source} has an invalid status",
                    path="$.providers",
                )
        observed: dict[str, str] = {}
        for (source, _repository_id, observed_provider_id), matches in by_group.items():
            if observed_provider_id != provider_id:
                continue
            for observation in matches:
                observed[source] = merge_capability_status(
                    observed.get(source), observation.get("status")
                )
        for source, expected in observed.items():
            if capabilities.get(source) != expected:
                _issue(
                    issues,
                    "coverage.capability_mismatch",
                    f"provider {provider_id} capability {source} must conservatively equal {expected}",
                    path="$.providers",
                )
    for warning_key, warning_items in warning_groups.items():
        matches = by_group.get(warning_key, [])
        if not matches:
            _issue(
                issues,
                "coverage.warning_observation_missing",
                f"coverage warning has no matching observation: {warning_key[0]} for {warning_key[1]}",
            )
            continue
        non_supported_matches = [
            observation
            for observation in matches
            if observation.get("status") != "supported"
        ]
        observed_failure_classes: set[str] = set()
        observed_notes: list[str] = []
        for observation in non_supported_matches:
            observed_failure_classes.update(
                _diagnostic_failure_classes(observation.get("diagnostics"))
            )
            note = observation.get("note")
            if isinstance(note, str) and note.strip() and note not in observed_notes:
                observed_notes.append(note)
        for warning in warning_items:
            if not non_supported_matches or any(
                observation.get("status") != warning.get("status")
                for observation in non_supported_matches
            ):
                _issue(
                    issues,
                    "coverage.warning_status_mismatch",
                    f"coverage warning status does not match observation: {warning_key[0]} for {warning_key[1]}",
                )
            warning_failure_classes = _diagnostic_failure_classes(warning)
            if warning_failure_classes != observed_failure_classes:
                _issue(
                    issues,
                    "coverage.warning_diagnostics",
                    f"coverage warning diagnostics do not fully cover observations: "
                    f"{warning_key[0]} for {warning_key[1]}",
                )
            warning_message = warning.get("message")
            if observed_notes and (
                not isinstance(warning_message, str)
                or warning_message != canonical_warning_message(*observed_notes)
            ):
                _issue(
                    issues,
                    "coverage.warning_message_missing",
                    f"coverage warning message does not cover observations: "
                    f"{warning_key[0]} for {warning_key[1]}",
                )
    for source in required_sources:
        for repository_id in sorted(scope_repository_ids):
            repository = indexes.get("repositories", {}).get(repository_id)
            expected_provider_id = (
                _entity_provider_id("repository", repository, indexes)
                if isinstance(repository, dict)
                else None
            )
            matches = by_group.get((source, repository_id, expected_provider_id), [])
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
        fatal = []
    else:
        for position, blocker in enumerate(fatal):
            if not isinstance(blocker, dict):
                _issue(
                    issues,
                    "coverage.fatal_shape",
                    f"coverage.fatal[{position}] must be an object",
                )
                continue
            for field in (
                "code",
                "provider",
                "instance",
                "repository",
                "source",
                "status",
            ):
                if not isinstance(blocker.get(field), str) or not blocker[field]:
                    _issue(
                        issues,
                        "coverage.fatal_field",
                        f"coverage.fatal[{position}].{field} must be a non-empty string",
                    )
            if blocker.get("status") not in {
                "unsupported",
                "unavailable",
                "incomplete",
            }:
                _issue(
                    issues,
                    "coverage.fatal_status",
                    f"coverage.fatal[{position}] has invalid status",
                )
            if blocker.get("code") not in BLOCKER_CODES:
                _issue(
                    issues,
                    "coverage.fatal_code",
                    f"coverage.fatal[{position}] has an unknown blocker code",
                )
            if blocker.get("source") not in KNOWN_COVERAGE_SOURCES:
                _issue(
                    issues,
                    "coverage.fatal_source",
                    f"coverage.fatal[{position}] has an unknown source",
                )
            failure_class = blocker.get("failure_class")
            if failure_class is not None and failure_class not in FAILURE_CLASSES:
                _issue(
                    issues,
                    "coverage.fatal_failure_class",
                    f"coverage.fatal[{position}] has invalid failure_class",
                )
            provider_kind = blocker.get("provider")
            instance = blocker.get("instance")
            repository_id = blocker.get("repository")
            source = blocker.get("source")
            expected_provider_id = (
                f"provider:{provider_kind}:{instance}"
                if isinstance(provider_kind, str) and isinstance(instance, str)
                else None
            )
            if (
                expected_provider_id is not None
                and expected_provider_id not in indexes.get("providers", {})
            ):
                _issue(
                    issues,
                    "coverage.fatal_provenance",
                    f"coverage.fatal[{position}] has no matching provider entity",
                )
            if (
                isinstance(repository_id, str)
                and repository_id not in scope_repository_ids
            ):
                _issue(
                    issues,
                    "coverage.fatal_scope",
                    f"coverage.fatal[{position}] repository is outside the allowlist",
                )
            matches = (
                by_group.get((source, repository_id, expected_provider_id), [])
                if isinstance(source, str)
                and isinstance(repository_id, str)
                and expected_provider_id is not None
                else []
            )
            if not matches:
                _issue(
                    issues,
                    "coverage.fatal_observation",
                    f"coverage.fatal[{position}] has no matching observation",
                )
            elif all(
                observation.get("status") != blocker.get("status")
                for observation in matches
            ):
                _issue(
                    issues,
                    "coverage.fatal_status_mismatch",
                    f"coverage.fatal[{position}] status does not match its observation",
                )
            if (
                isinstance(failure_class, str)
                and matches
                and all(
                    failure_class
                    not in _diagnostic_failure_classes(observation.get("diagnostics"))
                    for observation in matches
                )
            ):
                _issue(
                    issues,
                    "coverage.fatal_diagnostics",
                    f"coverage.fatal[{position}] failure_class is not recorded by its observation",
                )
        if fatal:
            _issue(
                issues,
                "coverage.fatal",
                f"coverage contains fatal observations: {len(fatal)}",
            )
    for observation in optional_privacy_observations:
        provider_id = observation.get("provider_id")
        repository_id = observation.get("repository_id")
        provider = (
            indexes.get("providers", {}).get(provider_id)
            if isinstance(provider_id, str)
            else None
        )
        fatal_match = any(
            isinstance(item, dict)
            and isinstance(provider, dict)
            and item.get("provider") == provider.get("kind")
            and item.get("instance") == provider.get("instance")
            and item.get("repository") == repository_id
            and item.get("source") == observation.get("source")
            and item.get("failure_class") == "privacy_violation"
            for item in (fatal if isinstance(fatal, list) else [])
        )
        if not fatal_match:
            _issue(
                issues,
                "coverage.optional_privacy_fatal",
                f"optional privacy violation is missing a fatal ledger entry: {observation.get('source')} for {repository_id}",
            )
    for position, failure in enumerate(group_failures):
        if not isinstance(failure, dict):
            continue
        provider_kind = failure.get("provider")
        instance = failure.get("instance")
        repository_id = failure.get("repository")
        source = failure.get("source")
        failure_class = failure.get("failure_class")
        expected_provider_id = (
            f"provider:{provider_kind}:{instance}"
            if isinstance(provider_kind, str) and isinstance(instance, str)
            else None
        )
        if expected_provider_id and expected_provider_id not in indexes.get(
            "providers", {}
        ):
            _issue(
                issues,
                "coverage.group_failure_provenance",
                f"coverage.group_failures[{position}] has no matching provider entity",
            )
        if isinstance(repository_id, str) and repository_id not in scope_repository_ids:
            _issue(
                issues,
                "coverage.group_failure_scope",
                f"coverage.group_failures[{position}] repository is outside the allowlist",
            )
        if (
            isinstance(provider_kind, str)
            and isinstance(instance, str)
            and isinstance(repository_id, str)
            and not repository_id.startswith(f"repo:{provider_kind}:{instance}:")
        ):
            _issue(
                issues,
                "coverage.group_failure_provenance",
                f"coverage.group_failures[{position}] repository does not match provider instance",
            )
        if isinstance(source, str) and source not in KNOWN_COVERAGE_SOURCES:
            _issue(
                issues,
                "coverage.group_failure_source",
                f"coverage.group_failures[{position}] uses unknown source: {source}",
            )
        matches = (
            by_group.get((source, repository_id, expected_provider_id), [])
            if isinstance(source, str)
            and isinstance(repository_id, str)
            and expected_provider_id
            else []
        )
        if not matches:
            _issue(
                issues,
                "coverage.group_failure_observation",
                f"coverage.group_failures[{position}] has no matching observation",
            )
        else:
            for observation in matches:
                if observation.get("status") == "supported":
                    _issue(
                        issues,
                        "coverage.group_failure_contradiction",
                        f"coverage.group_failures[{position}] is contradicted by a supported observation",
                    )
                diagnostics = observation.get("diagnostics")
                diagnostic_classes: set[str] = set()

                def collect_diagnostic_classes(
                    value: Any, accumulator: set[str]
                ) -> None:
                    if isinstance(value, dict):
                        diagnostic_class = value.get("failure_class")
                        if isinstance(diagnostic_class, str):
                            accumulator.add(diagnostic_class)
                        accumulator.update(
                            item
                            for item in value.get("failure_classes", [])
                            if isinstance(item, str)
                        )
                        for child in value.values():
                            collect_diagnostic_classes(child, accumulator)
                    elif isinstance(value, list):
                        for child in value:
                            collect_diagnostic_classes(child, accumulator)

                collect_diagnostic_classes(diagnostics, diagnostic_classes)
                if (
                    isinstance(failure_class, str)
                    and failure_class not in diagnostic_classes
                ):
                    _issue(
                        issues,
                        "coverage.group_failure_diagnostics",
                        f"coverage.group_failures[{position}] is not recorded by its observation",
                    )
        if source in required_sources:
            fatal_match = any(
                isinstance(item, dict)
                and item.get("provider") == provider_kind
                and item.get("instance") == instance
                and item.get("repository") == repository_id
                and item.get("source") == source
                and item.get("failure_class") == failure_class
                for item in (fatal if isinstance(fatal, list) else [])
            )
            if not fatal_match:
                _issue(
                    issues,
                    "coverage.group_failure_fatal",
                    f"required group failure {position} is missing a matching fatal ledger entry",
                )


def _validate_privacy(bundle: dict[str, Any], issues: list[ValidationIssue]) -> None:
    for path, reason in iter_privacy_violations(bundle):
        _issue(
            issues,
            f"privacy.{reason}",
            f"public payload is unsafe at {path}",
            path=path,
        )
    for path, reason in iter_privacy_warnings(bundle):
        _issue(
            issues,
            f"privacy.{reason}",
            f"public payload contains low-confidence secret-like text at {path}",
            severity="warning",
            path=path,
            remediation="Review the source text before disclosing this bundle or report.",
        )

    policy = bundle.get("privacy")
    if not isinstance(policy, dict):
        _issue(issues, "privacy.policy_shape", "privacy must be an object")
        return
    if policy.get("actor_display") != "anonymous":
        _issue(
            issues,
            "privacy.actor_display",
            "bundle actor display policy must be anonymous",
        )
    if policy.get("source_urls") != "sanitized":
        _issue(issues, "privacy.source_urls", "bundle source URLs must be sanitized")
    if policy.get("auth_redaction") is not True:
        _issue(
            issues, "privacy.auth_redaction", "bundle auth redaction must be enabled"
        )


def _validate_collection_transport(
    bundle: dict[str, Any], issues: list[ValidationIssue]
) -> None:
    collection_data = bundle.get("collection")
    if not isinstance(collection_data, dict):
        return

    pending = [collection_data]
    seen: set[int] = set()
    while pending:
        group = pending.pop()
        identity = id(group)
        if identity in seen:
            continue
        seen.add(identity)
        metrics = group.get("metrics")
        if group.get("failure_class") == "limit_exceeded":
            _issue(
                issues,
                "collection.limit_exceeded",
                "limit diagnostic bundles are not render eligible",
            )
            return
        if group.get("group_status") == "diagnostic_insecure_transport" or (
            isinstance(metrics, dict) and metrics.get("insecure_transport") is True
        ):
            _issue(
                issues,
                "collection.insecure_transport",
                "diagnostic insecure-transport bundles are not render eligible",
            )
            return
        nested_group = group.get("group")
        if isinstance(nested_group, dict):
            pending.append(nested_group)
        nested_groups = group.get("groups")
        if isinstance(nested_groups, list):
            pending.extend(item for item in nested_groups if isinstance(item, dict))


_SUBJECT_TYPE_BY_PREDICATE = {
    "work_item.observed.v1": "work_item",
    "change_request.observed.v1": "change_request",
    "change_request.merged.v1": "change_request",
    "interaction.observed.v1": "interaction",
    "commit.observed.v1": "commit",
    "ref_change.observed.v1": "ref_change",
    "release.observed.v1": "release",
    "release.published.v1": "release",
}

_OBSERVED_PREDICATE_BY_COLLECTION = {
    "work_items": "work_item.observed.v1",
    "change_requests": "change_request.observed.v1",
    "interactions": "interaction.observed.v1",
    "commits": "commit.observed.v1",
    "ref_changes": "ref_change.observed.v1",
    "releases": "release.observed.v1",
}


def _validate_assertions(
    bundle: dict[str, Any],
    indexes: dict[str, dict[str, dict[str, Any]]],
    scope_repository_ids: set[str],
    scope_actor_ids: set[str] | None,
    issues: list[ValidationIssue],
) -> None:
    assertions = bundle.get("assertions")
    if not isinstance(assertions, list):
        _issue(issues, "collection.shape", "assertions must be an array")
        return
    actors = indexes.get("actors", {})
    evidence_index = indexes.get("evidence", {})
    seen_ids: set[str] = set()
    asserted_events: set[tuple[str, str]] = set()
    for position, assertion in enumerate(assertions):
        path = f"$.assertions[{position}]"
        if not isinstance(assertion, dict):
            _issue(issues, "assertion.shape", "assertion must be an object", path=path)
            continue
        assertion_id = assertion.get("id")
        if not isinstance(assertion_id, str) or not assertion_id:
            _issue(
                issues,
                "assertion.id",
                "assertion must have a non-empty id",
                path=f"{path}.id",
            )
        elif assertion_id in seen_ids:
            _issue(
                issues,
                "assertion.duplicate_id",
                f"duplicate assertion id: {assertion_id}",
                path=f"{path}.id",
            )
        else:
            seen_ids.add(assertion_id)

        subject_type = assertion.get("subject_type")
        subject_id = assertion.get("subject_id")
        predicate = assertion.get("predicate")
        if isinstance(subject_id, str) and isinstance(predicate, str):
            asserted_events.add((subject_id, predicate))
        expected_subject_type = _SUBJECT_TYPE_BY_PREDICATE.get(predicate)
        if expected_subject_type is not None and subject_type != expected_subject_type:
            _issue(
                issues,
                "assertion.predicate_subject",
                f"assertion {assertion_id} predicate requires subject_type {expected_subject_type}",
                path=f"{path}.subject_type",
            )
        subject_collection = SUBJECT_COLLECTIONS.get(subject_type)
        subject = indexes.get(subject_collection or "", {}).get(subject_id)
        if subject is None:
            _issue(
                issues,
                "assertion.subject_missing",
                f"assertion {assertion_id} references an unknown subject",
                path=f"{path}.subject_id",
            )
        elif expected_subject_type is not None:
            subject_time_field = (
                "merged_at"
                if predicate == "change_request.merged.v1"
                else "occurred_at"
            )
            assertion_time = _parse_timestamp(assertion.get("occurred_at"))
            subject_time = _parse_timestamp(subject.get(subject_time_field))
            if (
                assertion_time is None
                or subject_time is None
                or assertion_time != subject_time
            ):
                _issue(
                    issues,
                    "assertion.event_time",
                    f"assertion {assertion_id} occurred_at does not match subject {subject_time_field}",
                    path=f"{path}.occurred_at",
                )
        repository_id = assertion.get("repository_id")
        subject_repository_id = (
            subject.get("repository_id") if isinstance(subject, dict) else None
        )
        if subject_type == "repository" and isinstance(subject, dict):
            subject_repository_id = subject.get("id")
        if repository_id != subject_repository_id:
            _issue(
                issues,
                "assertion.repository",
                f"assertion {assertion_id} repository does not match its subject",
                path=f"{path}.repository_id",
            )
        if (
            not isinstance(repository_id, str)
            or repository_id not in scope_repository_ids
        ):
            _issue(
                issues,
                "scope.entity_outside",
                f"assertion {assertion_id} is outside the repository allowlist",
                path=f"{path}.repository_id",
            )

        evidence_ids = assertion.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids:
            _issue(
                issues,
                "assertion.evidence",
                f"assertion {assertion_id} must reference evidence",
                path=f"{path}.evidence_ids",
            )
        else:
            for evidence_id in evidence_ids:
                evidence = evidence_index.get(evidence_id)
                if evidence is None:
                    _issue(
                        issues,
                        "assertion.evidence_ref",
                        f"assertion {assertion_id} references unknown evidence {evidence_id}",
                        path=f"{path}.evidence_ids",
                    )
                    continue
                if (
                    evidence.get("subject_type") != subject_type
                    or evidence.get("subject_id") != subject_id
                ):
                    _issue(
                        issues,
                        "assertion.evidence_subject",
                        f"assertion {assertion_id} evidence does not match its subject",
                        path=f"{path}.evidence_ids",
                    )
                evidence_subject = indexes.get(subject_collection or "", {}).get(
                    evidence.get("subject_id")
                )
                evidence_repository_id = (
                    evidence_subject.get("repository_id")
                    if isinstance(evidence_subject, dict)
                    else None
                )
                if evidence_repository_id != repository_id:
                    _issue(
                        issues,
                        "assertion.evidence_repository",
                        f"assertion {assertion_id} evidence resolves to a different repository",
                        path=f"{path}.evidence_ids",
                    )

        actor_id = assertion.get("actor_id")
        if actor_id is not None:
            if not isinstance(actor_id, str) or not actor_id:
                _issue(
                    issues,
                    "scope.actor_ref_invalid",
                    f"assertion {assertion_id} has an invalid actor_id",
                    path=f"{path}.actor_id",
                )
            else:
                if actor_id not in actors:
                    _issue(
                        issues,
                        "scope.actor_ref_missing",
                        f"assertion {assertion_id} references missing actor {actor_id}",
                        path=f"{path}.actor_id",
                    )
                if scope_actor_ids and actor_id not in scope_actor_ids:
                    _issue(
                        issues,
                        "scope.actor_outside",
                        f"assertion {assertion_id} has an actor outside the actor allowlist",
                        path=f"{path}.actor_id",
                    )

    for collection_key, predicate in _OBSERVED_PREDICATE_BY_COLLECTION.items():
        for subject_id, subject in indexes.get(collection_key, {}).items():
            if (
                isinstance(subject.get("occurred_at"), str)
                and (subject_id, predicate) not in asserted_events
            ):
                _issue(
                    issues,
                    "assertion.observation_missing",
                    f"{collection_key} {subject_id} has no {predicate} assertion",
                )

    for change_request_id, change_request in indexes.get("change_requests", {}).items():
        merged_at = change_request.get("merged_at")
        merged_event = (
            change_request_id,
            "change_request.merged.v1",
        )
        if isinstance(merged_at, str) and merged_event not in asserted_events:
            _issue(
                issues,
                "assertion.change_request_merge_missing",
                f"change request {change_request_id} has no merge assertion",
            )
        if merged_event in asserted_events and not isinstance(merged_at, str):
            _issue(
                issues,
                "assertion.change_request_merge_time",
                f"change request {change_request_id} merge assertion has no merged_at",
            )


def _validate_v03_identity_and_retrievals(
    bundle: dict[str, Any],
    issues: list[ValidationIssue],
    *,
    verify_bundle_digest: bool,
) -> None:
    plan = bundle.get("plan")
    declared_plan_id = bundle.get("plan_id")
    if isinstance(plan, dict):
        try:
            normalized_plan = normalize_plan(plan)
            expected_plan_id = compute_plan_id(plan)
        except IdentityError as exc:
            _issue(issues, "plan.canonicalization", str(exc), path="$.plan")
        else:
            if plan != normalized_plan:
                _issue(
                    issues,
                    "plan.noncanonical",
                    "plan sets and provider entries must use canonical order",
                    path="$.plan",
                )
            if declared_plan_id != expected_plan_id:
                _issue(
                    issues,
                    "plan.digest_mismatch",
                    "plan_id does not match the canonical plan",
                    path="$.plan_id",
                )
    invocation = bundle.get("invocation")
    if isinstance(invocation, dict):
        started_at = _parse_timestamp(invocation.get("started_at"))
        finished_at = _parse_timestamp(invocation.get("finished_at"))
        if (
            started_at is not None
            and finished_at is not None
            and started_at > finished_at
        ):
            _issue(
                issues,
                "invocation.order",
                "invocation.started_at must not be later than finished_at",
                path="$.invocation",
            )
    if verify_bundle_digest:
        try:
            expected_bundle_digest = compute_bundle_digest(bundle)
        except IdentityError as exc:
            _issue(issues, "bundle.canonicalization", str(exc), path="$")
        else:
            if bundle.get("bundle_digest") != expected_bundle_digest:
                _issue(
                    issues,
                    "bundle.digest_mismatch",
                    "bundle_digest does not match the canonical bundle",
                    path="$.bundle_digest",
                )

    providers = {
        item.get("id"): item
        for item in bundle.get("providers", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    top_provider_pairs = {
        (item.get("kind"), item.get("instance"))
        for item in providers.values()
        if isinstance(item.get("kind"), str) and isinstance(item.get("instance"), str)
    }
    plan_provider_pairs: list[tuple[str, str]] = []
    plan_sources: dict[str, set[str]] = {}
    if isinstance(plan, dict) and isinstance(plan.get("providers"), list):
        for position, provider in enumerate(plan["providers"]):
            if not isinstance(provider, dict):
                continue
            kind = provider.get("kind")
            instance = provider.get("instance")
            if not isinstance(kind, str) or not isinstance(instance, str):
                continue
            pair = (kind, instance)
            plan_provider_pairs.append(pair)
            provider_id = f"provider:{kind}:{instance}"
            sources = provider.get("selected_sources")
            if isinstance(sources, list):
                plan_sources[provider_id] = {
                    source for source in sources if isinstance(source, str)
                }
    if len(plan_provider_pairs) != len(set(plan_provider_pairs)):
        _issue(
            issues,
            "plan.provider_duplicate",
            "plan providers must be unique by kind and canonical instance",
            path="$.plan.providers",
        )
    if set(plan_provider_pairs) != top_provider_pairs:
        _issue(
            issues,
            "plan.provider_mismatch",
            "plan providers must exactly match the Bundle provider identities",
            path="$.plan.providers",
        )
    coverage = bundle.get("coverage")
    observed_sources: dict[str, set[str]] = {}
    if isinstance(coverage, dict) and isinstance(coverage.get("observations"), list):
        for observation in coverage["observations"]:
            if not isinstance(observation, dict):
                continue
            provider_id = observation.get("provider_id")
            source = observation.get("source")
            if isinstance(provider_id, str) and isinstance(source, str):
                observed_sources.setdefault(provider_id, set()).add(source)
    for provider_id in set(plan_sources) | set(observed_sources):
        if plan_sources.get(provider_id, set()) != observed_sources.get(
            provider_id, set()
        ):
            _issue(
                issues,
                "plan.sources_mismatch",
                f"plan selected_sources do not match coverage for {provider_id}",
                path="$.plan.providers",
            )
    scope = plan.get("scope") if isinstance(plan, dict) else None
    if isinstance(scope, dict) and isinstance(scope.get("repositories"), list):
        for repository_id in scope["repositories"]:
            matches = [
                pair
                for pair in set(plan_provider_pairs)
                if isinstance(repository_id, str)
                and repository_id.startswith(f"repo:{pair[0]}:{pair[1]}:")
            ]
            if len(matches) != 1:
                _issue(
                    issues,
                    "plan.repository_provider",
                    f"scope repository {repository_id!r} does not resolve to exactly one plan provider",
                    path="$.plan.scope.repositories",
                )

    subject_repositories: dict[str, str] = {}
    for repository in bundle.get("repositories", []):
        if isinstance(repository, dict) and isinstance(repository.get("id"), str):
            subject_repositories[repository["id"]] = repository["id"]
    for key in (
        "work_items",
        "change_requests",
        "interactions",
        "commits",
        "ref_changes",
        "releases",
    ):
        for subject in bundle.get(key, []):
            if (
                isinstance(subject, dict)
                and isinstance(subject.get("id"), str)
                and isinstance(subject.get("repository_id"), str)
            ):
                subject_repositories[subject["id"]] = subject["repository_id"]
    retrievals: dict[str, dict[str, Any]] = {}
    for position, retrieval in enumerate(bundle.get("retrievals", [])):
        if not isinstance(retrieval, dict):
            continue
        retrieval_id = retrieval.get("id")
        if not isinstance(retrieval_id, str) or not retrieval_id:
            continue
        if retrieval_id in retrievals:
            _issue(
                issues,
                "retrieval.duplicate_id",
                f"duplicate retrieval id: {retrieval_id}",
                path=f"$.retrievals[{position}].id",
            )
        retrievals[retrieval_id] = retrieval
        if retrieval.get("provider_id") not in providers:
            _issue(
                issues,
                "retrieval.provider_missing",
                f"retrieval {retrieval_id} references an unknown provider",
                path=f"$.retrievals[{position}].provider_id",
            )
        if retrieval.get("mode") == "cache_replay":
            fetched_at = _parse_timestamp(retrieval.get("fetched_at"))
            stored_at = _parse_timestamp(retrieval.get("stored_at"))
            replayed_at = _parse_timestamp(retrieval.get("replayed_at"))
            age = retrieval.get("cache_age_seconds")
            ttl = retrieval.get("cache_ttl_seconds")
            if (
                fetched_at is not None
                and stored_at is not None
                and replayed_at is not None
                and not fetched_at <= stored_at <= replayed_at
            ):
                _issue(
                    issues,
                    "retrieval.cache_time_order",
                    f"retrieval {retrieval_id} has inconsistent cache timestamps",
                    path=f"$.retrievals[{position}]",
                )
            if (
                stored_at is not None
                and replayed_at is not None
                and isinstance(age, (int, float))
            ):
                expected_age = (replayed_at - stored_at).total_seconds()
                if not math.isclose(
                    float(age), expected_age, rel_tol=0.0, abs_tol=1e-6
                ):
                    _issue(
                        issues,
                        "retrieval.cache_age_mismatch",
                        f"retrieval {retrieval_id} cache age does not match its timestamps",
                        path=f"$.retrievals[{position}].cache_age_seconds",
                    )
                if isinstance(ttl, (int, float)) and expected_age > float(ttl):
                    _issue(
                        issues,
                        "retrieval.cache_stale",
                        f"retrieval {retrieval_id} exceeds its recorded cache TTL",
                        path=f"$.retrievals[{position}]",
                    )
            elif (
                isinstance(age, (int, float))
                and isinstance(ttl, (int, float))
                and age > ttl
            ):
                _issue(
                    issues,
                    "retrieval.cache_stale",
                    f"retrieval {retrieval_id} exceeds its recorded cache TTL",
                    path=f"$.retrievals[{position}]",
                )
        common_fields = {
            "id",
            "provider_id",
            "mode",
            "endpoint_kind",
            "target_ref",
            "repository_id",
            "page",
            "pagination_outcome",
            "etag",
            "last_modified",
            "api_version",
            "payload_digest",
        }
        mode_fields = {
            "live": common_fields | {"fetched_at"},
            "cache_replay": common_fields
            | {
                "fetched_at",
                "stored_at",
                "replayed_at",
                "cache_age_seconds",
                "cache_ttl_seconds",
            },
            "recorded_replay": common_fields | {"replayed_at"},
        }
        allowed_fields = mode_fields.get(retrieval.get("mode"))
        if allowed_fields is not None and set(retrieval) - allowed_fields:
            _issue(
                issues,
                "retrieval.mode_fields",
                f"retrieval {retrieval_id} carries fields not valid for its mode",
                path=f"$.retrievals[{position}]",
            )
    for position, evidence in enumerate(bundle.get("evidence", [])):
        if not isinstance(evidence, dict):
            continue
        retrieval_id = evidence.get("retrieval_id")
        if retrieval_id not in retrievals:
            _issue(
                issues,
                "evidence.retrieval_missing",
                f"evidence {evidence.get('id')} references an unknown Retrieval",
                path=f"$.evidence[{position}].retrieval_id",
            )
            continue
        retrieval = retrievals[retrieval_id]
        if evidence.get("provider_id") != retrieval.get("provider_id"):
            _issue(
                issues,
                "evidence.retrieval_provider",
                f"evidence {evidence.get('id')} and its Retrieval use different providers",
                path=f"$.evidence[{position}].retrieval_id",
            )
        subject_repository = subject_repositories.get(evidence.get("subject_id"))
        if subject_repository != retrieval.get("repository_id"):
            _issue(
                issues,
                "evidence.retrieval_repository",
                f"evidence {evidence.get('id')} and its Retrieval use different repositories",
                path=f"$.evidence[{position}].retrieval_id",
            )


def _validate_event_and_revision_semantics(
    bundle: dict[str, Any],
    indexes: dict[str, dict[str, dict[str, Any]]],
    window: Any,
    issues: list[ValidationIssue],
) -> None:
    window_start = (
        _parse_timestamp(window.get("start")) if isinstance(window, dict) else None
    )
    window_end = (
        _parse_timestamp(window.get("end")) if isinstance(window, dict) else None
    )
    for key in COLLECTION_KEYS:
        for entity_id, item in indexes.get(key, {}).items():
            if "occurred_at" not in item:
                continue
            parsed_at = _parse_timestamp(item.get("occurred_at"))
            if parsed_at is None:
                _issue(
                    issues,
                    "entity.timestamp",
                    f"{key} {entity_id} has an invalid occurred_at",
                )
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
    for assertion in bundle.get("assertions", []):
        if not isinstance(assertion, dict):
            continue
        parsed_at = _parse_timestamp(assertion.get("occurred_at"))
        if parsed_at is None:
            _issue(
                issues,
                "entity.timestamp",
                f"assertion {assertion.get('id')} has an invalid occurred_at",
            )
        elif (
            window_start is not None
            and window_end is not None
            and not window_start <= parsed_at < window_end
        ):
            _issue(
                issues,
                "entity.timestamp_window",
                f"assertion {assertion.get('id')} occurred_at must be within "
                f"[{window.get('start')}, {window.get('end')})",
            )
    for entity_id, item in indexes.get("commits", {}).items():
        sha = item.get("sha")
        algorithm = git_object_id_algorithm(sha)
        if algorithm is None or not is_verifiable_sha(sha):
            code = (
                "commit.sha_missing"
                if not isinstance(sha, str) or not sha.strip()
                else "commit.sha_unverifiable"
            )
            _issue(issues, code, f"commit {entity_id} has no verifiable sha")
        elif not entity_id.endswith(f":{sha}"):
            _issue(
                issues,
                "commit.sha_mismatch",
                f"commit {entity_id} sha does not match its canonical id",
            )
        if algorithm is not None and item.get("hash_algorithm") != algorithm:
            _issue(
                issues,
                "commit.hash_algorithm",
                f"commit {entity_id} hash_algorithm does not match its object id",
            )
    for entity_id, item in indexes.get("ref_changes", {}).items():
        association = item.get("change_association")
        if not isinstance(association, str) or association not in ASSOCIATION_STATES:
            _issue(
                issues,
                "association.state",
                f"ref_change {entity_id} has invalid change_association",
            )


def _validate_v03_intrinsic(
    bundle: dict[str, Any],
    *,
    required_sources_contract: Iterable[str] | None = None,
    verify_bundle_digest: bool = True,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    _validate_schema(bundle, issues, schema_version="0.3")
    _validate_v03_identity_and_retrievals(
        bundle,
        issues,
        verify_bundle_digest=verify_bundle_digest,
    )
    indexes = _validate_ids(bundle, issues)
    scope_repository_ids, scope_actor_ids = _validate_plan_scope(bundle, issues)
    _validate_assertions(bundle, indexes, scope_repository_ids, scope_actor_ids, issues)
    _validate_provenance(indexes, issues)
    _validate_scope(indexes, scope_repository_ids, scope_actor_ids, issues)
    _validate_interactions(indexes, issues)
    _validate_evidence(indexes, issues)
    _validate_privacy(bundle, issues)
    _validate_collection_transport(bundle, issues)
    contract = (
        tuple(RESOURCE_SOURCES)
        if required_sources_contract is None
        else tuple(required_sources_contract)
    )
    _validate_coverage(bundle, indexes, scope_repository_ids, issues, contract)
    plan = bundle.get("plan")
    window = plan.get("window") if isinstance(plan, dict) else None
    _validate_event_and_revision_semantics(bundle, indexes, window, issues)
    return issues


def _validate_intrinsic(
    bundle: dict[str, Any],
    *,
    required_sources_contract: Iterable[str] | None = None,
    verify_bundle_digest: bool = True,
) -> list[ValidationIssue]:
    schema_version = bundle.get("schema_version") if isinstance(bundle, dict) else None
    if schema_version == "0.3":
        return _validate_v03_intrinsic(
            bundle,
            required_sources_contract=required_sources_contract,
            verify_bundle_digest=verify_bundle_digest,
        )
    issues: list[ValidationIssue] = []
    _issue(
        issues,
        "schema.version",
        "schema_version must be '0.3'",
        path="$.schema_version",
    )
    return issues


def compute_render_eligibility(
    bundle: dict[str, Any],
    *,
    required_sources_contract: Iterable[str] | None = None,
) -> bool:
    """Derive publication eligibility solely from intrinsic bundle invariants."""
    return not any(
        issue.severity == "error"
        for issue in _validate_intrinsic(
            bundle,
            required_sources_contract=required_sources_contract,
        )
    )


def recompute_render_eligibility(
    bundle: dict[str, Any],
    *,
    required_sources_contract: Iterable[str] | None = None,
) -> bool:
    """Overwrite the declaration with the authoritative derived decision."""
    coverage = bundle.get("coverage")
    if not isinstance(coverage, dict):
        return False
    if bundle.get("schema_version") == "0.3":
        coverage["render_eligible"] = False
        eligible = not any(
            issue.severity == "error"
            for issue in _validate_intrinsic(
                bundle,
                required_sources_contract=required_sources_contract,
                verify_bundle_digest=False,
            )
        )
        coverage["render_eligible"] = eligible
        try:
            bundle["bundle_digest"] = compute_bundle_digest(bundle)
        except IdentityError:
            coverage["render_eligible"] = False
            return False
        return eligible
    return False


def validate_bundle(
    bundle: dict[str, Any],
    *,
    required_sources_contract: Iterable[str] | None = None,
) -> list[ValidationIssue]:
    """Validate deterministic invariants; an empty list means render_eligible."""
    issues = _validate_intrinsic(
        bundle,
        required_sources_contract=required_sources_contract,
    )
    eligible = not any(issue.severity == "error" for issue in issues)
    coverage = bundle.get("coverage") if isinstance(bundle, dict) else None
    declaration_name = "render_eligible"
    declared = coverage.get(declaration_name) if isinstance(coverage, dict) else None
    if not eligible:
        _issue(
            issues,
            "coverage.render_blocked",
            "intrinsic validation blockers make this bundle not render eligible",
            remediation="Resolve every validation blocker, then recompute render_eligible.",
        )
    if declared is not eligible:
        _issue(
            issues,
            "coverage.render_mismatch",
            f"coverage.{declaration_name} must equal the derived value {eligible}",
            remediation=f"Set {declaration_name} only through the authoritative eligibility computation.",
        )
    return issues


def validate_provider_fragment(
    fragment: dict[str, Any],
    *,
    required_sources_contract: Iterable[str] | None = None,
) -> list[ValidationIssue]:
    """Validate the current internal provider/aggregate fragment contract."""
    issues: list[ValidationIssue] = []
    _validate_provider_fragment_schema(fragment, issues)
    if fragment.get("fragment_version") != "0.3":
        _issue(
            issues,
            "fragment.version",
            "fragment_version must be '0.3'",
            path="$.fragment_version",
        )
        return issues
    semantic = dict(fragment)
    semantic["plan"] = {
        "window": fragment.get("window"),
        "scope": fragment.get("scope"),
    }
    indexes = _validate_ids(semantic, issues)
    scope_repository_ids, scope_actor_ids = _validate_plan_scope(semantic, issues)
    _validate_assertions(
        fragment, indexes, scope_repository_ids, scope_actor_ids, issues
    )
    _validate_provenance(indexes, issues)
    _validate_scope(indexes, scope_repository_ids, scope_actor_ids, issues)
    _validate_interactions(indexes, issues)
    _validate_evidence(indexes, issues)
    _validate_collection_transport(semantic, issues)
    contract = (
        tuple(RESOURCE_SOURCES)
        if required_sources_contract is None
        else tuple(required_sources_contract)
    )
    _validate_coverage(semantic, indexes, scope_repository_ids, issues, contract)
    _validate_event_and_revision_semantics(
        fragment, indexes, fragment.get("window"), issues
    )
    coverage = fragment.get("coverage")
    declared = coverage.get("render_eligible") if isinstance(coverage, dict) else None
    provider_ids_by_repository = {
        repository_id: str(repository["provider_id"])
        for repository_id, repository in indexes.get("repositories", {}).items()
        if isinstance(repository.get("provider_id"), str)
    }
    blocked_by_semantics = any(issue.severity == "error" for issue in issues)
    blocked_by_coverage = has_blocking_core_coverage(
        coverage,
        repository_ids=scope_repository_ids,
        provider_ids_by_repository=provider_ids_by_repository,
    )
    expected = not blocked_by_semantics and not blocked_by_coverage
    if not expected:
        _issue(
            issues,
            "coverage.render_blocked",
            "fragment validation blockers make this output not render eligible",
        )
    if declared is not expected:
        _issue(
            issues,
            "coverage.render_mismatch",
            f"coverage.render_eligible must equal the derived value {expected}",
        )
    return issues


def format_issues(issues: Iterable[ValidationIssue]) -> str:
    return "\n".join(
        f"{item.severity.upper()}: {item.code} at {item.path} "
        f"[{item.scope}]: {item.message} Remediation: {item.remediation}"
        for item in issues
    )
