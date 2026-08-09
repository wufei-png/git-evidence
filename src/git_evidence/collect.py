from __future__ import annotations

import os
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
from typing import Any

from .bounds import (
    InputLimitError,
    indented_json_growth_upper_bound,
    json_size_with_limit,
)
from .config import CollectionConfig, ProviderInstanceConfig, provider_runtime_options
from .identity import (
    CANONICALIZATION,
    compute_bundle_digest,
    compute_plan_id,
    invocation_record,
    normalize_plan,
    utc_now,
)
from .limits import MAX_BUNDLE_BYTES, MAX_NORMALIZED_ENTITIES
from .model import ALL_COLLECTION_KEYS
from .privacy import PrivacyError, sanitize_public_payload
from .providers import (
    PROVIDER_REGISTRY,
    CollectionRequest,
    ProviderNotReady,
    RepositoryTarget,
)
from .providers.base import (
    ACTIVITY_SOURCES,
    RESOURCE_SOURCES,
    append_optional_coverage_warning,
    coverage_blocker,
    merge_optional_coverage_warning,
)
from .providers.resource_base import exception_diagnostics, merge_diagnostics
from .providers.transport import ApiError, ResponseShapeError, empty_transport_metrics
from .time import TimeValueError, normalize_utc
from .validation import (
    has_blocking_core_coverage,
    recompute_render_eligibility,
    validate_bundle,
    validate_provider_fragment,
)


class CollectionError(ValueError):
    """The collection plan cannot be executed safely."""


class PrivacyResponseError(ResponseShapeError):
    """Provider output crossed the public boundary with credential material."""

    def __init__(self, message: str) -> None:
        super().__init__(message, failure_class="privacy_violation")


ProviderFactory = Callable[[str, str, dict[str, Any], str | None], Any]


def _timestamp_text(value: Any, field: str) -> str:
    if not isinstance(value, (str, datetime)):
        raise CollectionError(f"{field} must be a non-empty timestamp")
    try:
        return normalize_utc(value)
    except TimeValueError as exc:
        raise CollectionError(f"{field}: {exc}") from exc


def _group_failure_diagnostics(error: Exception) -> tuple[str, dict[str, Any]]:
    diagnostics = exception_diagnostics(error)
    return str(diagnostics["failure_class"]), diagnostics


def _validate_provider_bundle_shape(bundle: Any) -> dict[str, Any]:
    """Validate the container shapes consumed by the group merge boundary."""
    try:
        bundle = sanitize_public_payload(bundle)
    except PrivacyError as exc:
        raise PrivacyResponseError(str(exc)) from exc
    if not isinstance(bundle, dict):
        raise ResponseShapeError("provider returned a non-object bundle")

    allowed_keys = {
        "fragment_version",
        "window",
        "scope",
        *ALL_COLLECTION_KEYS,
        "collection",
        "coverage",
    }
    unknown_keys = set(bundle) - allowed_keys
    missing_keys = allowed_keys - set(bundle)
    if unknown_keys:
        raise ResponseShapeError(
            f"provider fragment has unknown fields: {', '.join(sorted(unknown_keys))}"
        )
    if missing_keys:
        raise ResponseShapeError(
            f"provider fragment is missing fields: {', '.join(sorted(missing_keys))}"
        )

    for key in ALL_COLLECTION_KEYS:
        if key not in bundle:
            continue
        value = bundle[key]
        if not isinstance(value, list):
            raise ResponseShapeError(f"provider bundle {key} must be an array")
        seen_ids: set[str] = set()
        for position, item in enumerate(value):
            if not isinstance(item, dict):
                raise ResponseShapeError(
                    f"provider bundle {key}[{position}] must be an object"
                )
            entity_id = item.get("id")
            if not isinstance(entity_id, str) or not entity_id.strip():
                raise ResponseShapeError(
                    f"provider bundle {key}[{position}] is missing a non-empty id"
                )
            if entity_id in seen_ids:
                raise ResponseShapeError(
                    f"provider bundle {key} contains duplicate id: {entity_id}"
                )
            seen_ids.add(entity_id)

    coverage = bundle.get("coverage")
    if coverage is not None and not isinstance(coverage, dict):
        raise ResponseShapeError("provider bundle coverage must be an object")
    if isinstance(coverage, dict):
        for key in ("required_sources", "observations", "fatal", "group_failures"):
            if key in coverage and not isinstance(coverage[key], list):
                raise ResponseShapeError(
                    f"provider bundle coverage.{key} must be an array"
                )

    collection = bundle.get("collection")
    if collection is not None and not isinstance(collection, dict):
        raise ResponseShapeError("provider bundle collection must be an object")
    if isinstance(collection, dict):
        for key in ("groups",):
            if key in collection and not isinstance(collection[key], list):
                raise ResponseShapeError(
                    f"provider bundle collection.{key} must be an array"
                )
        for key in ("limits", "metrics", "group"):
            if (
                key in collection
                and collection[key] is not None
                and not isinstance(collection[key], dict)
            ):
                raise ResponseShapeError(
                    f"provider bundle collection.{key} must be an object"
                )

    retrievals = {
        item.get("id"): item
        for item in bundle.get("retrievals", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    evidence_by_subject: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for evidence in bundle.get("evidence", []):
        if not isinstance(evidence, dict):
            continue
        subject_type = evidence.get("subject_type")
        subject_id = evidence.get("subject_id")
        if isinstance(subject_type, str) and isinstance(subject_id, str):
            evidence_by_subject[(subject_type, subject_id)].append(evidence)
    subject_types = {
        "work_items": "work_item",
        "change_requests": "change_request",
        "interactions": "interaction",
        "commits": "commit",
        "ref_changes": "ref_change",
        "releases": "release",
    }
    for category, subject_type in subject_types.items():
        for entity in bundle.get(category, []):
            if not isinstance(entity, dict) or not isinstance(
                entity.get("occurred_at"), str
            ):
                # Actor-filtered structural parents intentionally carry no claim/evidence.
                continue
            subject_id = entity.get("id")
            repository_id = entity.get("repository_id")
            candidates = evidence_by_subject.get((subject_type, subject_id), [])
            valid = False
            for evidence in candidates:
                retrieval = retrievals.get(evidence.get("retrieval_id"))
                native = evidence.get("native_identity")
                if (
                    isinstance(retrieval, dict)
                    and retrieval.get("provider_id") == evidence.get("provider_id")
                    and retrieval.get("repository_id") == repository_id
                    and isinstance(native, dict)
                    and native.get("state") == "known"
                    and isinstance(native.get("value"), str)
                    and native["value"]
                ):
                    valid = True
                    break
            if not valid:
                raise ResponseShapeError(
                    f"provider bundle {category} entity lacks bound Retrieval/native Evidence",
                    failure_class="malformed_response",
                )

    validation_issues = validate_provider_fragment(bundle)
    group_failures = (bundle.get("coverage") or {}).get("group_failures", [])
    hard_issues = [
        issue
        for issue in validation_issues
        if issue.severity == "error"
        and not issue.code.startswith("coverage.")
        and issue.code
        not in {"collection.insecure_transport", "collection.limit_exceeded"}
        and not (issue.code == "scope.repository_missing" and group_failures)
    ]
    if hard_issues:
        details = "; ".join(issue.code for issue in hard_issues[:4])
        raise ResponseShapeError(
            f"provider fragment semantic validation failed: {details}",
            failure_class="malformed_response",
        )

    return bundle


def _failed_group_bundle(
    *,
    kind: str,
    instance: str,
    targets: list[RepositoryTarget],
    actor_ids: list[str],
    window_start: str,
    window_end: str,
    timezone: str,
    runtime: dict[str, Any],
    error: Exception,
) -> dict[str, Any]:
    failure_class, base_diagnostics = _group_failure_diagnostics(error)
    provider_id = f"provider:{kind}:{instance}"
    observations: list[dict[str, Any]] = []
    fatal: list[dict[str, Any]] = []
    group_failures: list[dict[str, Any]] = []
    capabilities = {
        source: "incomplete" for source in (*RESOURCE_SOURCES, *ACTIVITY_SOURCES)
    }
    for target in targets:
        for source in (*RESOURCE_SOURCES, *ACTIVITY_SOURCES):
            diagnostics = {
                **base_diagnostics,
                "group_failure": True,
            }
            observation = {
                "source": source,
                "provider_id": provider_id,
                "repository_id": target.canonical_id,
                "status": "incomplete",
                "diagnostics": diagnostics,
            }
            observations.append(observation)
            failure = {
                "provider": kind,
                "instance": instance,
                "repository": target.canonical_id,
                "source": source,
                "failure_class": failure_class,
            }
            group_failures.append(failure)
            if source in RESOURCE_SOURCES:
                fatal.append(
                    coverage_blocker(
                        code="required_source_failure",
                        status="incomplete",
                        provider=kind,
                        instance=instance,
                        repository=target.canonical_id,
                        source=source,
                        failure_class=failure_class,
                    )
                )
    return {
        "fragment_version": "0.3",
        "window": {"start": window_start, "end": window_end, "timezone": timezone},
        "scope": {
            "repositories": [target.canonical_id for target in targets],
            "actors": actor_ids,
        },
        "providers": [
            {
                "id": provider_id,
                "kind": kind,
                "instance": instance,
                "capabilities": capabilities,
            }
        ],
        "repositories": [],
        "actors": [],
        "work_items": [],
        "change_requests": [],
        "interactions": [],
        "commits": [],
        "ref_changes": [],
        "releases": [],
        "evidence": [],
        "retrievals": [],
        "assertions": [],
        "collection": {
            "provider": kind,
            "instance": instance,
            "group_status": "failed",
            "failure_class": failure_class,
            "limits": {
                key: runtime[key]
                for key in (
                    "timeout_seconds",
                    "max_retries",
                    "max_pages",
                    "max_requests",
                    "retry_jitter_seconds",
                    "retry_after_max_seconds",
                )
            },
            "metrics": empty_transport_metrics(
                cache_enabled=bool(runtime["cache_enabled"])
            ),
        },
        "coverage": {
            "required_sources": list(RESOURCE_SOURCES),
            "observations": observations,
            "fatal": fatal,
            "group_failures": group_failures,
            "warnings": [],
            "render_eligible": False,
        },
    }


def _bundle_group_identity(bundle: dict[str, Any]) -> tuple[str, str, list[str]]:
    collection = bundle.get("collection")
    if isinstance(collection, dict):
        provider = collection.get("provider")
        instance = collection.get("instance")
        if isinstance(provider, str) and isinstance(instance, str):
            scope = bundle.get("scope") if isinstance(bundle.get("scope"), dict) else {}
            repositories = (
                scope.get("repositories", []) if isinstance(scope, dict) else []
            )
            return (
                provider,
                instance,
                [item for item in repositories if isinstance(item, str)],
            )
    providers = bundle.get("providers")
    if isinstance(providers, list) and providers and isinstance(providers[0], dict):
        provider = providers[0]
        kind = provider.get("kind")
        instance = provider.get("instance")
        if isinstance(kind, str) and isinstance(instance, str):
            scope = bundle.get("scope") if isinstance(bundle.get("scope"), dict) else {}
            repositories = (
                scope.get("repositories", []) if isinstance(scope, dict) else []
            )
            return (
                kind,
                instance,
                [item for item in repositories if isinstance(item, str)],
            )
    return "unknown", "unknown", []


def _provider_ids_by_repository(
    bundle: dict[str, Any], repository_ids: list[str]
) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in bundle.get("repositories", []):
        if not isinstance(item, dict):
            continue
        repository_id = item.get("id")
        provider_id = item.get("provider_id")
        if isinstance(repository_id, str) and isinstance(provider_id, str):
            mapping[repository_id] = provider_id
    providers = bundle.get("providers", [])
    for repository_id in repository_ids:
        if repository_id in mapping:
            continue
        for provider in providers:
            if not isinstance(provider, dict):
                continue
            provider_id = provider.get("id")
            kind = provider.get("kind")
            instance = provider.get("instance")
            if (
                isinstance(provider_id, str)
                and isinstance(kind, str)
                and isinstance(instance, str)
                and repository_id.startswith(f"repo:{kind}:{instance}:")
            ):
                mapping[repository_id] = provider_id
                break
    return mapping


def _provider_bundle_has_complete_core_coverage(bundle: dict[str, Any]) -> bool:
    """Require every allowlisted repository to prove every core source."""
    coverage = bundle.get("coverage")
    if not isinstance(coverage, dict):
        return False
    required_sources = coverage.get("required_sources")
    if not isinstance(required_sources, list) or any(
        source not in required_sources for source in RESOURCE_SOURCES
    ):
        return False
    _, _, repositories = _bundle_group_identity(bundle)
    if not repositories:
        return False
    return not has_blocking_core_coverage(
        coverage,
        repository_ids=repositories,
        provider_ids_by_repository=_provider_ids_by_repository(bundle, repositories),
    )


def _record_merge_failure(
    merged: dict[str, Any],
    bundle: dict[str, Any],
    source_category: str,
    item: Any,
    reason: str,
) -> None:
    provider, instance, scoped_repositories = _bundle_group_identity(bundle)
    repository = item.get("repository_id") if isinstance(item, dict) else None
    if not isinstance(repository, str) or not repository:
        repository = (
            scoped_repositories[0] if scoped_repositories else "unknown-repository"
        )
    source = (
        source_category
        if source_category in (*RESOURCE_SOURCES, *ACTIVITY_SOURCES)
        else "repositories"
    )
    provider_id = f"provider:{provider}:{instance}"
    failure = {
        "provider": provider,
        "instance": instance,
        "repository": repository,
        "source": source,
        "failure_class": "malformed_response",
        "reason": reason,
    }
    merged["coverage"]["group_failures"].append(failure)
    observations = [
        item
        for item in merged["coverage"]["observations"]
        if isinstance(item, dict)
        and item.get("source") == source
        and item.get("provider_id") == provider_id
        and item.get("repository_id") == repository
    ]
    if not observations:
        observation = {
            "source": source,
            "provider_id": provider_id,
            "repository_id": repository,
            "status": "incomplete",
            "diagnostics": {
                "failure_class": "malformed_response",
                "group_failure": True,
                "reason": reason,
            },
        }
        merged["coverage"]["observations"].append(observation)
        append_optional_coverage_warning(merged["coverage"], observation)
    else:
        for observation in observations:
            observation["status"] = "incomplete"
            observation["note"] = (
                f"{observation.get('note')}; " if observation.get("note") else ""
            ) + reason
            diagnostics = observation.setdefault("diagnostics", {})
            if isinstance(diagnostics, dict):
                merge_diagnostics(
                    diagnostics,
                    {
                        "failure_class": "malformed_response",
                        "group_failure": True,
                        "reason": reason,
                    },
                )
            append_optional_coverage_warning(merged["coverage"], observation)
    if source in RESOURCE_SOURCES:
        merged["coverage"]["fatal"].append(
            coverage_blocker(
                code="aggregate_record_failure",
                status="incomplete",
                provider=provider,
                instance=instance,
                repository=repository,
                source=source,
                failure_class="malformed_response",
            )
        )


def _merge_bundles(
    bundles: list[dict[str, Any]],
    *,
    window_start: str,
    window_end: str,
    timezone: str,
    repository_ids: list[str],
    actor_ids: list[str],
) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "fragment_version": "0.3",
        "window": {"start": window_start, "end": window_end, "timezone": timezone},
        "scope": {"repositories": repository_ids, "actors": actor_ids},
        "providers": [],
        "repositories": [],
        "actors": [],
        "work_items": [],
        "change_requests": [],
        "interactions": [],
        "commits": [],
        "ref_changes": [],
        "releases": [],
        "evidence": [],
        "retrievals": [],
        "assertions": [],
        "collection": {
            "groups": [],
            "metrics": empty_transport_metrics(),
        },
        "privacy": {
            "actor_display": "anonymous",
            "source_urls": "sanitized",
            "auth_redaction": True,
        },
        "coverage": {
            "required_sources": list(RESOURCE_SOURCES),
            "observations": [],
            "fatal": [],
            "group_failures": [],
            "warnings": [],
            "render_eligible": True,
        },
    }
    collection_keys = (
        "providers",
        "repositories",
        "actors",
        "work_items",
        "change_requests",
        "interactions",
        "commits",
        "ref_changes",
        "releases",
        "evidence",
        "retrievals",
        "assertions",
    )
    seen: dict[str, set[str]] = {key: set() for key in collection_keys}
    provider_gate_blocked = False
    aggregate_limit_exceeded = False
    estimated_size = (
        json_size_with_limit(
            merged,
            max_bytes=MAX_BUNDLE_BYTES - 1,
        )
        + 1
    )
    for bundle in bundles:
        coverage = bundle.get("coverage") or {}
        if not _provider_bundle_has_complete_core_coverage(bundle):
            provider_gate_blocked = True
        merged["coverage"]["observations"].extend(coverage.get("observations") or [])
        merged["coverage"]["fatal"].extend(coverage.get("fatal") or [])
        merged["coverage"]["group_failures"].extend(
            coverage.get("group_failures") or []
        )
        if isinstance(coverage.get("warnings"), list):
            for item in coverage["warnings"]:
                if isinstance(item, dict):
                    merge_optional_coverage_warning(merged["coverage"], item)
        collection = bundle.get("collection") or {}
        if isinstance(collection, dict):
            group = collection.get("group")
            if not isinstance(group, dict):
                group = {
                    key: value
                    for key, value in collection.items()
                    if key
                    in {
                        "provider",
                        "instance",
                        "group_status",
                        "failure_class",
                        "limits",
                        "metrics",
                    }
                }
            if group:
                merged["collection"]["groups"].append(group)
            incoming_metrics = collection.get("metrics")
            if isinstance(incoming_metrics, dict):
                aggregate = merged["collection"]["metrics"]
                for key in (
                    "request_count",
                    "page_count",
                    "retry_count",
                    "cache_hits",
                    "cache_misses",
                ):
                    value = incoming_metrics.get(key)
                    if isinstance(value, int) and value >= 0:
                        aggregate[key] += value
                aggregate["budget_exhausted"] = bool(
                    aggregate["budget_exhausted"]
                    or incoming_metrics.get("budget_exhausted", False)
                )
                aggregate["cache_enabled"] = bool(
                    aggregate["cache_enabled"]
                    or incoming_metrics.get("cache_enabled", False)
                )
                aggregate["insecure_transport"] = bool(
                    aggregate["insecure_transport"]
                    or incoming_metrics.get("insecure_transport", False)
                )
        try:
            estimated_size = (
                json_size_with_limit(
                    merged,
                    max_bytes=MAX_BUNDLE_BYTES - 1,
                )
                + 1
            )
        except (InputLimitError, TypeError, ValueError):
            aggregate_limit_exceeded = True
        for key in collection_keys:
            for item in bundle.get(key, []):
                if aggregate_limit_exceeded:
                    continue
                entity_id = item.get("id") if isinstance(item, dict) else None
                if not isinstance(entity_id, str) or not entity_id.strip():
                    _record_merge_failure(
                        merged, bundle, key, item, "record is missing a non-empty id"
                    )
                    try:
                        estimated_size = (
                            json_size_with_limit(
                                merged,
                                max_bytes=MAX_BUNDLE_BYTES - 1,
                            )
                            + 1
                        )
                    except (InputLimitError, TypeError, ValueError):
                        aggregate_limit_exceeded = True
                    continue
                if entity_id in seen[key]:
                    _record_merge_failure(
                        merged, bundle, key, item, f"duplicate record id: {entity_id}"
                    )
                    try:
                        estimated_size = (
                            json_size_with_limit(
                                merged,
                                max_bytes=MAX_BUNDLE_BYTES - 1,
                            )
                            + 1
                        )
                    except (InputLimitError, TypeError, ValueError):
                        aggregate_limit_exceeded = True
                    continue
                if (
                    sum(len(merged[name]) for name in collection_keys)
                    >= MAX_NORMALIZED_ENTITIES
                ):
                    aggregate_limit_exceeded = True
                    continue
                seen[key].add(entity_id)
                merged[key].append(item)
                estimated_size += indented_json_growth_upper_bound(item, base_indent=4)
                if estimated_size <= MAX_BUNDLE_BYTES:
                    continue
                try:
                    estimated_size = (
                        json_size_with_limit(
                            merged,
                            max_bytes=MAX_BUNDLE_BYTES - 1,
                        )
                        + 1
                    )
                except (InputLimitError, TypeError, ValueError):
                    merged[key].pop()
                    seen[key].remove(entity_id)
                    aggregate_limit_exceeded = True
    for observation in merged["coverage"]["observations"]:
        if isinstance(observation, dict):
            append_optional_coverage_warning(merged["coverage"], observation)
    merged["coverage"]["render_eligible"] = not (
        provider_gate_blocked
        or has_blocking_core_coverage(
            merged["coverage"],
            repository_ids=repository_ids,
            provider_ids_by_repository=_provider_ids_by_repository(
                merged, repository_ids
            ),
        )
    )
    try:
        json_size_with_limit(merged, max_bytes=MAX_BUNDLE_BYTES - 1)
    except (InputLimitError, TypeError, ValueError):
        aggregate_limit_exceeded = True
    if aggregate_limit_exceeded:
        for key in collection_keys:
            if key != "providers":
                merged[key] = []
        merged["collection"]["group_status"] = "failed"
        merged["collection"]["failure_class"] = "limit_exceeded"
        merged["coverage"]["render_eligible"] = False
        try:
            json_size_with_limit(merged, max_bytes=MAX_BUNDLE_BYTES - 1)
        except (InputLimitError, TypeError, ValueError) as exc:
            raise CollectionError(
                "aggregate limit diagnostic exceeds the final bundle size limit"
            ) from exc
    return merged


def _collection_plan(
    *,
    window_start: str,
    window_end: str,
    timezone: str,
    repository_ids: list[str],
    actor_ids: list[str],
    grouped: dict[tuple[str, str], list[RepositoryTarget]],
    provider_options: dict[tuple[str, str], dict[str, Any]],
    provider_runtime: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    providers: list[dict[str, Any]] = []
    for kind, instance in sorted(grouped):
        configured = provider_options[(kind, instance)]
        runtime = provider_runtime[(kind, instance)]
        selected_sources = list(RESOURCE_SOURCES)
        selected_sources.extend(ACTIVITY_SOURCES)
        providers.append(
            {
                "kind": kind,
                "instance": instance,
                "selected_sources": selected_sources,
                "options": {
                    "include_activity_api": bool(
                        configured.get("include_activity_api", False)
                    ),
                    "verify_tls": bool(configured.get("verify_tls", True)),
                    "allow_insecure_loopback": bool(
                        configured.get("allow_insecure_loopback", False)
                    ),
                    **{
                        key: runtime[key]
                        for key in (
                            "timeout_seconds",
                            "max_retries",
                            "max_pages",
                            "max_requests",
                            "retry_backoff_seconds",
                            "retry_jitter_seconds",
                            "retry_after_max_seconds",
                            "cache_enabled",
                            "cache_ttl_seconds",
                            "cache_max_entries",
                        )
                    },
                },
            }
        )
    return normalize_plan(
        {
            "origin": "collection",
            "window": {
                "start": window_start,
                "end": window_end,
                "timezone": timezone,
            },
            "scope": {
                "repositories": repository_ids,
                "actors": actor_ids,
            },
            "providers": providers,
        }
    )


def _finalize_v03(
    merged: dict[str, Any],
    *,
    plan: dict[str, Any],
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    coverage = dict(merged["coverage"])
    result: dict[str, Any] = {
        "schema_version": "0.3",
        "canonicalization": dict(CANONICALIZATION),
        "plan_id": compute_plan_id(plan),
        "plan": plan,
        "invocation": invocation_record(
            started_at=started_at,
            finished_at=finished_at,
        ),
        **{
            key: merged.get(key, [])
            for key in (
                "providers",
                "repositories",
                "actors",
                "work_items",
                "change_requests",
                "interactions",
                "commits",
                "ref_changes",
                "releases",
                "retrievals",
                "evidence",
            )
        },
        "assertions": merged.get("assertions", []),
        "collection": merged.get("collection", {}),
        "privacy": merged.get("privacy", {}),
        "coverage": coverage,
    }
    result["bundle_digest"] = compute_bundle_digest(result)
    recompute_render_eligibility(result)
    blockers = [
        issue
        for issue in validate_bundle(result)
        if issue.severity == "error"
        and not issue.code.startswith("coverage.")
        and issue.code
        not in {
            "scope.repository_missing",
            "collection.insecure_transport",
            "collection.limit_exceeded",
        }
    ]
    if blockers:
        codes = ", ".join(sorted({f"{issue.code}@{issue.path}" for issue in blockers}))
        raise CollectionError(
            f"collector produced an invalid schema 0.3 bundle: {codes}"
        )
    return result


def collect_config(
    config: CollectionConfig,
    *,
    provider_factory: ProviderFactory | None = None,
) -> dict[str, Any]:
    """Collect all explicitly allowlisted repositories into one canonical bundle."""
    started_at = utc_now()
    if not isinstance(config, CollectionConfig):
        raise TypeError("config must be a validated CollectionConfig")
    window_start = _timestamp_text(config.window_start, "window.start")
    window_end = _timestamp_text(config.window_end, "window.end")
    timezone = config.timezone
    repositories = config.repositories
    actor_ids = list(config.actors)

    grouped: dict[tuple[str, str], list[RepositoryTarget]] = defaultdict(list)
    provider_options: dict[tuple[str, str], dict[str, Any]] = {}
    provider_runtime: dict[tuple[str, str], dict[str, Any]] = {}
    providers_by_group: dict[tuple[str, str], ProviderInstanceConfig] = {}
    for repository in repositories:
        provider_config = config.provider(repository.provider_ref)
        group_key = (provider_config.kind, provider_config.instance)
        grouped[group_key].append(repository.target)
        providers_by_group[group_key] = provider_config
        provider_options[group_key] = provider_config.factory_options()
        provider_runtime[group_key] = provider_runtime_options(provider_config)

    collected: list[dict[str, Any]] = []
    group_plans: list[
        tuple[tuple[str, str], list[RepositoryTarget], dict[str, Any], str | None]
    ] = []
    for group_key, targets in sorted(grouped.items()):
        kind, instance = group_key
        options = provider_options[group_key]
        provider_config = providers_by_group[group_key]
        token_env = provider_config.token_env
        token = os.environ.get(token_env) if token_env else None
        if token_env and not token:
            raise CollectionError(
                f"providers.{provider_config.ref}.token_env is configured but the "
                "environment variable is not set"
            )
        group_plans.append((group_key, targets, options, token))
    for (kind, instance), targets, options, token in group_plans:
        runtime = provider_runtime[(kind, instance)]
        request = CollectionRequest(
            provider_kind=kind,
            instance=instance,
            repositories=tuple(targets),
            window_start=window_start,
            window_end=window_end,
            timezone=timezone,
            include_activity_api=bool(options.get("include_activity_api", False)),
            actor_ids=tuple(actor_ids),
            timeout_seconds=float(runtime["timeout_seconds"]),
            max_retries=int(runtime["max_retries"]),
            max_pages=int(runtime["max_pages"]),
            max_requests=int(runtime["max_requests"]),
            retry_jitter_seconds=float(runtime["retry_jitter_seconds"]),
            retry_after_max_seconds=float(runtime["retry_after_max_seconds"]),
        )
        try:
            if provider_factory is not None:
                provider = provider_factory(kind, instance, options, token)
            else:
                provider = PROVIDER_REGISTRY.create(
                    kind,
                    instance=instance,
                    provider_config=options,
                    token=token,
                    runtime_options=runtime,
                )
            collected.append(_validate_provider_bundle_shape(provider.collect(request)))
        except CollectionError:
            raise
        except (ApiError, ProviderNotReady, PrivacyError) as exc:
            collected.append(
                _failed_group_bundle(
                    kind=kind,
                    instance=instance,
                    targets=targets,
                    actor_ids=actor_ids,
                    window_start=window_start,
                    window_end=window_end,
                    timezone=timezone,
                    runtime=runtime,
                    error=exc,
                )
            )

    repository_ids = [repository.target.canonical_id for repository in repositories]
    plan = _collection_plan(
        window_start=window_start,
        window_end=window_end,
        timezone=timezone,
        repository_ids=repository_ids,
        actor_ids=actor_ids,
        grouped=grouped,
        provider_options=provider_options,
        provider_runtime=provider_runtime,
    )
    merged = _merge_bundles(
        collected,
        window_start=window_start,
        window_end=window_end,
        timezone=timezone,
        repository_ids=repository_ids,
        actor_ids=actor_ids,
    )
    return _finalize_v03(
        merged,
        plan=plan,
        started_at=started_at,
        finished_at=utc_now(),
    )
