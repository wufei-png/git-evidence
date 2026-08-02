from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Callable

from .config import provider_runtime_options
from .model import COLLECTION_KEYS
from .privacy import PrivacyError, sanitize_public_payload
from .providers import CollectionRequest, PROVIDER_REGISTRY, RepositoryTarget
from .providers.base import ACTIVITY_SOURCES, ProviderNotReady, RESOURCE_SOURCES
from .providers.resource_base import StrictNormalizationError, api_error_diagnostics
from .providers.transport import ApiError, ResponseShapeError, empty_transport_metrics
from .validation import validate_bundle


class CollectionError(ValueError):
    """The collection plan cannot be executed safely."""


class PrivacyResponseError(ResponseShapeError):
    """Provider output crossed the public boundary with credential material."""

    def __init__(self, message: str) -> None:
        super().__init__(message, failure_class="privacy_violation")


ProviderFactory = Callable[[str, str, dict[str, Any], str | None], Any]


def _timestamp_text(value: Any, field: str) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise CollectionError(f"{field} must include a timezone")
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, str) and value:
        return value
    raise CollectionError(f"{field} must be a non-empty timestamp")


def _group_failure_diagnostics(error: Exception) -> tuple[str, dict[str, Any]]:
    if isinstance(error, ProviderNotReady):
        return "provider_not_ready", {"failure_class": "provider_not_ready"}
    if isinstance(error, PrivacyError):
        return "privacy_violation", {"failure_class": "privacy_violation"}
    if isinstance(error, (StrictNormalizationError, ResponseShapeError)):
        diagnostics = api_error_diagnostics(error)
        return diagnostics.get("failure_class", "malformed_response"), diagnostics
    if isinstance(error, ApiError):
        return error.failure_class or "transport_error", api_error_diagnostics(error)
    return "unexpected_error", {
        "failure_class": "unexpected_error",
        "exception_type": type(error).__name__,
    }


def _validate_provider_bundle_shape(bundle: Any) -> dict[str, Any]:
    """Validate the container shapes consumed by the group merge boundary."""
    try:
        bundle = sanitize_public_payload(bundle)
    except PrivacyError as exc:
        raise PrivacyResponseError(str(exc)) from exc
    if not isinstance(bundle, dict):
        raise ResponseShapeError("provider returned a non-object bundle")

    for key in COLLECTION_KEYS:
        if key not in bundle:
            continue
        value = bundle[key]
        if not isinstance(value, list):
            raise ResponseShapeError(f"provider bundle {key} must be an array")
        seen_ids: set[str] = set()
        for position, item in enumerate(value):
            if not isinstance(item, dict):
                raise ResponseShapeError(f"provider bundle {key}[{position}] must be an object")
            entity_id = item.get("id")
            if not isinstance(entity_id, str) or not entity_id.strip():
                raise ResponseShapeError(f"provider bundle {key}[{position}] is missing a non-empty id")
            if entity_id in seen_ids:
                raise ResponseShapeError(f"provider bundle {key} contains duplicate id: {entity_id}")
            seen_ids.add(entity_id)

    coverage = bundle.get("coverage")
    if coverage is not None and not isinstance(coverage, dict):
        raise ResponseShapeError("provider bundle coverage must be an object")
    if isinstance(coverage, dict):
        for key in ("required_sources", "observations", "fatal", "group_failures"):
            if key in coverage and not isinstance(coverage[key], list):
                raise ResponseShapeError(f"provider bundle coverage.{key} must be an array")
        if "allow_publish" in coverage and not isinstance(coverage["allow_publish"], bool):
            raise ResponseShapeError("provider bundle coverage.allow_publish must be boolean")

    collection = bundle.get("collection")
    if collection is not None and not isinstance(collection, dict):
        raise ResponseShapeError("provider bundle collection must be an object")
    if isinstance(collection, dict):
        for key in ("groups",):
            if key in collection and not isinstance(collection[key], list):
                raise ResponseShapeError(f"provider bundle collection.{key} must be an array")
        for key in ("limits", "metrics", "group"):
            if key in collection and collection[key] is not None and not isinstance(collection[key], dict):
                raise ResponseShapeError(f"provider bundle collection.{key} must be an object")

    # A provider group may legitimately be partial when its coverage ledger
    # records a failed repository. Validate all other schema/semantic
    # invariants before the aggregate merge; coverage and the corresponding
    # missing repository are diagnosed by the final bundle gate.
    validation_issues = validate_bundle(bundle)
    group_failures = (bundle.get("coverage") or {}).get("group_failures", [])
    hard_issues = [
        issue
        for issue in validation_issues
        if not issue.code.startswith("coverage.")
        and not (issue.code == "scope.repository_missing" and group_failures)
    ]
    if hard_issues:
        details = "; ".join(issue.code for issue in hard_issues[:4])
        raise ResponseShapeError(f"provider bundle semantic validation failed: {details}")
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
    capabilities = {source: "incomplete" for source in (*RESOURCE_SOURCES, *ACTIVITY_SOURCES)}
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
                fatal.append(failure)
    return {
        "schema_version": "0.1",
        "run": {
            "run_id": f"run:{kind}:{instance}:failed",
            "window": {"start": window_start, "end": window_end, "timezone": timezone},
            "scope": {
                "repositories": [target.canonical_id for target in targets],
                "actors": actor_ids,
            },
        },
        "providers": [{
            "id": provider_id,
            "kind": kind,
            "instance": instance,
            "capabilities": capabilities,
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
            "metrics": empty_transport_metrics(cache_enabled=bool(runtime["cache_enabled"])),
        },
        "privacy": {
            "actor_display": "anonymous",
            "source_urls": "sanitized",
            "auth_redaction": True,
        },
        "coverage": {
            "required_sources": list(RESOURCE_SOURCES),
            "observations": observations,
            "fatal": fatal,
            "group_failures": group_failures,
            "allow_publish": False,
        },
    }


def _bundle_group_identity(bundle: dict[str, Any]) -> tuple[str, str, list[str]]:
    collection = bundle.get("collection")
    if isinstance(collection, dict):
        provider = collection.get("provider")
        instance = collection.get("instance")
        if isinstance(provider, str) and isinstance(instance, str):
            scope = (bundle.get("run") or {}).get("scope") if isinstance(bundle.get("run"), dict) else {}
            repositories = scope.get("repositories", []) if isinstance(scope, dict) else []
            return provider, instance, [item for item in repositories if isinstance(item, str)]
    providers = bundle.get("providers")
    if isinstance(providers, list) and providers and isinstance(providers[0], dict):
        provider = providers[0]
        kind = provider.get("kind")
        instance = provider.get("instance")
        if isinstance(kind, str) and isinstance(instance, str):
            scope = (bundle.get("run") or {}).get("scope") if isinstance(bundle.get("run"), dict) else {}
            repositories = scope.get("repositories", []) if isinstance(scope, dict) else []
            return kind, instance, [item for item in repositories if isinstance(item, str)]
    return "unknown", "unknown", []


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
        repository = scoped_repositories[0] if scoped_repositories else "unknown-repository"
    source = source_category if source_category in RESOURCE_SOURCES else "repositories"
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
        merged["coverage"]["observations"].append(
            {
                "source": source,
                "provider_id": provider_id,
                "repository_id": repository,
                "status": "incomplete",
                "diagnostics": {"failure_class": "malformed_response", "group_failure": True, "reason": reason},
            }
        )
    else:
        for observation in observations:
            observation["status"] = "incomplete"
            diagnostics = observation.setdefault("diagnostics", {})
            if isinstance(diagnostics, dict):
                diagnostics.update(
                    {"failure_class": "malformed_response", "group_failure": True, "reason": reason}
                )
    if source in RESOURCE_SOURCES:
        merged["coverage"]["fatal"].append(failure)
    merged["coverage"]["allow_publish"] = False


def _merge_bundles(
    bundles: list[dict[str, Any]],
    *,
    window_start: str,
    window_end: str,
    timezone: str,
    repository_ids: list[str],
    actor_ids: list[str],
) -> dict[str, Any]:
    identity = json.dumps(
        {
            "window": [window_start, window_end, timezone],
            "repositories": repository_ids,
            "actors": actor_ids,
        },
        ensure_ascii=True,
        sort_keys=True,
    ).encode("utf-8")
    run_digest = hashlib.sha256(identity).hexdigest()[:12]
    merged: dict[str, Any] = {
        "schema_version": "0.1",
        "run": {
            "run_id": f"run:aggregate:{run_digest}",
            "window": {"start": window_start, "end": window_end, "timezone": timezone},
            "scope": {"repositories": repository_ids, "actors": actor_ids},
        },
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
        "facts": [],
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
            "allow_publish": True,
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
        "facts",
    )
    seen: dict[str, set[str]] = {key: set() for key in collection_keys}
    for bundle in bundles:
        coverage = bundle.get("coverage") or {}
        merged["coverage"]["observations"].extend(coverage.get("observations") or [])
        merged["coverage"]["fatal"].extend(coverage.get("fatal") or [])
        merged["coverage"]["group_failures"].extend(coverage.get("group_failures") or [])
        if coverage.get("allow_publish") is not True:
            merged["coverage"]["allow_publish"] = False
        for key in collection_keys:
            for item in bundle.get(key, []):
                entity_id = item.get("id") if isinstance(item, dict) else None
                if not isinstance(entity_id, str) or not entity_id.strip():
                    _record_merge_failure(merged, bundle, key, item, "record is missing a non-empty id")
                    continue
                if entity_id in seen[key]:
                    _record_merge_failure(merged, bundle, key, item, f"duplicate record id: {entity_id}")
                    continue
                seen[key].add(entity_id)
                merged[key].append(item)
        collection = bundle.get("collection") or {}
        if isinstance(collection, dict):
            group = collection.get("group")
            if not isinstance(group, dict):
                group = {
                    key: value
                    for key, value in collection.items()
                    if key in {"provider", "instance", "group_status", "failure_class", "limits", "metrics"}
                }
            if group:
                merged["collection"]["groups"].append(group)
            incoming_metrics = collection.get("metrics")
            if isinstance(incoming_metrics, dict):
                aggregate = merged["collection"]["metrics"]
                for key in ("request_count", "page_count", "retry_count", "cache_hits", "cache_misses"):
                    value = incoming_metrics.get(key)
                    if isinstance(value, int) and value >= 0:
                        aggregate[key] += value
                aggregate["budget_exhausted"] = bool(
                    aggregate["budget_exhausted"] or incoming_metrics.get("budget_exhausted", False)
                )
                aggregate["cache_enabled"] = bool(
                    aggregate["cache_enabled"] or incoming_metrics.get("cache_enabled", False)
                )
    return merged


def collect_config(
    config: dict[str, Any],
    *,
    provider_factory: ProviderFactory | None = None,
) -> dict[str, Any]:
    """Collect all explicitly allowlisted repositories into one canonical bundle."""
    window = config.get("window") or {}
    window_start = _timestamp_text(window.get("start"), "window.start")
    window_end = _timestamp_text(window.get("end"), "window.end")
    timezone = window.get("timezone")
    if not isinstance(timezone, str) or not timezone:
        raise CollectionError("window.timezone must be non-empty")
    scope = config.get("scope") or {}
    repositories = scope.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise CollectionError("scope.repositories must be a non-empty allowlist")
    actor_ids = scope.get("actors", [])
    if not isinstance(actor_ids, list) or not all(isinstance(value, str) and value for value in actor_ids):
        raise CollectionError("scope.actors must be an array of non-empty actor IDs")
    if len(actor_ids) != len(set(actor_ids)):
        raise CollectionError("scope.actors must not contain duplicate actor IDs")
    provider_configs = config.get("providers")
    if not isinstance(provider_configs, dict):
        raise CollectionError("providers must be an object")

    grouped: dict[tuple[str, str], list[RepositoryTarget]] = defaultdict(list)
    provider_options: dict[tuple[str, str], dict[str, Any]] = {}
    provider_runtime: dict[tuple[str, str], dict[str, Any]] = {}
    for index, item in enumerate(repositories):
        if not isinstance(item, dict):
            raise CollectionError(f"scope.repositories[{index}] must be an object")
        kind = item.get("provider")
        instance = item.get("instance")
        owner = item.get("owner")
        name = item.get("name")
        if not all(isinstance(value, str) and value for value in (kind, instance, owner, name)):
            raise CollectionError(f"scope.repositories[{index}] has incomplete provider target")
        if not PROVIDER_REGISTRY.contains(kind):
            raise CollectionError(f"unsupported provider: {kind}")
        provider_config = provider_configs.get(kind)
        if not isinstance(provider_config, dict):
            raise CollectionError(f"missing provider configuration: {kind}")
        group_key = (kind, instance)
        grouped[group_key].append(RepositoryTarget(kind, instance, owner, name))
        provider_options[group_key] = provider_config
        try:
            provider_runtime[group_key] = provider_runtime_options(kind, provider_config)
        except ValueError as exc:
            raise CollectionError(str(exc)) from exc

    collected: list[dict[str, Any]] = []
    group_plans: list[tuple[tuple[str, str], list[RepositoryTarget], dict[str, Any], str | None]] = []
    for group_key, targets in sorted(grouped.items()):
        kind, instance = group_key
        options = provider_options[group_key]
        token_env = options.get("token_env")
        if token_env is not None and (not isinstance(token_env, str) or not token_env):
            raise CollectionError(f"providers.{kind}.token_env must be a non-empty string")
        token = os.environ.get(token_env) if token_env else None
        if token_env and not token:
            raise CollectionError(
                f"providers.{kind}.token_env is configured but the environment variable is not set"
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
        except Exception as exc:
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

    repository_ids = [
        RepositoryTarget(item["provider"], item["instance"], item["owner"], item["name"]).canonical_id
        for item in repositories
    ]
    return _merge_bundles(
        collected,
        window_start=window_start,
        window_end=window_end,
        timezone=timezone,
        repository_ids=repository_ids,
        actor_ids=actor_ids,
    )
