from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Callable

from .providers import CollectionRequest, GiteeProvider, GitHubProvider, GitLabProvider, RepositoryTarget
from .providers.base import RESOURCE_SOURCES


class CollectionError(ValueError):
    """The collection plan cannot be executed safely."""


ProviderFactory = Callable[[str, str, dict[str, Any], str | None], Any]


def _timestamp_text(value: Any, field: str) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise CollectionError(f"{field} must include a timezone")
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, str) and value:
        return value
    raise CollectionError(f"{field} must be a non-empty timestamp")


def _default_provider_factory(
    kind: str, instance: str, provider_config: dict[str, Any], token: str | None
) -> Any:
    verify_tls = provider_config.get("verify_tls", True)
    if kind == "github":
        return GitHubProvider(instance=instance, token=token, verify_tls=verify_tls)
    if kind == "gitlab":
        return GitLabProvider(instance=instance, token=token, verify_tls=verify_tls)
    if kind == "gitee":
        return GiteeProvider(instance=instance, token=token, verify_tls=verify_tls)
    raise CollectionError(f"unsupported provider: {kind}")


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
        "coverage": {
            "required_sources": list(RESOURCE_SOURCES),
            "observations": [],
            "fatal": [],
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
        for key in collection_keys:
            for item in bundle.get(key, []):
                entity_id = item.get("id") if isinstance(item, dict) else None
                if not isinstance(entity_id, str) or entity_id in seen[key]:
                    continue
                seen[key].add(entity_id)
                merged[key].append(item)
        coverage = bundle.get("coverage") or {}
        merged["coverage"]["observations"].extend(coverage.get("observations") or [])
        merged["coverage"]["fatal"].extend(coverage.get("fatal") or [])
        if coverage.get("allow_publish") is not True:
            merged["coverage"]["allow_publish"] = False
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
    for index, item in enumerate(repositories):
        if not isinstance(item, dict):
            raise CollectionError(f"scope.repositories[{index}] must be an object")
        kind = item.get("provider")
        instance = item.get("instance")
        owner = item.get("owner")
        name = item.get("name")
        if not all(isinstance(value, str) and value for value in (kind, instance, owner, name)):
            raise CollectionError(f"scope.repositories[{index}] has incomplete provider target")
        provider_config = provider_configs.get(kind)
        if not isinstance(provider_config, dict):
            raise CollectionError(f"missing provider configuration: {kind}")
        group_key = (kind, instance)
        grouped[group_key].append(RepositoryTarget(kind, instance, owner, name))
        provider_options[group_key] = provider_config

    factory = provider_factory or _default_provider_factory
    collected: list[dict[str, Any]] = []
    for (kind, instance), targets in sorted(grouped.items()):
        options = provider_options[(kind, instance)]
        token_env = options.get("token_env")
        if token_env is not None and (not isinstance(token_env, str) or not token_env):
            raise CollectionError(f"providers.{kind}.token_env must be a non-empty string")
        token = os.environ.get(token_env) if token_env else None
        if token_env and not token:
            raise CollectionError(
                f"providers.{kind}.token_env is configured but the environment variable is not set"
            )
        provider = factory(kind, instance, options, token)
        request = CollectionRequest(
            provider_kind=kind,
            instance=instance,
            repositories=tuple(targets),
            window_start=window_start,
            window_end=window_end,
            timezone=timezone,
            include_activity_api=bool(options.get("include_activity_api", False)),
            actor_ids=tuple(actor_ids),
        )
        collected.append(provider.collect(request))

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
