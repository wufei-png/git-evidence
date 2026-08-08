from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .limits import (
    MAX_CACHE_ENTRIES,
    MAX_CACHE_TTL_SECONDS,
    MAX_PAGES,
    MAX_REQUESTS,
    MAX_RETRIES,
    MAX_RETRY_AFTER_SECONDS,
    MAX_RETRY_BACKOFF_SECONDS,
    MAX_RETRY_JITTER_SECONDS,
    MAX_TIMEOUT_SECONDS,
    MIN_CORE_REQUESTS_PER_REPOSITORY,
    MIN_RETRY_AFTER_SECONDS,
    MIN_TIMEOUT_SECONDS,
)
from .privacy import canonicalize_field_name, is_sensitive_field
from .providers.base import (
    RepositoryTarget,
    is_loopback_instance,
    validate_instance,
    validate_timezone,
)
from .providers.catalog import PROVIDER_REGISTRY
from .render import LANGUAGES, PROFILES


class ConfigError(ValueError):
    """Configuration is unsafe or insufficient for a collection or report."""


class PlanBudgetInfeasibleConfigError(ConfigError):
    """A provider-instance group cannot attempt its minimum required core work."""

    code = "plan_budget_infeasible"


DEFAULT_REPORT_PROFILE = "project-first"
DEFAULT_REPORT_LANGUAGE = "en"
DEFAULT_ACTOR_DISPLAY = "anonymous"
DEFAULT_ALLOW_SOURCE_URLS = True
INLINE_SECRET_KEYS = frozenset(
    {
        "authorization",
        "api_key",
        "apikey",
        "access_token",
        "client_secret",
        "cookie",
        "credential",
        "credentials",
        "id_token",
        "password",
        "private_token",
        "proxy_authorization",
        "refresh_token",
        "secret",
        "token",
    }
)

ROOT_KEYS = frozenset({"window", "scope", "providers", "report"})
WINDOW_KEYS = frozenset({"start", "end", "timezone"})
SCOPE_KEYS = frozenset({"repositories", "actors"})
REPOSITORY_KEYS = frozenset({"provider", "instance", "owner", "name"})
PROVIDER_KEYS = frozenset(
    {
        "token_env",
        "include_activity_api",
        "verify_tls",
        "allow_insecure_loopback",
        "timeout_seconds",
        "max_retries",
        "max_pages",
        "max_requests",
        "retry_backoff_seconds",
        "retry_jitter_seconds",
        "retry_after_max_seconds",
        "cache",
    }
)
CACHE_KEYS = frozenset({"enabled", "path", "ttl_seconds", "max_entries"})
REPORT_KEYS = frozenset(
    {"profile", "language", "display_actor_names", "actor_labels", "privacy"}
)
PRIVACY_KEYS = frozenset({"actor_display", "allow_source_urls", "auth_redaction"})


def _reject_unknown_keys(
    value: Mapping[str, Any], allowed: frozenset[str], path: str
) -> None:
    unknown = sorted(
        repr(key) for key in value if not isinstance(key, str) or key not in allowed
    )
    if unknown:
        raise ConfigError(f"{path} contains unknown key(s): {', '.join(unknown)}")


def _reject_report_unknown_keys(raw: Mapping[str, Any]) -> None:
    """Reject report typos without coupling collection to report value policy."""
    if "report" not in raw:
        return
    report = raw["report"]
    if not isinstance(report, Mapping):
        return
    _reject_unknown_keys(report, REPORT_KEYS, "report")
    privacy = report.get("privacy")
    if isinstance(privacy, Mapping):
        _reject_unknown_keys(privacy, PRIVACY_KEYS, "report.privacy")


def _normalized_key(value: Any) -> str:
    return canonicalize_field_name(value)


def provider_runtime_options(
    provider_kind: str, provider_config: dict[str, Any]
) -> dict[str, Any]:
    """Validate and materialize bounded transport/cache settings for one group."""
    if not isinstance(provider_config, dict):
        raise ConfigError(f"providers.{provider_kind} must be an object")
    _reject_unknown_keys(provider_config, PROVIDER_KEYS, f"providers.{provider_kind}")

    def number(
        name: str,
        default: float,
        *,
        minimum: float,
        maximum: float,
        integer: bool = False,
    ) -> int | float:
        value = provider_config.get(name, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"providers.{provider_kind}.{name} must be numeric")
        if not math.isfinite(float(value)):
            raise ConfigError(f"providers.{provider_kind}.{name} must be finite")
        if value < minimum:
            raise ConfigError(
                f"providers.{provider_kind}.{name} must be at least {minimum}"
            )
        if value > maximum:
            raise ConfigError(
                f"providers.{provider_kind}.{name} must be at most {maximum}"
            )
        if integer and not isinstance(value, int):
            raise ConfigError(f"providers.{provider_kind}.{name} must be an integer")
        return value

    cache = provider_config.get("cache", {})
    if not isinstance(cache, dict):
        raise ConfigError(f"providers.{provider_kind}.cache must be an object")
    _reject_unknown_keys(cache, CACHE_KEYS, f"providers.{provider_kind}.cache")
    cache_enabled = cache.get("enabled", False)
    if not isinstance(cache_enabled, bool):
        raise ConfigError(f"providers.{provider_kind}.cache.enabled must be boolean")
    cache_path = cache.get("path")
    if cache_path is not None and (
        not isinstance(cache_path, str) or not cache_path.strip()
    ):
        raise ConfigError(
            f"providers.{provider_kind}.cache.path must be a non-empty string"
        )
    cache_ttl = cache.get("ttl_seconds", 300.0)
    if isinstance(cache_ttl, bool) or not isinstance(cache_ttl, (int, float)):
        raise ConfigError(
            f"providers.{provider_kind}.cache.ttl_seconds must be numeric"
        )
    if not math.isfinite(float(cache_ttl)):
        raise ConfigError(f"providers.{provider_kind}.cache.ttl_seconds must be finite")
    if cache_ttl <= 0 or cache_ttl > MAX_CACHE_TTL_SECONDS:
        raise ConfigError(
            f"providers.{provider_kind}.cache.ttl_seconds must be in (0, {MAX_CACHE_TTL_SECONDS}]"
        )
    cache_max_entries = cache.get("max_entries", 256)
    if (
        isinstance(cache_max_entries, bool)
        or not isinstance(cache_max_entries, int)
        or cache_max_entries < 1
        or cache_max_entries > MAX_CACHE_ENTRIES
    ):
        raise ConfigError(
            f"providers.{provider_kind}.cache.max_entries must be in [1, {MAX_CACHE_ENTRIES}]"
        )
    if cache_enabled and (
        not cache_path or not {"path", "ttl_seconds", "max_entries"}.issubset(cache)
    ):
        raise ConfigError(
            f"providers.{provider_kind}.cache.path, ttl_seconds, and max_entries are required when cache is enabled"
        )
    return {
        "timeout_seconds": number(
            "timeout_seconds",
            30.0,
            minimum=MIN_TIMEOUT_SECONDS,
            maximum=MAX_TIMEOUT_SECONDS,
        ),
        "max_retries": number(
            "max_retries", 2, minimum=0, maximum=MAX_RETRIES, integer=True
        ),
        "max_pages": number(
            "max_pages", 100, minimum=1, maximum=MAX_PAGES, integer=True
        ),
        "max_requests": number(
            "max_requests", 1000, minimum=1, maximum=MAX_REQUESTS, integer=True
        ),
        "retry_backoff_seconds": number(
            "retry_backoff_seconds", 0.5, minimum=0.0, maximum=MAX_RETRY_BACKOFF_SECONDS
        ),
        "retry_jitter_seconds": number(
            "retry_jitter_seconds", 0.25, minimum=0.0, maximum=MAX_RETRY_JITTER_SECONDS
        ),
        "retry_after_max_seconds": number(
            "retry_after_max_seconds",
            60.0,
            minimum=MIN_RETRY_AFTER_SECONDS,
            maximum=MAX_RETRY_AFTER_SECONDS,
        ),
        "cache_enabled": cache_enabled,
        "cache_path": cache_path,
        "cache_ttl_seconds": cache_ttl,
        "cache_max_entries": cache_max_entries,
    }


def _aware_timestamp(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ConfigError(f"{field} must include a timezone")
        return value
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{field} must be a non-empty ISO timestamp")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConfigError(f"{field} is not a valid ISO timestamp") from exc
    if timestamp.tzinfo is None:
        raise ConfigError(f"{field} must include a timezone")
    return timestamp


def _read_config(path: str | Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(str(exc)) from exc
    if not isinstance(raw, dict):
        raise ConfigError("configuration root must be an object")
    return raw


def _validate_collection_mapping(raw: Mapping[str, Any]) -> None:
    _reject_unknown_keys(raw, ROOT_KEYS, "configuration")
    _reject_report_unknown_keys(raw)
    window = raw.get("window")
    if not isinstance(window, dict):
        raise ConfigError("window is required")
    _reject_unknown_keys(window, WINDOW_KEYS, "window")
    start = _aware_timestamp(window.get("start"), "window.start")
    end = _aware_timestamp(window.get("end"), "window.end")
    if start >= end:
        raise ConfigError("window.start must be before window.end")
    try:
        validate_timezone(window.get("timezone"))
    except ValueError as exc:
        raise ConfigError(f"window.timezone is invalid: {exc}") from exc

    scope = raw.get("scope")
    if not isinstance(scope, dict):
        raise ConfigError("scope is required")
    _reject_unknown_keys(scope, SCOPE_KEYS, "scope")
    repositories = scope.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ConfigError("scope.repositories must be a non-empty allowlist")
    targets: list[RepositoryTarget] = []
    for index, repository in enumerate(repositories):
        if not isinstance(repository, dict):
            raise ConfigError(f"scope.repositories[{index}] must be an object")
        _reject_unknown_keys(
            repository, REPOSITORY_KEYS, f"scope.repositories[{index}]"
        )
        for key in ("provider", "instance", "owner", "name"):
            if not isinstance(repository.get(key), str) or not repository[key]:
                raise ConfigError(f"scope.repositories[{index}].{key} is required")
        provider = repository["provider"]
        if not PROVIDER_REGISTRY.contains(provider):
            raise ConfigError(
                f"scope.repositories[{index}].provider is unsupported: {provider}"
            )
        try:
            target = RepositoryTarget(
                provider,
                repository["instance"],
                repository["owner"],
                repository["name"],
            )
        except ValueError as exc:
            raise ConfigError(f"scope.repositories[{index}] is invalid: {exc}") from exc
        targets.append(target)
    canonical_ids = [target.canonical_id for target in targets]
    duplicate_ids = sorted(
        repository_id
        for repository_id, count in Counter(canonical_ids).items()
        if count > 1
    )
    if duplicate_ids:
        raise ConfigError(
            "scope.repositories contains duplicate canonical repository(s): "
            + ", ".join(duplicate_ids)
        )

    actors = scope.get("actors", [])
    if not isinstance(actors, list) or not all(
        isinstance(value, str) and value for value in actors
    ):
        raise ConfigError("scope.actors must be an array of non-empty actor IDs")
    if len(actors) != len(set(actors)):
        raise ConfigError("scope.actors must not contain duplicate actor IDs")

    providers = raw.get("providers")
    if not isinstance(providers, dict):
        raise ConfigError("providers is required")
    for provider_kind, provider_config in providers.items():
        if not isinstance(provider_kind, str) or not isinstance(provider_config, dict):
            raise ConfigError(
                "providers entries must be objects keyed by provider kind"
            )
        if not PROVIDER_REGISTRY.contains(provider_kind):
            raise ConfigError(f"unsupported provider: {provider_kind}")

        def reject_inline_credentials(
            value: Any, path: str, *, root: bool = False
        ) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    normalized = _normalized_key(key)
                    if normalized == "token_env":
                        if root and key == "token_env":
                            continue
                        if root:
                            raise ConfigError(
                                f"{path}.{key} must use the exact top-level token_env reference"
                            )
                        raise ConfigError(
                            f"{path}.{key} must be a top-level environment reference"
                        )
                    if is_sensitive_field(key):
                        raise ConfigError(
                            f"{path}.{key} must not contain credentials; use token_env"
                        )
                    reject_inline_credentials(child, f"{path}.{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    reject_inline_credentials(child, f"{path}[{index}]")

        reject_inline_credentials(
            provider_config, f"providers.{provider_kind}", root=True
        )
        token_env = provider_config.get("token_env")
        if token_env is not None and (not isinstance(token_env, str) or not token_env):
            raise ConfigError(
                f"providers.{provider_kind}.token_env must be a non-empty string"
            )
        if "include_activity_api" in provider_config and not isinstance(
            provider_config["include_activity_api"], bool
        ):
            raise ConfigError(
                f"providers.{provider_kind}.include_activity_api must be boolean"
            )
        if "verify_tls" in provider_config and not isinstance(
            provider_config["verify_tls"], bool
        ):
            raise ConfigError(f"providers.{provider_kind}.verify_tls must be boolean")
        if "allow_insecure_loopback" in provider_config and not isinstance(
            provider_config["allow_insecure_loopback"], bool
        ):
            raise ConfigError(
                f"providers.{provider_kind}.allow_insecure_loopback must be boolean"
            )
        provider_runtime_options(provider_kind, provider_config)
    configured_providers = set(providers)
    missing_provider_config = sorted(
        {repository["provider"] for repository in repositories} - configured_providers
    )
    if missing_provider_config:
        raise ConfigError(
            "missing provider configuration: " + ", ".join(missing_provider_config)
        )
    group_counts = Counter(
        (target.provider_kind, target.instance) for target in targets
    )
    for (provider_kind, instance), repository_count in sorted(group_counts.items()):
        runtime = provider_runtime_options(provider_kind, providers[provider_kind])
        minimum_core_budget = MIN_CORE_REQUESTS_PER_REPOSITORY * repository_count
        if runtime["max_requests"] < minimum_core_budget:
            raise PlanBudgetInfeasibleConfigError(
                f"plan_budget_infeasible: providers.{provider_kind}.max_requests="
                f"{runtime['max_requests']} cannot cover {repository_count} repositories "
                f"at {instance}; minimum is {minimum_core_budget}"
            )
    for index, repository in enumerate(repositories):
        provider_kind = repository["provider"]
        provider_config = providers[provider_kind]
        instance = targets[index].instance
        token_env = provider_config.get("token_env")
        verify_tls = provider_config.get("verify_tls", True)
        allow_insecure_loopback = provider_config.get("allow_insecure_loopback", False)
        explicit_http = instance.lower().startswith("http://")
        insecure_transport = explicit_http or verify_tls is False
        if token_env and insecure_transport:
            raise ConfigError(
                f"scope.repositories[{index}] authenticated requests require HTTPS "
                "with TLS verification"
            )
        if insecure_transport and not (
            allow_insecure_loopback and is_loopback_instance(instance) and not token_env
        ):
            raise ConfigError(
                f"scope.repositories[{index}] insecure transport requires explicit "
                "credentialless loopback development mode"
            )


def _report_mapping(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    if "report" in raw:
        _reject_unknown_keys(raw, ROOT_KEYS, "configuration")
        report = raw.get("report")
    elif any(key in raw for key in ("window", "scope", "providers")):
        _reject_unknown_keys(raw, ROOT_KEYS, "configuration")
        report = {}
    else:
        report = raw
    if report is None:
        return {}
    if not isinstance(report, dict):
        raise ConfigError("report must be an object")
    _reject_unknown_keys(report, REPORT_KEYS, "report")
    return report


def validate_report_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize only report/profile/privacy settings."""
    report = _report_mapping(config)
    profile = report.get("profile", DEFAULT_REPORT_PROFILE)
    language = report.get("language", DEFAULT_REPORT_LANGUAGE)
    if not isinstance(profile, str) or profile not in PROFILES:
        raise ConfigError(f"report.profile must be one of {', '.join(PROFILES)}")
    if not isinstance(language, str) or language not in LANGUAGES:
        raise ConfigError(f"report.language must be one of {', '.join(LANGUAGES)}")

    display_actor_names = report.get("display_actor_names", False)
    if not isinstance(display_actor_names, bool):
        raise ConfigError("report.display_actor_names must be boolean")
    actor_labels = report.get("actor_labels", {})
    if not isinstance(actor_labels, dict):
        raise ConfigError("report.actor_labels must be an object")
    for actor_id, label in actor_labels.items():
        if not isinstance(actor_id, str) or not actor_id:
            raise ConfigError("report.actor_labels keys must be non-empty actor IDs")
        if not isinstance(label, str) or not label.strip():
            raise ConfigError(
                f"report.actor_labels[{actor_id!r}] must be a non-empty label"
            )

    privacy = report.get("privacy", {})
    if privacy is None:
        privacy = {}
    if not isinstance(privacy, dict):
        raise ConfigError("report.privacy must be an object")
    _reject_unknown_keys(privacy, PRIVACY_KEYS, "report.privacy")
    actor_display = privacy.get("actor_display", DEFAULT_ACTOR_DISPLAY)
    if not isinstance(actor_display, str) or actor_display not in {
        "anonymous",
        "explicit-labels",
    }:
        raise ConfigError(
            "report.privacy.actor_display must be anonymous or explicit-labels"
        )
    if (
        display_actor_names
        and "actor_display" in privacy
        and actor_display == "anonymous"
    ):
        raise ConfigError(
            "report.display_actor_names conflicts with report.privacy.actor_display=anonymous"
        )
    if display_actor_names:
        actor_display = "explicit-labels"
    allow_source_urls = privacy.get("allow_source_urls", DEFAULT_ALLOW_SOURCE_URLS)
    if not isinstance(allow_source_urls, bool):
        raise ConfigError("report.privacy.allow_source_urls must be boolean")
    auth_redaction = privacy.get("auth_redaction", True)
    if auth_redaction is not True:
        raise ConfigError("report.privacy.auth_redaction must remain true")

    return {
        "profile": profile,
        "language": language,
        "display_actor_names": actor_display == "explicit-labels",
        "actor_labels": dict(actor_labels),
        "privacy": {
            "actor_display": actor_display,
            "allow_source_urls": allow_source_urls,
            "auth_redaction": True,
        },
    }


def validate_collection_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Validate only collection/window/scope/provider settings."""
    if not isinstance(config, Mapping):
        raise ConfigError("configuration root must be an object")
    _validate_collection_mapping(config)
    validated = dict(config)
    scope = dict(config["scope"])
    scope["repositories"] = sorted(
        (
            {
                **dict(repository),
                "instance": validate_instance(repository["instance"]),
            }
            for repository in scope["repositories"]
        ),
        key=lambda repository: (
            RepositoryTarget(
                repository["provider"],
                repository["instance"],
                repository["owner"],
                repository["name"],
            ).canonical_id
        ),
    )
    validated["scope"] = scope
    return validated


def load_collection_config(path: str | Path) -> dict[str, Any]:
    """Load a collection plan without evaluating report settings."""
    raw = _read_config(path)
    return validate_collection_config(raw)


def load_report_config(path: str | Path) -> dict[str, Any]:
    """Load normalized report/profile/privacy settings without collection checks."""
    return validate_report_config(_read_config(path))


def load_config(path: str | Path) -> dict[str, Any]:
    """Legacy single-file loader that validates both configuration domains."""
    raw = _read_config(path)
    validate_collection_config(raw)
    validate_report_config(raw)
    return raw
