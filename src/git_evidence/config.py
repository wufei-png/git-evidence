from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

import yaml

from .providers.catalog import PROVIDER_REGISTRY
from .render import LANGUAGES, PROFILES


class ConfigError(ValueError):
    """Configuration is unsafe or insufficient for a collection or report."""


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


def _normalized_key(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_")


def provider_runtime_options(provider_kind: str, provider_config: dict[str, Any]) -> dict[str, Any]:
    """Validate and materialize bounded transport/cache settings for one group."""
    if not isinstance(provider_config, dict):
        raise ConfigError(f"providers.{provider_kind} must be an object")

    def number(name: str, default: float, *, minimum: float, integer: bool = False) -> int | float:
        value = provider_config.get(name, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"providers.{provider_kind}.{name} must be numeric")
        if value < minimum:
            raise ConfigError(f"providers.{provider_kind}.{name} must be at least {minimum}")
        if integer and not isinstance(value, int):
            raise ConfigError(f"providers.{provider_kind}.{name} must be an integer")
        return value

    cache = provider_config.get("cache", {})
    if not isinstance(cache, dict):
        raise ConfigError(f"providers.{provider_kind}.cache must be an object")
    cache_enabled = cache.get("enabled", False)
    if not isinstance(cache_enabled, bool):
        raise ConfigError(f"providers.{provider_kind}.cache.enabled must be boolean")
    cache_path = cache.get("path")
    if cache_path is not None and (not isinstance(cache_path, str) or not cache_path.strip()):
        raise ConfigError(f"providers.{provider_kind}.cache.path must be a non-empty string")
    cache_ttl = cache.get("ttl_seconds", 300.0)
    if isinstance(cache_ttl, bool) or not isinstance(cache_ttl, (int, float)) or cache_ttl <= 0:
        raise ConfigError(f"providers.{provider_kind}.cache.ttl_seconds must be greater than zero")
    cache_max_entries = cache.get("max_entries", 256)
    if isinstance(cache_max_entries, bool) or not isinstance(cache_max_entries, int) or cache_max_entries < 1:
        raise ConfigError(f"providers.{provider_kind}.cache.max_entries must be a positive integer")
    if cache_enabled and (
        not cache_path
        or not {"path", "ttl_seconds", "max_entries"}.issubset(cache)
    ):
        raise ConfigError(
            f"providers.{provider_kind}.cache.path, ttl_seconds, and max_entries are required when cache is enabled"
        )
    return {
        "timeout_seconds": number("timeout_seconds", 30.0, minimum=0.001),
        "max_retries": number("max_retries", 2, minimum=0, integer=True),
        "max_pages": number("max_pages", 100, minimum=1, integer=True),
        "max_requests": number("max_requests", 1000, minimum=1, integer=True),
        "retry_backoff_seconds": number("retry_backoff_seconds", 0.5, minimum=0.0),
        "retry_jitter_seconds": number("retry_jitter_seconds", 0.25, minimum=0.0),
        "retry_after_max_seconds": number("retry_after_max_seconds", 60.0, minimum=0.001),
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
    window = raw.get("window")
    if not isinstance(window, dict):
        raise ConfigError("window is required")
    start = _aware_timestamp(window.get("start"), "window.start")
    end = _aware_timestamp(window.get("end"), "window.end")
    if start >= end:
        raise ConfigError("window.start must be before window.end")
    if not isinstance(window.get("timezone"), str) or not window["timezone"]:
        raise ConfigError("window.timezone is required")

    scope = raw.get("scope")
    if not isinstance(scope, dict):
        raise ConfigError("scope is required")
    repositories = scope.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ConfigError("scope.repositories must be a non-empty allowlist")
    for index, repository in enumerate(repositories):
        if not isinstance(repository, dict):
            raise ConfigError(f"scope.repositories[{index}] must be an object")
        for key in ("provider", "instance", "owner", "name"):
            if not isinstance(repository.get(key), str) or not repository[key]:
                raise ConfigError(f"scope.repositories[{index}].{key} is required")
        provider = repository["provider"]
        if not PROVIDER_REGISTRY.contains(provider):
            raise ConfigError(f"scope.repositories[{index}].provider is unsupported: {provider}")

    actors = scope.get("actors", [])
    if not isinstance(actors, list) or not all(isinstance(value, str) and value for value in actors):
        raise ConfigError("scope.actors must be an array of non-empty actor IDs")
    if len(actors) != len(set(actors)):
        raise ConfigError("scope.actors must not contain duplicate actor IDs")

    providers = raw.get("providers")
    if not isinstance(providers, dict):
        raise ConfigError("providers is required")
    for provider_kind, provider_config in providers.items():
        if not isinstance(provider_kind, str) or not isinstance(provider_config, dict):
            raise ConfigError("providers entries must be objects keyed by provider kind")
        if not PROVIDER_REGISTRY.contains(provider_kind):
            raise ConfigError(f"unsupported provider: {provider_kind}")
        for key in provider_config:
            if _normalized_key(key) in INLINE_SECRET_KEYS:
                raise ConfigError(
                    f"providers.{provider_kind}.{key} must not contain credentials; use token_env"
                )
        token_env = provider_config.get("token_env")
        if token_env is not None and (not isinstance(token_env, str) or not token_env):
            raise ConfigError(f"providers.{provider_kind}.token_env must be a non-empty string")
        if "include_activity_api" in provider_config and not isinstance(
            provider_config["include_activity_api"], bool
        ):
            raise ConfigError(f"providers.{provider_kind}.include_activity_api must be boolean")
        if "verify_tls" in provider_config and not isinstance(provider_config["verify_tls"], bool):
            raise ConfigError(f"providers.{provider_kind}.verify_tls must be boolean")
        provider_runtime_options(provider_kind, provider_config)
    configured_providers = set(providers)
    missing_provider_config = sorted(
        {repository["provider"] for repository in repositories} - configured_providers
    )
    if missing_provider_config:
        raise ConfigError(
            "missing provider configuration: " + ", ".join(missing_provider_config)
        )


def _report_mapping(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    report = raw.get("report") if "report" in raw else raw
    if report is None:
        return {}
    if not isinstance(report, dict):
        raise ConfigError("report must be an object")
    return report


def validate_report_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize only report/profile/privacy settings."""
    report = _report_mapping(config)
    profile = report.get("profile", DEFAULT_REPORT_PROFILE)
    language = report.get("language", DEFAULT_REPORT_LANGUAGE)
    if profile not in PROFILES:
        raise ConfigError(f"report.profile must be one of {', '.join(PROFILES)}")
    if language not in LANGUAGES:
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
            raise ConfigError(f"report.actor_labels[{actor_id!r}] must be a non-empty label")

    privacy = report.get("privacy", {})
    if privacy is None:
        privacy = {}
    if not isinstance(privacy, dict):
        raise ConfigError("report.privacy must be an object")
    actor_display = privacy.get("actor_display", DEFAULT_ACTOR_DISPLAY)
    if actor_display not in {"anonymous", "explicit-labels"}:
        raise ConfigError("report.privacy.actor_display must be anonymous or explicit-labels")
    if display_actor_names and "actor_display" in privacy and actor_display == "anonymous":
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
    return dict(config)


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
