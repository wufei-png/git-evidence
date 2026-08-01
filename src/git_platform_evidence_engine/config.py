from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .render import LANGUAGES, PROFILES
from .providers.catalog import PROVIDER_DESCRIPTORS


class ConfigError(ValueError):
    """Configuration is unsafe or insufficient for a collection plan."""


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


def load_config(path: str | Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(str(exc)) from exc
    if not isinstance(raw, dict):
        raise ConfigError("configuration root must be an object")

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
        if repository["provider"] not in PROVIDER_DESCRIPTORS:
            raise ConfigError(f"scope.repositories[{index}].provider is unsupported: {repository['provider']}")

    providers = raw.get("providers")
    if not isinstance(providers, dict):
        raise ConfigError("providers is required")
    for provider_kind, provider_config in providers.items():
        if not isinstance(provider_kind, str) or not isinstance(provider_config, dict):
            raise ConfigError("providers entries must be objects keyed by provider kind")
        if provider_kind not in PROVIDER_DESCRIPTORS:
            raise ConfigError(f"unsupported provider: {provider_kind}")
        token_env = provider_config.get("token_env")
        if token_env is not None and (not isinstance(token_env, str) or not token_env):
            raise ConfigError(f"providers.{provider_kind}.token_env must be a non-empty string")
        if "include_activity_api" in provider_config and not isinstance(
            provider_config["include_activity_api"], bool
        ):
            raise ConfigError(f"providers.{provider_kind}.include_activity_api must be boolean")
        if "verify_tls" in provider_config and not isinstance(provider_config["verify_tls"], bool):
            raise ConfigError(f"providers.{provider_kind}.verify_tls must be boolean")
    configured_providers = set(providers)
    missing_provider_config = sorted(
        {repository["provider"] for repository in repositories} - configured_providers
    )
    if missing_provider_config:
        raise ConfigError(
            "missing provider configuration: " + ", ".join(missing_provider_config)
        )

    report = raw.get("report") or {}
    if not isinstance(report, dict):
        raise ConfigError("report must be an object")
    profile = report.get("profile", "project-first")
    language = report.get("language", "en")
    if profile not in PROFILES:
        raise ConfigError(f"report.profile must be one of {', '.join(PROFILES)}")
    if language not in LANGUAGES:
        raise ConfigError(f"report.language must be one of {', '.join(LANGUAGES)}")
    if not isinstance(report.get("display_actor_names", False), bool):
        raise ConfigError("report.display_actor_names must be boolean")

    return raw
