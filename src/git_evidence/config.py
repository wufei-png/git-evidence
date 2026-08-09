from __future__ import annotations

import math
import re
import tomllib
from collections import Counter
from collections.abc import Mapping
from dataclasses import InitVar, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .bounds import InputLimitError, read_bounded_bytes, validate_json_value_limits
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


MAX_CONFIG_BYTES = 1024 * 1024
MAX_CONFIG_DEPTH = 16
MAX_CONFIG_SCALAR_CHARS = 16 * 1024
PROVIDER_REF_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
TOKEN_ENV_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

DEFAULT_REPORT_PROFILE = "project-first"
DEFAULT_REPORT_LANGUAGE = "en"
DEFAULT_ACTOR_DISPLAY = "anonymous"
DEFAULT_ALLOW_SOURCE_URLS = True

ROOT_KEYS = frozenset({"window", "scope", "providers", "report"})
WINDOW_KEYS = frozenset({"start", "end", "timezone"})
SCOPE_KEYS = frozenset({"repositories", "actors"})
REPOSITORY_KEYS = frozenset({"provider_ref", "owner", "name"})
PROVIDER_KEYS = frozenset(
    {"kind", "instance", "token_env", "include_activity_api", "transport", "cache"}
)
TRANSPORT_KEYS = frozenset(
    {
        "verify_tls",
        "allow_insecure_loopback",
        "timeout_seconds",
        "max_retries",
        "max_pages",
        "max_requests",
        "retry_backoff_seconds",
        "retry_jitter_seconds",
        "retry_after_max_seconds",
    }
)
CACHE_KEYS = frozenset({"enabled", "path", "ttl_seconds", "max_entries"})
REPORT_KEYS = frozenset(
    {"profile", "language", "display_actor_names", "actor_labels", "privacy"}
)
PRIVACY_KEYS = frozenset({"actor_display", "allow_source_urls", "auth_redaction"})
_VALIDATED_CONFIG_SEAL = object()


@dataclass(frozen=True)
class RuntimeOptions:
    timeout_seconds: float
    max_retries: int
    max_pages: int
    max_requests: int
    retry_backoff_seconds: float
    retry_jitter_seconds: float
    retry_after_max_seconds: float
    cache_enabled: bool
    cache_path: str | None
    cache_ttl_seconds: float
    cache_max_entries: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "max_pages": self.max_pages,
            "max_requests": self.max_requests,
            "retry_backoff_seconds": self.retry_backoff_seconds,
            "retry_jitter_seconds": self.retry_jitter_seconds,
            "retry_after_max_seconds": self.retry_after_max_seconds,
            "cache_enabled": self.cache_enabled,
            "cache_path": self.cache_path,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "cache_max_entries": self.cache_max_entries,
        }


@dataclass(frozen=True)
class ProviderInstanceConfig:
    ref: str
    kind: str
    instance: str
    token_env: str | None
    include_activity_api: bool
    verify_tls: bool
    allow_insecure_loopback: bool
    runtime: RuntimeOptions
    _validation_seal: InitVar[object | None] = None

    def __post_init__(self, _validation_seal: object | None) -> None:
        if _validation_seal is not _VALIDATED_CONFIG_SEAL:
            raise TypeError(
                "ProviderInstanceConfig is issued only by configuration validation"
            )

    def factory_options(self) -> dict[str, Any]:
        return {
            "token_env": self.token_env,
            "include_activity_api": self.include_activity_api,
            "verify_tls": self.verify_tls,
            "allow_insecure_loopback": self.allow_insecure_loopback,
            "timeout_seconds": self.runtime.timeout_seconds,
            "max_retries": self.runtime.max_retries,
            "max_pages": self.runtime.max_pages,
            "max_requests": self.runtime.max_requests,
            "retry_backoff_seconds": self.runtime.retry_backoff_seconds,
            "retry_jitter_seconds": self.runtime.retry_jitter_seconds,
            "retry_after_max_seconds": self.runtime.retry_after_max_seconds,
            "cache": {
                "enabled": self.runtime.cache_enabled,
                "path": self.runtime.cache_path,
                "ttl_seconds": self.runtime.cache_ttl_seconds,
                "max_entries": self.runtime.cache_max_entries,
            },
        }


@dataclass(frozen=True)
class RepositoryConfig:
    provider_ref: str
    owner: str
    name: str
    target: RepositoryTarget


@dataclass(frozen=True)
class ReportConfig:
    profile: str = DEFAULT_REPORT_PROFILE
    language: str = DEFAULT_REPORT_LANGUAGE
    display_actor_names: bool = False
    actor_labels: tuple[tuple[str, str], ...] = ()
    actor_display: str = DEFAULT_ACTOR_DISPLAY
    allow_source_urls: bool = DEFAULT_ALLOW_SOURCE_URLS
    auth_redaction: bool = True

    def actor_label_map(self) -> dict[str, str]:
        return dict(self.actor_labels)


@dataclass(frozen=True)
class CollectionConfig:
    window_start: datetime
    window_end: datetime
    timezone: str
    repositories: tuple[RepositoryConfig, ...]
    actors: tuple[str, ...]
    providers: tuple[ProviderInstanceConfig, ...]
    report: ReportConfig
    _validation_seal: InitVar[object | None] = None

    def __post_init__(self, _validation_seal: object | None) -> None:
        if _validation_seal is not _VALIDATED_CONFIG_SEAL:
            raise TypeError(
                "CollectionConfig is issued only by configuration validation"
            )

    def provider(self, provider_ref: str) -> ProviderInstanceConfig:
        for provider in self.providers:
            if provider.ref == provider_ref:
                return provider
        raise ConfigError(f"unknown provider_ref: {provider_ref}")


def _reject_unknown_keys(
    value: Mapping[str, Any], allowed: frozenset[str], path: str
) -> None:
    unknown = sorted(
        repr(key) for key in value if not isinstance(key, str) or key not in allowed
    )
    if unknown:
        raise ConfigError(f"{path} contains unknown key(s): {', '.join(unknown)}")


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"{path} must be an object")
    return value


def _required_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{path} must be a non-empty string")
    return value


def _aware_timestamp(value: Any, path: str) -> datetime:
    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str) and value:
        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ConfigError(f"{path} is not a valid ISO timestamp") from exc
    else:
        raise ConfigError(f"{path} must be an offset-aware TOML datetime")
    if timestamp.tzinfo is None:
        raise ConfigError(f"{path} must include a timezone")
    return timestamp


def _number(
    value: Any,
    path: str,
    *,
    default: float,
    minimum: float,
    maximum: float,
    integer: bool = False,
) -> int | float:
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{path} must be numeric")
    if not math.isfinite(float(value)):
        raise ConfigError(f"{path} must be finite")
    if integer and not isinstance(value, int):
        raise ConfigError(f"{path} must be an integer")
    if value < minimum or value > maximum:
        raise ConfigError(f"{path} must be in [{minimum}, {maximum}]")
    return value


def _parse_runtime(
    provider_ref: str, raw: Mapping[str, Any]
) -> tuple[bool, bool, RuntimeOptions]:
    transport = _mapping(
        raw.get("transport", {}), f"providers.{provider_ref}.transport"
    )
    _reject_unknown_keys(
        transport, TRANSPORT_KEYS, f"providers.{provider_ref}.transport"
    )
    cache = _mapping(raw.get("cache", {}), f"providers.{provider_ref}.cache")
    _reject_unknown_keys(cache, CACHE_KEYS, f"providers.{provider_ref}.cache")

    verify_tls = transport.get("verify_tls", True)
    allow_insecure_loopback = transport.get("allow_insecure_loopback", False)
    if not isinstance(verify_tls, bool):
        raise ConfigError(
            f"providers.{provider_ref}.transport.verify_tls must be boolean"
        )
    if not isinstance(allow_insecure_loopback, bool):
        raise ConfigError(
            f"providers.{provider_ref}.transport.allow_insecure_loopback must be boolean"
        )
    cache_enabled = cache.get("enabled", False)
    if not isinstance(cache_enabled, bool):
        raise ConfigError(f"providers.{provider_ref}.cache.enabled must be boolean")
    cache_path = cache.get("path")
    if cache_path is not None and (
        not isinstance(cache_path, str) or not cache_path.strip()
    ):
        raise ConfigError(f"providers.{provider_ref}.cache.path must be a string")
    cache_ttl = _number(
        cache.get("ttl_seconds"),
        f"providers.{provider_ref}.cache.ttl_seconds",
        default=300.0,
        minimum=MIN_RETRY_AFTER_SECONDS,
        maximum=MAX_CACHE_TTL_SECONDS,
    )
    cache_max_entries = _number(
        cache.get("max_entries"),
        f"providers.{provider_ref}.cache.max_entries",
        default=256,
        minimum=1,
        maximum=MAX_CACHE_ENTRIES,
        integer=True,
    )
    if cache_enabled and (
        not cache_path or not {"path", "ttl_seconds", "max_entries"}.issubset(cache)
    ):
        raise ConfigError(
            f"providers.{provider_ref}.cache.path, ttl_seconds, and max_entries "
            "are required when cache is enabled"
        )
    runtime = RuntimeOptions(
        timeout_seconds=float(
            _number(
                transport.get("timeout_seconds"),
                f"providers.{provider_ref}.transport.timeout_seconds",
                default=30.0,
                minimum=MIN_TIMEOUT_SECONDS,
                maximum=MAX_TIMEOUT_SECONDS,
            )
        ),
        max_retries=int(
            _number(
                transport.get("max_retries"),
                f"providers.{provider_ref}.transport.max_retries",
                default=2,
                minimum=0,
                maximum=MAX_RETRIES,
                integer=True,
            )
        ),
        max_pages=int(
            _number(
                transport.get("max_pages"),
                f"providers.{provider_ref}.transport.max_pages",
                default=100,
                minimum=1,
                maximum=MAX_PAGES,
                integer=True,
            )
        ),
        max_requests=int(
            _number(
                transport.get("max_requests"),
                f"providers.{provider_ref}.transport.max_requests",
                default=1000,
                minimum=1,
                maximum=MAX_REQUESTS,
                integer=True,
            )
        ),
        retry_backoff_seconds=float(
            _number(
                transport.get("retry_backoff_seconds"),
                f"providers.{provider_ref}.transport.retry_backoff_seconds",
                default=0.5,
                minimum=0.0,
                maximum=MAX_RETRY_BACKOFF_SECONDS,
            )
        ),
        retry_jitter_seconds=float(
            _number(
                transport.get("retry_jitter_seconds"),
                f"providers.{provider_ref}.transport.retry_jitter_seconds",
                default=0.25,
                minimum=0.0,
                maximum=MAX_RETRY_JITTER_SECONDS,
            )
        ),
        retry_after_max_seconds=float(
            _number(
                transport.get("retry_after_max_seconds"),
                f"providers.{provider_ref}.transport.retry_after_max_seconds",
                default=60.0,
                minimum=MIN_RETRY_AFTER_SECONDS,
                maximum=MAX_RETRY_AFTER_SECONDS,
            )
        ),
        cache_enabled=cache_enabled,
        cache_path=cache_path,
        cache_ttl_seconds=float(cache_ttl),
        cache_max_entries=int(cache_max_entries),
    )
    return verify_tls, allow_insecure_loopback, runtime


def _parse_provider(provider_ref: str, value: Any) -> ProviderInstanceConfig:
    if not PROVIDER_REF_PATTERN.fullmatch(provider_ref):
        raise ConfigError(
            f"provider reference {provider_ref!r} must match {PROVIDER_REF_PATTERN.pattern}"
        )
    raw = _mapping(value, f"providers.{provider_ref}")
    _reject_unknown_keys(raw, PROVIDER_KEYS, f"providers.{provider_ref}")
    kind = _required_string(raw.get("kind"), f"providers.{provider_ref}.kind")
    if not PROVIDER_REGISTRY.contains(kind):
        raise ConfigError(f"providers.{provider_ref}.kind is unsupported: {kind}")
    try:
        instance = validate_instance(
            _required_string(raw.get("instance"), f"providers.{provider_ref}.instance")
        )
    except ValueError as exc:
        raise ConfigError(
            f"providers.{provider_ref}.instance is invalid: {exc}"
        ) from exc
    token_env = raw.get("token_env")
    if token_env is not None and (
        not isinstance(token_env, str) or not TOKEN_ENV_PATTERN.fullmatch(token_env)
    ):
        raise ConfigError(
            f"providers.{provider_ref}.token_env must name an environment variable"
        )
    include_activity_api = raw.get("include_activity_api", False)
    if not isinstance(include_activity_api, bool):
        raise ConfigError(
            f"providers.{provider_ref}.include_activity_api must be boolean"
        )
    verify_tls, allow_insecure_loopback, runtime = _parse_runtime(provider_ref, raw)
    explicit_http = instance.lower().startswith("http://")
    insecure_transport = explicit_http or not verify_tls
    if token_env and insecure_transport:
        raise ConfigError(
            f"providers.{provider_ref} authenticated requests require HTTPS with TLS verification"
        )
    if insecure_transport and not (
        allow_insecure_loopback and is_loopback_instance(instance) and not token_env
    ):
        raise ConfigError(
            f"providers.{provider_ref} insecure transport requires explicit credentialless "
            "loopback development mode"
        )
    return ProviderInstanceConfig(
        ref=provider_ref,
        kind=kind,
        instance=instance,
        token_env=token_env,
        include_activity_api=include_activity_api,
        verify_tls=verify_tls,
        allow_insecure_loopback=allow_insecure_loopback,
        runtime=runtime,
        _validation_seal=_VALIDATED_CONFIG_SEAL,
    )


def validate_report_config(config: Mapping[str, Any]) -> ReportConfig:
    """Validate normalized report/profile/privacy settings from a TOML root."""
    if not isinstance(config, Mapping):
        raise ConfigError("configuration root must be an object")
    _reject_unknown_keys(config, ROOT_KEYS, "configuration")
    report = _mapping(config.get("report", {}), "report")
    _reject_unknown_keys(report, REPORT_KEYS, "report")
    profile = report.get("profile", DEFAULT_REPORT_PROFILE)
    language = report.get("language", DEFAULT_REPORT_LANGUAGE)
    if not isinstance(profile, str) or profile not in PROFILES:
        raise ConfigError(f"report.profile must be one of {', '.join(PROFILES)}")
    if not isinstance(language, str) or language not in LANGUAGES:
        raise ConfigError(f"report.language must be one of {', '.join(LANGUAGES)}")
    display_actor_names = report.get("display_actor_names", False)
    if not isinstance(display_actor_names, bool):
        raise ConfigError("report.display_actor_names must be boolean")
    actor_labels = _mapping(report.get("actor_labels", {}), "report.actor_labels")
    normalized_labels: list[tuple[str, str]] = []
    for actor_id, label in actor_labels.items():
        normalized_labels.append(
            (
                _required_string(actor_id, "report.actor_labels key"),
                _required_string(label, f"report.actor_labels[{actor_id!r}]"),
            )
        )
    privacy = _mapping(report.get("privacy", {}), "report.privacy")
    _reject_unknown_keys(privacy, PRIVACY_KEYS, "report.privacy")
    actor_display = privacy.get("actor_display", DEFAULT_ACTOR_DISPLAY)
    if not isinstance(actor_display, str) or actor_display not in {
        "anonymous",
        "explicit-labels",
    }:
        raise ConfigError(
            "report.privacy.actor_display must be anonymous or explicit-labels"
        )
    if display_actor_names and privacy.get("actor_display") == "anonymous":
        raise ConfigError(
            "report.display_actor_names conflicts with report.privacy.actor_display=anonymous"
        )
    if display_actor_names:
        actor_display = "explicit-labels"
    allow_source_urls = privacy.get("allow_source_urls", DEFAULT_ALLOW_SOURCE_URLS)
    if not isinstance(allow_source_urls, bool):
        raise ConfigError("report.privacy.allow_source_urls must be boolean")
    if privacy.get("auth_redaction", True) is not True:
        raise ConfigError("report.privacy.auth_redaction must remain true")
    return ReportConfig(
        profile=profile,
        language=language,
        display_actor_names=actor_display == "explicit-labels",
        actor_labels=tuple(sorted(normalized_labels)),
        actor_display=actor_display,
        allow_source_urls=allow_source_urls,
    )


def validate_collection_config(config: Mapping[str, Any]) -> CollectionConfig:
    """Validate and materialize one immutable collection plan."""
    if not isinstance(config, Mapping):
        raise ConfigError("configuration root must be an object")
    _reject_unknown_keys(config, ROOT_KEYS, "configuration")
    window = _mapping(config.get("window"), "window")
    _reject_unknown_keys(window, WINDOW_KEYS, "window")
    start = _aware_timestamp(window.get("start"), "window.start")
    end = _aware_timestamp(window.get("end"), "window.end")
    if start >= end:
        raise ConfigError("window.start must be before window.end")
    try:
        timezone = validate_timezone(window.get("timezone"))
    except ValueError as exc:
        raise ConfigError(f"window.timezone is invalid: {exc}") from exc

    providers_raw = _mapping(config.get("providers"), "providers")
    if not providers_raw:
        raise ConfigError("providers must be a non-empty object")
    providers = tuple(
        sorted(
            (_parse_provider(str(ref), value) for ref, value in providers_raw.items()),
            key=lambda provider: provider.ref,
        )
    )
    duplicate_instances = sorted(
        f"{kind}:{instance}"
        for (kind, instance), count in Counter(
            (provider.kind, provider.instance) for provider in providers
        ).items()
        if count > 1
    )
    if duplicate_instances:
        raise ConfigError(
            "providers contain duplicate canonical provider instance(s): "
            + ", ".join(duplicate_instances)
        )
    providers_by_ref = {provider.ref: provider for provider in providers}

    scope = _mapping(config.get("scope"), "scope")
    _reject_unknown_keys(scope, SCOPE_KEYS, "scope")
    repositories_raw = scope.get("repositories")
    if not isinstance(repositories_raw, list) or not repositories_raw:
        raise ConfigError("scope.repositories must be a non-empty allowlist")
    repositories: list[RepositoryConfig] = []
    for index, value in enumerate(repositories_raw):
        path = f"scope.repositories[{index}]"
        raw = _mapping(value, path)
        _reject_unknown_keys(raw, REPOSITORY_KEYS, path)
        provider_ref = _required_string(raw.get("provider_ref"), f"{path}.provider_ref")
        provider = providers_by_ref.get(provider_ref)
        if provider is None:
            raise ConfigError(f"{path}.provider_ref is unknown: {provider_ref}")
        owner = _required_string(raw.get("owner"), f"{path}.owner")
        name = _required_string(raw.get("name"), f"{path}.name")
        try:
            target = RepositoryTarget(provider.kind, provider.instance, owner, name)
        except ValueError as exc:
            raise ConfigError(f"{path} is invalid: {exc}") from exc
        repositories.append(RepositoryConfig(provider_ref, owner, name, target))
    repositories.sort(key=lambda repository: repository.target.canonical_id)
    duplicate_repositories = sorted(
        repository_id
        for repository_id, count in Counter(
            repository.target.canonical_id for repository in repositories
        ).items()
        if count > 1
    )
    if duplicate_repositories:
        raise ConfigError(
            "scope.repositories contains duplicate canonical repository(s): "
            + ", ".join(duplicate_repositories)
        )
    used_refs = {repository.provider_ref for repository in repositories}
    unused_refs = sorted(set(providers_by_ref) - used_refs)
    if unused_refs:
        raise ConfigError(
            "providers contain unused reference(s): " + ", ".join(unused_refs)
        )
    for provider_ref, repository_count in Counter(
        repository.provider_ref for repository in repositories
    ).items():
        provider = providers_by_ref[provider_ref]
        minimum_core_budget = MIN_CORE_REQUESTS_PER_REPOSITORY * repository_count
        if provider.runtime.max_requests < minimum_core_budget:
            raise PlanBudgetInfeasibleConfigError(
                f"plan_budget_infeasible: providers.{provider_ref}.transport.max_requests="
                f"{provider.runtime.max_requests} cannot cover {repository_count} repositories; "
                f"minimum is {minimum_core_budget}"
            )
    actors = scope.get("actors", [])
    if not isinstance(actors, list) or not all(
        isinstance(value, str) and value for value in actors
    ):
        raise ConfigError("scope.actors must be an array of non-empty actor IDs")
    if len(actors) != len(set(actors)):
        raise ConfigError("scope.actors must not contain duplicate actor IDs")
    return CollectionConfig(
        window_start=start,
        window_end=end,
        timezone=timezone,
        repositories=tuple(repositories),
        actors=tuple(actors),
        providers=providers,
        report=validate_report_config(config),
        _validation_seal=_VALIDATED_CONFIG_SEAL,
    )


def provider_runtime_options(provider: ProviderInstanceConfig) -> dict[str, Any]:
    """Materialize the transport API expected by provider factories."""
    if not isinstance(provider, ProviderInstanceConfig):
        raise TypeError("provider must be a ProviderInstanceConfig")
    return provider.runtime.as_dict()


def _read_config(path: str | Path) -> dict[str, Any]:
    try:
        raw_bytes = read_bounded_bytes(path, max_bytes=MAX_CONFIG_BYTES)
        raw = tomllib.loads(raw_bytes.decode("utf-8"))
        validate_json_value_limits(
            raw,
            max_depth=MAX_CONFIG_DEPTH,
            max_string_chars=MAX_CONFIG_SCALAR_CHARS,
        )
    except InputLimitError as exc:
        raise ConfigError(str(exc).replace("JSON", "configuration")) from exc
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(str(exc)) from exc
    return raw


def load_collection_config(path: str | Path) -> CollectionConfig:
    """Load the sole supported TOML collection configuration."""
    return validate_collection_config(_read_config(path))


def load_report_config(path: str | Path) -> ReportConfig:
    """Load report/profile/privacy settings from TOML."""
    return validate_report_config(_read_config(path))
