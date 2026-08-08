from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import math
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit

from ..limits import (
    MAX_PAGES,
    MAX_REQUESTS,
    MAX_RETRIES,
    MAX_RETRY_AFTER_SECONDS,
    MAX_RETRY_JITTER_SECONDS,
    MAX_TIMEOUT_SECONDS,
    MIN_RETRY_AFTER_SECONDS,
    MIN_TIMEOUT_SECONDS,
)

CAPABILITY_STATES = ("supported", "unsupported", "unavailable", "incomplete")
RESOURCE_SOURCES = (
    "repositories",
    "work_items",
    "change_requests",
    "interactions",
    "commits",
    "releases",
)
ACTIVITY_SOURCES = ("activities", "ref_changes")
OPTIONAL_COVERAGE_WARNING_CODE = "optional_coverage_warning"
# Optional warning status is an evidence-quality severity, not a success flag.
# Keep the most conservative state when observations are combined in either
# order so warning output cannot depend on provider/group iteration order.
OPTIONAL_STATUS_PRIORITY = {
    "unsupported": 1,
    "unavailable": 2,
    "incomplete": 3,
}
OPERATIONAL_FAILURE_CLASSES = frozenset(
    {
        "permission_denied",
        "rate_limited",
        "service_error",
        "not_found",
        "request_rejected",
        "network_error",
        "transport_error",
        "fixture_missing",
        "http_error",
        "malformed_response",
        "provider_not_ready",
        "unexpected_error",
        "unexpected_normalizer_error",
        "budget_exhausted",
        "insecure_transport",
        "limit_exceeded",
        "privacy_violation",
    }
)
UNVERIFIABLE_SHA_SENTINELS = frozenset(
    {
        "missing",
        "na",
        "n/a",
        "nil",
        "none",
        "not available",
        "not provided",
        "null",
        "undefined",
        "unknown",
        "unavailable",
    }
)


def is_verifiable_sha(value: Any) -> bool:
    """Return whether a commit SHA is a non-sentinel string value."""
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    return bool(normalized) and normalized not in UNVERIFIABLE_SHA_SENTINELS


def _coverage_failure_classes(value: Any) -> set[str]:
    classes: set[str] = set()
    if isinstance(value, Mapping):
        failure_class = value.get("failure_class")
        if isinstance(failure_class, str) and failure_class:
            classes.add(failure_class)
        failure_classes = value.get("failure_classes")
        if isinstance(failure_classes, (list, tuple, set)):
            classes.update(item for item in failure_classes if isinstance(item, str) and item)
        for child in value.values():
            classes.update(_coverage_failure_classes(child))
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            classes.update(_coverage_failure_classes(child))
    return classes


def optional_coverage_warning(observation: Mapping[str, Any]) -> dict[str, Any] | None:
    """Build a machine-readable warning for a non-complete optional source."""
    source = observation.get("source")
    status = observation.get("status")
    provider_id = observation.get("provider_id")
    repository_id = observation.get("repository_id")
    if (
        source not in ACTIVITY_SOURCES
        or status == "supported"
        or not isinstance(provider_id, str)
        or not isinstance(repository_id, str)
    ):
        return None
    warning: dict[str, Any] = {
        "code": OPTIONAL_COVERAGE_WARNING_CODE,
        "source": source,
        "provider_id": provider_id,
        "repository_id": repository_id,
        "status": status,
    }
    note = observation.get("note")
    if isinstance(note, str) and note.strip():
        warning["message"] = note
    failure_classes = sorted(_coverage_failure_classes(observation.get("diagnostics")))
    if len(failure_classes) == 1:
        warning["failure_class"] = failure_classes[0]
    elif failure_classes:
        warning["failure_classes"] = failure_classes
    return warning


def append_optional_coverage_warning(
    coverage: dict[str, Any], observation: Mapping[str, Any]
) -> None:
    warning = optional_coverage_warning(observation)
    if warning is None:
        return
    merge_optional_coverage_warning(coverage, warning)


def merge_optional_coverage_warning(
    coverage: dict[str, Any], warning: Mapping[str, Any]
) -> None:
    """Insert or monotonically enrich one optional coverage warning."""
    if warning.get("code") != OPTIONAL_COVERAGE_WARNING_CODE:
        return
    warnings = coverage.setdefault("warnings", [])
    if not isinstance(warnings, list):
        warnings = []
        coverage["warnings"] = warnings
    fields = ("code", "source", "provider_id", "repository_id")
    observation_fields = ("source", "provider_id", "repository_id")
    key = tuple(warning.get(field) for field in fields)
    statuses = [
        status
        for status in (warning.get("status"),)
        if status in OPTIONAL_STATUS_PRIORITY
    ]
    for existing in warnings:
        if not isinstance(existing, dict) or tuple(existing.get(field) for field in fields) != key:
            continue
        existing_status = existing.get("status")
        if existing_status in OPTIONAL_STATUS_PRIORITY:
            statuses.append(existing_status)
        if statuses:
            existing["status"] = max(statuses, key=OPTIONAL_STATUS_PRIORITY.__getitem__)
        failure_classes = _coverage_failure_classes(existing) | _coverage_failure_classes(warning)
        if len(failure_classes) == 1:
            existing["failure_class"] = next(iter(failure_classes))
            existing.pop("failure_classes", None)
        elif failure_classes:
            existing.pop("failure_class", None)
            existing["failure_classes"] = sorted(failure_classes)
        existing_message = existing.get("message")
        incoming_message = warning.get("message")
        if isinstance(existing_message, str) and existing_message.strip():
            if isinstance(incoming_message, str) and incoming_message.strip():
                if existing_message in incoming_message:
                    existing["message"] = incoming_message
                elif incoming_message not in existing_message:
                    existing["message"] = f"{existing_message}; {incoming_message}"
        elif isinstance(incoming_message, str) and incoming_message.strip():
            existing["message"] = incoming_message
        if statuses:
            observations = coverage.get("observations")
            if isinstance(observations, list):
                for observation in observations:
                    if (
                        isinstance(observation, dict)
                        and tuple(observation.get(field) for field in observation_fields)
                        == key[1:]
                        and observation.get("status") in OPTIONAL_STATUS_PRIORITY
                    ):
                        observation["status"] = existing["status"]
        return
    new_warning = dict(warning)
    if statuses:
        new_warning["status"] = max(statuses, key=OPTIONAL_STATUS_PRIORITY.__getitem__)
    warnings.append(new_warning)
    if statuses:
        observations = coverage.get("observations")
        if isinstance(observations, list):
            for observation in observations:
                if (
                    isinstance(observation, dict)
                    and tuple(observation.get(field) for field in observation_fields)
                    == key[1:]
                    and observation.get("status") in OPTIONAL_STATUS_PRIORITY
                ):
                    observation["status"] = new_warning["status"]


@dataclass(frozen=True)
class ProviderDescriptor:
    """Public provider contract metadata, not a claim of live completeness."""

    kind: str
    display_name: str
    endpoint_style: str
    resource_sources: tuple[str, ...] = RESOURCE_SOURCES
    activity_sources: tuple[str, ...] = ACTIVITY_SOURCES
    implementation_status: str = "contract-only"

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "display_name": self.display_name,
            "endpoint_style": self.endpoint_style,
            "resource_sources": list(self.resource_sources),
            "activity_sources": list(self.activity_sources),
            "implementation_status": self.implementation_status,
        }


@dataclass(frozen=True)
class RepositoryTarget:
    provider_kind: str
    instance: str
    owner: str
    name: str

    def __post_init__(self) -> None:
        validate_instance(self.instance)

    @property
    def canonical_id(self) -> str:
        return f"repo:{self.provider_kind}:{self.instance}:{self.owner}/{self.name}"


def validate_instance(instance: Any) -> str:
    """Validate an instance authority while allowing a safe base path."""
    if not isinstance(instance, str) or not instance or instance != instance.strip():
        raise ValueError("instance must be a non-empty URL host or http(s) base")
    if any(character.isspace() or ord(character) < 0x20 for character in instance):
        raise ValueError("instance must not contain whitespace or control characters")
    if "?" in instance or "#" in instance:
        raise ValueError("instance must not contain a query or fragment")
    candidate = instance if instance.startswith(("http://", "https://")) else f"//{instance}"
    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        parts.port
    except ValueError as exc:
        raise ValueError("instance is not a valid URL authority") from exc
    if parts.scheme and parts.scheme not in {"http", "https"}:
        raise ValueError("instance must use http or https")
    if not parts.netloc or not hostname:
        raise ValueError("instance must contain a host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("instance must not contain URL userinfo")
    if parts.query or parts.fragment:
        raise ValueError("instance must not contain a query or fragment")
    return instance


def is_loopback_instance(instance: str) -> bool:
    """Return whether an already validated instance targets loopback only."""
    validate_instance(instance)
    candidate = instance if instance.startswith(("http://", "https://")) else f"//{instance}"
    hostname = urlsplit(candidate).hostname
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def instance_web_base(instance: str) -> str:
    """Return an HTTPS-or-explicit-scheme web base for a provider instance."""
    validate_instance(instance)
    value = instance.rstrip("/")
    if value.startswith(("http://", "https://")):
        return value
    return f"https://{value}"


@dataclass(frozen=True)
class CollectionRequest:
    provider_kind: str
    instance: str
    repositories: tuple[RepositoryTarget, ...]
    window_start: str
    window_end: str
    timezone: str
    include_activity_api: bool = False
    actor_ids: tuple[str, ...] = ()
    timeout_seconds: float = 30.0
    max_retries: int = 2
    max_pages: int = 100
    max_requests: int = 1000
    retry_jitter_seconds: float = 0.25
    retry_after_max_seconds: float = 60.0

    def __post_init__(self) -> None:
        validate_instance(self.instance)
        for target in self.repositories:
            if not isinstance(target, RepositoryTarget):
                raise ValueError("repositories must contain RepositoryTarget values")
            if target.provider_kind != self.provider_kind or target.instance != self.instance:
                raise ValueError("repository target provider and instance must match the request")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds < MIN_TIMEOUT_SECONDS
            or self.timeout_seconds > MAX_TIMEOUT_SECONDS
        ):
            raise ValueError(
                f"timeout_seconds must be finite and in [{MIN_TIMEOUT_SECONDS}, {MAX_TIMEOUT_SECONDS}]"
            )
        for name, value, maximum, minimum in (
            ("max_retries", self.max_retries, MAX_RETRIES, 0),
            ("max_pages", self.max_pages, MAX_PAGES, 1),
            ("max_requests", self.max_requests, MAX_REQUESTS, 1),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
                raise ValueError(f"{name} must be in [{minimum}, {maximum}]")
        if (
            isinstance(self.retry_jitter_seconds, bool)
            or not isinstance(self.retry_jitter_seconds, (int, float))
            or not math.isfinite(float(self.retry_jitter_seconds))
            or self.retry_jitter_seconds < 0
            or self.retry_jitter_seconds > MAX_RETRY_JITTER_SECONDS
        ):
            raise ValueError(f"retry_jitter_seconds must be finite and in [0, {MAX_RETRY_JITTER_SECONDS}]")
        if (
            isinstance(self.retry_after_max_seconds, bool)
            or not isinstance(self.retry_after_max_seconds, (int, float))
            or not math.isfinite(float(self.retry_after_max_seconds))
            or self.retry_after_max_seconds < MIN_RETRY_AFTER_SECONDS
            or self.retry_after_max_seconds > MAX_RETRY_AFTER_SECONDS
        ):
            raise ValueError(
                f"retry_after_max_seconds must be finite and in [{MIN_RETRY_AFTER_SECONDS}, {MAX_RETRY_AFTER_SECONDS}]"
            )

    @property
    def repository_ids(self) -> tuple[str, ...]:
        return tuple(repository.canonical_id for repository in self.repositories)


class ProviderNotReady(RuntimeError):
    """A provider contract exists but its network collector is not ready."""


class Provider(Protocol):
    descriptor: ProviderDescriptor

    def probe(self) -> dict[str, Any]:
        """Return provider metadata without making a repository claim."""

    def collect(self, request: CollectionRequest) -> dict[str, Any]:
        """Collect a canonical bundle or raise ProviderNotReady."""


def validate_descriptor(descriptor: ProviderDescriptor) -> None:
    if not descriptor.kind or not descriptor.display_name:
        raise ValueError("provider descriptor requires kind and display_name")
    if descriptor.implementation_status not in {"contract-only", "experimental", "stable"}:
        raise ValueError("invalid provider implementation_status")
    for source in (*descriptor.resource_sources, *descriptor.activity_sources):
        if not source:
            raise ValueError("provider source names cannot be empty")
