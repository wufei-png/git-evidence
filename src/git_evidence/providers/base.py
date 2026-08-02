from __future__ import annotations

from dataclasses import dataclass
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
