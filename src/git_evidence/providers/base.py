from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

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

    @property
    def canonical_id(self) -> str:
        return f"repo:{self.provider_kind}:{self.instance}:{self.owner}/{self.name}"


def instance_web_base(instance: str) -> str:
    """Return an HTTPS-or-explicit-scheme web base for a provider instance."""
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
