from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .base import Provider, ProviderDescriptor, validate_descriptor


class ProviderRegistryError(ValueError):
    """A provider is not registered or its registration is invalid."""


ProviderFactory = Callable[..., Provider]


@dataclass(frozen=True)
class ProviderRegistration:
    """The complete construction contract for one provider kind."""

    descriptor: ProviderDescriptor
    factory: ProviderFactory

    def __post_init__(self) -> None:
        validate_descriptor(self.descriptor)
        if not callable(self.factory):
            raise ProviderRegistryError(
                f"provider factory for {self.descriptor.kind!r} must be callable"
            )


class ProviderRegistry:
    """Fail-closed registry for provider descriptors and instance factories."""

    def __init__(self, registrations: Mapping[str, ProviderRegistration] | None = None) -> None:
        self._registrations: dict[str, ProviderRegistration] = {}
        for kind, registration in (registrations or {}).items():
            self.register(kind, registration)

    def register(self, kind: str, registration: ProviderRegistration) -> None:
        if not isinstance(kind, str) or not kind.strip():
            raise ProviderRegistryError("provider registration kind must be a non-empty string")
        if not isinstance(registration, ProviderRegistration):
            raise ProviderRegistryError(f"invalid provider registration for {kind!r}")
        if registration.descriptor.kind != kind:
            raise ProviderRegistryError(
                f"provider registration key {kind!r} does not match descriptor "
                f"{registration.descriptor.kind!r}"
            )
        if kind in self._registrations:
            raise ProviderRegistryError(f"provider is already registered: {kind}")
        self._registrations[kind] = registration

    def registration(self, kind: str) -> ProviderRegistration:
        registration = self._registrations.get(kind)
        if registration is None:
            raise ProviderRegistryError(f"unsupported provider: {kind}")
        return registration

    def descriptor(self, kind: str) -> ProviderDescriptor:
        return self.registration(kind).descriptor

    def contains(self, kind: str) -> bool:
        return kind in self._registrations

    def descriptors(self) -> list[ProviderDescriptor]:
        return [self._registrations[key].descriptor for key in sorted(self._registrations)]

    def create(
        self,
        kind: str,
        *,
        instance: str,
        provider_config: Mapping[str, Any],
        token: str | None,
        runtime_options: Mapping[str, Any],
    ) -> Provider:
        """Create an adapter only through a validated registration."""
        registration = self.registration(kind)
        verify_tls = provider_config.get("verify_tls", True)
        options = dict(runtime_options)
        return registration.factory(
            instance=instance,
            token=token,
            verify_tls=verify_tls,
            **options,
        )


PROVIDER_DESCRIPTORS = {
    "gitlab": ProviderDescriptor(
        kind="gitlab",
        display_name="GitLab",
        endpoint_style="REST resource APIs; optional events/activity APIs",
        implementation_status="experimental",
    ),
    "github": ProviderDescriptor(
        kind="github",
        display_name="GitHub",
        endpoint_style="REST repository, issues, pulls, commits, and releases APIs",
        implementation_status="experimental",
    ),
    "gitee": ProviderDescriptor(
        kind="gitee",
        display_name="Gitee",
        endpoint_style="REST repository, issues, pull requests, commits, and releases APIs",
        implementation_status="experimental",
    ),
}

for _descriptor in PROVIDER_DESCRIPTORS.values():
    validate_descriptor(_descriptor)


def _default_registry() -> ProviderRegistry:
    # Imports are intentionally delayed until after PROVIDER_DESCRIPTORS exists;
    # provider adapters expose their descriptor through this catalog module.
    from .gitee import GiteeProvider
    from .github import GitHubProvider
    from .gitlab import GitLabProvider

    registry = ProviderRegistry()
    registry.register(
        "gitee",
        ProviderRegistration(PROVIDER_DESCRIPTORS["gitee"], GiteeProvider),
    )
    registry.register(
        "github",
        ProviderRegistration(PROVIDER_DESCRIPTORS["github"], GitHubProvider),
    )
    registry.register(
        "gitlab",
        ProviderRegistration(PROVIDER_DESCRIPTORS["gitlab"], GitLabProvider),
    )
    return registry


PROVIDER_REGISTRY = _default_registry()


def provider_catalog() -> list[ProviderDescriptor]:
    """Return the public catalog while preserving the existing CLI shape."""
    return PROVIDER_REGISTRY.descriptors()
