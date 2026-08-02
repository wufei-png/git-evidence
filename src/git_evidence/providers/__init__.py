from .base import (
    ACTIVITY_SOURCES,
    RESOURCE_SOURCES,
    CollectionRequest,
    ProviderDescriptor,
    ProviderNotReady,
    RepositoryTarget,
)
from .catalog import (
    PROVIDER_REGISTRY,
    ProviderRegistration,
    ProviderRegistry,
    ProviderRegistryError,
    provider_catalog,
)
from .gitee import GiteeProvider
from .github import GitHubProvider
from .gitlab import GitLabProvider

__all__ = [
    "ACTIVITY_SOURCES",
    "RESOURCE_SOURCES",
    "CollectionRequest",
    "GiteeProvider",
    "GitHubProvider",
    "GitLabProvider",
    "ProviderDescriptor",
    "ProviderNotReady",
    "ProviderRegistration",
    "ProviderRegistry",
    "ProviderRegistryError",
    "PROVIDER_REGISTRY",
    "RepositoryTarget",
    "provider_catalog",
]
