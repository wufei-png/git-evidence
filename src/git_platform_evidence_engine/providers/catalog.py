from __future__ import annotations

from .base import ProviderDescriptor, validate_descriptor

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


def provider_catalog() -> list[ProviderDescriptor]:
    return [PROVIDER_DESCRIPTORS[key] for key in sorted(PROVIDER_DESCRIPTORS)]
