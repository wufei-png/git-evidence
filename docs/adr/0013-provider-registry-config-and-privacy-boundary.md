---
status: accepted
date: 2026-08-02
---

# Provider registry, configuration domains, and public privacy defaults

## Decision

The provider catalog is a fail-closed registry. Each registered kind owns one
descriptor and one factory/constructor, and collection creates instances only
through that registration. `provider_catalog` and the `providers` CLI continue
to expose descriptors, while an absent or unknown registration is an error.
There is no provider-kind `if/elif` fallback in collection.

Collection and report configuration are separate validation domains:

- `load_collection_config` and `validate_collection_config` own the window,
  scope, provider allowlist, provider runtime limits, and credential references.
- `load_report_config` and `validate_report_config` own profile, language,
  privacy, and display identity.
- `collect` consumes only the collection domain and `render` consumes only the
  report domain. `load_config` remains a strict compatibility loader for an
  existing single YAML file.

The public privacy default is anonymous actors, no inline tokens or credentials,
and no display of provider-supplied actor names. A display name is possible only
through an explicit actor-ID-to-label map. Source URLs remain valid evidence,
but auth query parameters and URL userinfo are removed at collection/render
boundaries; an unsafe URL or sensitive payload field blocks publication.

## Consequences

Offline registry, fixture, schema, semantic, and renderer tests prove the
deterministic contract only. They do not prove live provider behavior. A live
canary must use an explicit repository allowlist and environment/CI secrets;
until it succeeds, its bundle or report must not be described as publishable.
