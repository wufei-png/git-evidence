---
status: accepted
date: 2026-08-07
---

# Authenticated collection requires a trusted transport boundary

Requests carrying provider credentials must use HTTPS with TLS verification;
there is no configuration escape hatch for authenticated HTTP or disabled TLS
verification. Pagination and redirects may be followed only when every target
stays within the transport's canonical API origin and path boundary, contains
no userinfo or additional authentication query, does not downgrade the scheme,
and does not repeat or regress a visited pagination target. Private deployments
with custom certificate authorities must establish trust through the runtime CA
configuration rather than weakening collection transport checks.

Credentialless HTTP is limited to an explicit loopback-only development mode.
Its output is diagnostic and not render-eligible. This preserves bounded local
development without allowing a publication warning to stand in for preventing
credential disclosure or evidence tampering before collection occurs.
