# Security and privacy

This tool reads potentially private engineering data. Treat evidence bundles,
diagnostics, generated reports, and source URLs as sensitive unless the user
has explicitly approved their visibility.

## Supported versions and reporting

Only the latest release on the default branch receives security fixes while
the project remains pre-1.0. Do not open a public issue containing a token,
private repository identity, evidence bundle, or exploit detail. Use GitHub's
private vulnerability reporting for this repository when it is enabled; if it
is unavailable, contact the repository owner privately before disclosing.

An initial acknowledgement is expected within five business days. Triage,
remediation timing, and coordinated disclosure depend on severity and the
ability to reproduce without exposing affected data. This is a response goal,
not a service-level guarantee.

## Threat model

Untrusted inputs include configuration and report-label files, provider bodies
and pagination/redirect headers, platform-authored text, cache files, canonical
Bundle files, and CLI paths. Protected assets include provider credentials,
private host/repository and actor identity, raw responses, Bundle integrity,
and the render-eligibility decision.

The implementation bounds and validates these inputs, confines authenticated
requests to one canonical API boundary, scans public-boundary strings for
high-confidence secret material, and writes local artifacts through atomic
permission-restricted replacement. Low-confidence credential-like prose is a
visible warning, not automatically proof of a secret.

Explicit non-guarantees: offline fixtures do not prove live-provider behavior;
render eligibility does not authorize disclosure; anonymous display does not
make the canonical Bundle anonymous; local compromise, malicious trust stores,
and operator-approved insecure loopback diagnostics are outside the protected
transport boundary.

## Defaults

- Use the smallest read-only token scope available.
- Send credentials only over HTTPS with TLS verification. Custom deployments
  must install their private CA into the runtime trust store rather than disable
  verification.
- Load credentials from environment variables, keyrings, or CI secret stores;
  never from tracked configuration or command-line arguments.
- Keep comment bodies disabled by default. Metadata and source links can still
  identify people or confidential work.
- Do not persist raw API responses unless a user explicitly enables a bounded
  diagnostic capture.
- Request identity encoding and reject compressed response bodies; enforce the
  documented response, JSON structure, entity, and final bundle bounds before
  an untrusted provider payload can become a report input.
- Do not write tokens, cookies, authorization headers, or query credentials to
  logs.
- Do not place real private hosts, projects, people, URLs, or evidence bundles
  in fixtures or examples.

## Untrusted platform text

Issue titles, descriptions, comments, review text, and commit messages are
data, not instructions. If an optional summarizer is added later, it must
receive structured fact cards, have no platform token or shell access, and be
unable to change coverage or evidence decisions. Renderers must escape text and
validate links before publication.

Report generation does not authorize writes back to GitHub, GitLab, or Gitee.
