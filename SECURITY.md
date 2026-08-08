# Security and privacy

This tool reads potentially private engineering data. Treat evidence bundles,
diagnostics, generated reports, and source URLs as sensitive unless the user
has explicitly approved their visibility.

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
