# Project status

This page separates checked-in contract evidence from dated live-provider
evidence. Offline fixture success is not a live-provider claim.

| Provider | Core resources | Activity/ref | Last live smoke | Commit | Current status |
| --- | --- | --- | --- | --- | --- |
| GitHub | experimental | incomplete | 2026-08-01 | not recorded | Schema 0.3 live behavior unverified |
| GitLab/Jihulab | experimental | incomplete | 2026-08-01 | not recorded | Schema 0.3 live behavior unverified |
| Gitee | experimental | unsupported | 2026-08-01 | not recorded | Schema 0.3 live behavior unverified |

The dated smoke evidence is described in
[`docs/testing/live-e2e.md`](docs/testing/live-e2e.md). It predates the Schema
0.3-only contract and therefore cannot certify the current checkout. The
current offline gate covers the Python support matrix, sole packaged Schema,
provider fixtures, semantic validation, rendering, Ruff, and the production
Pyright ratchet.

No provider is production-certified. A new protected canary must record its
provider, bounded scope/window, exact commit, and result here without exposing
repository coordinates, credentials, Bundle contents, or report contents.
