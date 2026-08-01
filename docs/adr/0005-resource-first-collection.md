---
status: accepted
date: 2026-08-01
---

# Resource-first collection

The collector uses repository/project resource APIs as the primary source for
Issues, merge requests or pull requests, comments and review metadata,
commits, and releases. Activity or event APIs are optional supplements for
candidate discovery, push/ref attribution, and cross-checking; when they are
not enabled, the coverage manifest must explicitly prohibit any claim of
complete push/ref-change coverage. This avoids treating a bounded or lossy
activity stream as a complete source of truth while still allowing providers
to exploit useful native activity data.
