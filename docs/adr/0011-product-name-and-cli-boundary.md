---
status: accepted
date: 2026-08-01
---

# Product name and CLI boundary

The public product and repository are named `Git Evidence` and `git-evidence`.
The product position is evidence-first engineering activity reports across
GitHub, GitLab, and Gitee—not an engineering productivity scoring system and
not a generic AI summarizer.

The name is intentionally platform-neutral: GitLab, GitHub, and Gitee are
first-class providers, while provider-specific capability limits remain
explicit in the coverage contract. It also avoids `weekly`, because the public
window is an arbitrary configured half-open interval rather than a fixed
schedule.

The naming map is deliberately uniform:

- product: `Git Evidence`
- repository: `git-evidence`
- Python distribution: `git-evidence`
- import package: `git_evidence`
- user-facing CLI: `git-evidence`

The CLI name describes the evidence workflow without reintroducing a provider
or productivity-scoring assumption.
