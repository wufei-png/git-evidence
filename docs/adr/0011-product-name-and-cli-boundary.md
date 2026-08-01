---
status: accepted
date: 2026-08-01
---

# Product name and CLI boundary

The public project is named `git-platform-evidence-engine`. Its product
position is an evidence-first Git platform engineering activity report engine,
not an engineering productivity scoring system and not a generic AI summarizer.

The name is intentionally platform-neutral: GitLab, GitHub, and Gitee are
first-class providers, while provider-specific capability limits remain
explicit in the coverage contract. It also avoids `weekly`, because the public
window is an arbitrary configured half-open interval rather than a fixed
schedule.

The Python distribution is `git-platform-evidence-engine`, the import package
is `git_platform_evidence_engine`, and the user-facing CLI is `git-evidence`.
The CLI name describes the evidence workflow without reintroducing a provider
or productivity-scoring assumption.
