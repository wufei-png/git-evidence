---
status: accepted
date: 2026-08-01
---

# Standalone multi-provider boundary

The project is the standalone `git-platform-evidence-engine` repository,
separate from the private weekly-report workspace. Its public core owns a
platform-neutral provider contract and first-class GitLab, GitHub, and Gitee
adapters; no private organization profile or compatibility workflow is
shipped. This preserves a clean open-source history and makes multi-platform
behavior a tested contract rather than a copied collection of private
assumptions.

## Considered options

- Publishing a redacted copy of the private Skill was rejected because its
  hard-coded team, project, wording, and `glab` assumptions are not a public
  product boundary.
- Making `glab` the public runtime contract was rejected because it would make a
  CLI installation and one provider's authentication tool a library contract.
