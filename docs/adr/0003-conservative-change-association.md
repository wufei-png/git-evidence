---
status: accepted
date: 2026-08-01
---

# Conservative change association

Commit and ref activity uses the four-state `change_association` vocabulary:
`linked`, `unlinked`, `ambiguous`, and `unknown`. The public model does not
claim “direct push” merely because no change request was found in one activity
stream. Provider-specific association checks, branch history, rebases,
cherry-picks, bulk pushes, and missing API detail can all change the confidence
of that conclusion. Reader-facing profiles may translate a bounded
`unlinked` result into local wording, but must preserve uncertainty elsewhere.

This replaces the private Skill's narrower current-window source-branch
partition as a public semantic contract. The old behavior is only an internal
extraction reference and is not shipped as a compatibility profile.
