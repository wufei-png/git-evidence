# Quality debt baseline

The `Offline contract required` job is the intended required branch check; it
becomes a merge-blocking gate when the default-branch ruleset requires it. The
three quality lanes below are deliberately visible but non-blocking until their
recorded debt reaches zero.
This snapshot was measured on 2026-08-09 from commit `c92f0ed` plus the P0-C
workflow changes, using Ruff 0.16.2 and Pyright 1.1.411.

| Lane | Command | Baseline |
| --- | --- | ---: |
| Ruff lint | `ruff check .` | 68 diagnostics |
| Ruff format | `ruff format --check .` | 21 files would change |
| Pyright | `pyright --outputjson` | 144 errors, 7 warnings |

A lane becomes blocking only in the same cohesive change that reduces its
baseline to zero. Updating this file to hide a regression is not an acceptable
substitute for fixing or explicitly re-scoping the rule set.
