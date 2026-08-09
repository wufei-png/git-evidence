# Quality debt baseline

The `Offline contract required`, Ruff lint, Ruff format, and production-source
Pyright ratchet jobs are blocking CI jobs. This snapshot was measured on
2026-08-10 from the stage based on `b6a3829`, using Ruff 0.16.2 and Pyright
1.1.411.

| Lane | Command | Baseline |
| --- | --- | ---: |
| Ruff lint | `ruff check .` | 0 diagnostics |
| Ruff format | `ruff format --check .` | 0 files would change |
| Pyright production source | `python scripts/check_pyright_baseline.py` | at most 94 errors, 0 warnings |

The Pyright gate intentionally checks `src/git_evidence` rather than test
fixtures and accepts improvements below the recorded ceiling. Raising the
ceiling to hide a regression is not an acceptable substitute for fixing or
explicitly re-scoping the affected code.
