# Repository Guidelines

## Project Structure & Module Organization

Production code uses the `src/` layout under `src/git_evidence/`. Provider adapters live in `providers/`; the CLI entry point is `cli.py`; collection, validation, privacy, and rendering remain separate modules. The authoritative JSON Schema is packaged from `src/git_evidence/schemas/`. Tests are flat `tests/test_*.py` modules, while synthetic replay data belongs in `fixtures/` and `fixtures/provider_contract/`. Architecture and operational docs live under `docs/`. Keep the optional adapter in `integrations/agent-skill/git-evidence/` thin: it sequences the CLI and must not duplicate core logic.

## Build, Test, and Development Commands

- `python -m pip install --editable .` installs the package and `git-evidence` CLI for local development.
- `python -m pytest -q --disable-socket` runs the offline contract suite without network access.
- `ruff check .` and `ruff format --check .` enforce lint and formatting rules.
- `python scripts/check_pyright_baseline.py` checks the production-source type-error ratchet.
- `python scripts/check_schema_sync.py` verifies the packaged Schema is synchronized.
- `python -m compileall -q src tests` catches syntax/import compilation failures.
- `python -m build` produces the source distribution and wheel in `dist/`.

## Coding Style & Naming Conventions

Target Python 3.11 or newer. Use four-space indentation, Ruff formatting, and type annotations for production interfaces. Name modules, functions, and variables with `snake_case`, classes with `PascalCase`, and constants with `UPPER_SNAKE_CASE`. Preserve provider-neutral core contracts: provider-specific behavior belongs in `providers/`, and CLI diagnostics must remain bounded and machine-readable where promised.

## Testing Guidelines

Use pytest and name files and tests `test_*.py`. Add regression tests beside the closest contract area and use synthetic or anonymous fixtures only. Tests must be deterministic and offline by default; do not add live-provider calls to the normal suite. For schema, privacy, identity, transport, or rendering changes, test both the success path and fail-closed behavior.

## Commit & Pull Request Guidelines

Recent history favors concise, imperative subjects with prefixes such as `feat:`, `fix:`, `test:`, `docs:`, `ci:`, and `refactor:`. Keep commits cohesive. Pull requests should explain the contract or behavior changed, list validation commands run, and link relevant issues or ADRs. Call out privacy, coverage, provider, schema, or disclosure-boundary effects explicitly; screenshots are only useful for rendered-output changes.

## Security & Configuration

Keep credentials in environment variables referenced by TOML; never commit tokens, private caches, evidence bundles, or reports. Treat generated bundles and reports as sensitive even when validation succeeds. Follow `SECURITY.md`, `RESPONSIBLE_USE.md`, and the protected live-canary runbook before any provider-backed validation.
