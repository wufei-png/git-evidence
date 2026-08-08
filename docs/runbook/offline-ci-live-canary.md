# Offline CI and live-provider canary contract

This project has two deliberately separate validation lanes. Offline CI proves
the deterministic contract from checked-in fixtures. A live provider canary
proves only the explicitly allowlisted provider/instance/window at the time it
runs. Neither lane may be represented as the other.

## Offline CI gate

The required offline lane has no network access and no provider secrets. It must
run all of the following gates:

1. **Fixture/provider gate** — replay the checked-in
   `fixtures/provider_contract/*.json` responses through every registered
   provider and exercise the provider registry. No `MappingTransport` fixture
   is evidence of live API compatibility.
2. **Schema gate** — validate `fixtures/example_bundle.json` against the
   versioned bundle schema, including the privacy policy shape.
3. **Semantic/render gate** — exercise required-source coverage,
   evidence references, timestamps, scope ownership, failure classes, and the
   fail-closed legacy `allow_publish` decision. Per ADR-0017, this means render
   eligibility and never grants disclosure approval.
4. **Renderer/privacy gate** — render valid bundles offline, keep actors
   anonymous by default, accept only explicit actor labels, and reject or
   sanitize auth-bearing source URLs and sensitive fields.
5. **Registry/config gate** — verify known provider construction, unknown
   provider rejection, and the independent collection/report configuration
   validators.

The CI commands are:

```bash
python -m pytest -q --disable-socket
python -m compileall -q src
git diff --check
python scripts/check_schema_sync.py
python -m build
```

The repository's `unittest` suite is an equivalent dependency-light test entry
point when pytest is not installed:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Offline CI may produce diagnostic bundles for failed fixture cases, but it must
not call a provider endpoint, consume a provider secret, or label a fixture
replay as a live canary.

## Live provider canary

A live canary is a separate protected/manual job. It requires all of these
inputs before it starts:

- an ephemeral `LIVE_CANARY_CONFIG` containing an explicit, non-empty
  `scope.repositories` allowlist with provider, instance, owner, and name;
- a bounded timezone-aware window and provider runtime limits in that config;
- only the secret required by the selected provider, supplied through the
  environment or CI secret store: `GITHUB_TOKEN`, `GITLAB_TOKEN`, or
  `GITEE_TOKEN` (and the authorized `instance`/host allowlist for compatible
  installations);
- operator authorization to read every allowlisted repository and a record of
  the canary provider/instance/window.

The config must use `token_env`; tokens, authorization headers, cookies, and
credentials must never appear in YAML, command-line arguments, fixtures, logs,
or committed bundles. The allowlist is exact: provider discovery, wildcard
repositories, and “all projects” expansion are not valid canary inputs.

The live sequence is:

```bash
PYTHONPATH=src python -m git_evidence collect \
  --config "$LIVE_CANARY_CONFIG" --output /tmp/live-bundle.json
PYTHONPATH=src python -m git_evidence validate /tmp/live-bundle.json
PYTHONPATH=src python -m git_evidence render /tmp/live-bundle.json \
  --config "$LIVE_CANARY_CONFIG" --output /tmp/live-report.md
```

The collection exit status, schema/semantic validation, required-source
coverage, privacy gate, and offline render must all succeed before a canary is
eligible to enter an operator-controlled publication workflow. A core provider group failure,
incomplete required source, unsafe URL/payload, missing secret, or validation
error is a failed canary. An ordinary optional activity/ref malformed, typed,
transport, or capability failure is not by itself a failed canary when the
core resources are complete, but its `coverage.warnings[]` entry must remain
visible. An optional `privacy_violation` is fail-closed and is a failed
canary even when core resources are complete. A diagnostic bundle with a
core failure may be retained outside the repository, but it must keep
`coverage.allow_publish: false` and never be described as render-eligible. A
canary that was not executed is simply **unverified**; offline CI cannot
substitute for it.

The current repository validation does not execute a live canary. No GitHub,
GitLab, or Gitee live-provider result should be inferred from the offline test
suite.

The repository provides a separate `Protected live-provider canary` manual
workflow. Configure the `live-provider-canary` GitHub Environment with required
reviewers, restrict its deployment branches to protected `main`, and provide
only the selected provider's `LIVE_<PROVIDER>_CONFIG` and
`LIVE_<PROVIDER>_TOKEN` secrets. Add a comma-separated, non-secret
`LIVE_<PROVIDER>_INSTANCES` environment variable containing the independently
authorized exact instances. The protected config must reference
`token_env: LIVE_PROVIDER_TOKEN`. The workflow itself rejects non-`main` refs,
provider/config mismatches, and instances outside that environment allowlist.
It logs only the sanitized provider/instances/window/repository-count scope,
does not upload the sensitive bundle or report, and removes its temporary
config, bundle, and report at exit.

After `.github/workflows/ci.yml` is present on the default branch, protect
`main` with a branch ruleset that requires the stable `Offline contract
required` check. The workflow cannot configure repository rulesets itself; a
green Actions job is not a merge gate until that administrator-controlled
setting is enabled and verified.
