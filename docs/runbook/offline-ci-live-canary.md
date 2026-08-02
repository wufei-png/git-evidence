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
3. **Semantic/publication gate** — exercise required-source coverage,
   evidence references, timestamps, scope ownership, failure classes, and the
   fail-closed `allow_publish` decision.
4. **Renderer/privacy gate** — render valid bundles offline, keep actors
   anonymous by default, accept only explicit actor labels, and reject or
   sanitize auth-bearing source URLs and sensitive fields.
5. **Registry/config gate** — verify known provider construction, unknown
   provider rejection, and the independent collection/report configuration
   validators.

The CI commands are:

```bash
python -m pytest -q
python -m compileall -q src
git diff --check
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
eligible for any publication workflow. A provider group failure, incomplete
required source, unsafe URL/payload, missing secret, or validation error is a
failed canary. Its diagnostic bundle may be retained outside the repository,
but it must keep `coverage.allow_publish: false` where a bundle exists and must
never be described as publishable. A canary that was not executed is simply
**unverified**; offline CI cannot substitute for it.

The current repository validation does not execute a live canary. No GitHub,
GitLab, or Gitee live-provider result should be inferred from the offline test
suite.
