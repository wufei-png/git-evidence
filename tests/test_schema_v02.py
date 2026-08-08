from __future__ import annotations

from copy import deepcopy
from io import StringIO
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from git_evidence.cli import main as cli_main
from git_evidence.identity import (
    compute_artifact_bytes_digest,
    compute_bundle_digest,
    compute_plan_id,
    invocation_record,
)
from git_evidence.migration import MigrationError, migrate_v01_to_v02
from git_evidence.model import load_bundle
from git_evidence.render import render_bundle
from git_evidence.validation import recompute_allow_publish, validate_bundle
from git_evidence.providers.gitee import GiteeProvider
from git_evidence.providers.github import GitHubProvider
from git_evidence.providers.gitlab import GitLabProvider
from tests.test_contract import (
    gitee_transport,
    github_transport,
    gitlab_transport,
    request_for,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "example_bundle.json"
MIGRATED_AT = "2026-08-09T00:00:00Z"


def migrated_fixture() -> dict[str, object]:
    return migrate_v01_to_v02(
        load_bundle(FIXTURE),
        source_artifact_digest=compute_artifact_bytes_digest(FIXTURE.read_bytes()),
        migrated_at=MIGRATED_AT,
    )


def resign(bundle: dict[str, object]) -> None:
    bundle["plan_id"] = compute_plan_id(bundle["plan"])
    bundle["bundle_digest"] = compute_bundle_digest(bundle)


class CanonicalIdentityTests(unittest.TestCase):
    def test_plan_digest_normalizes_unicode_and_invocations_are_unique(self) -> None:
        decomposed = {"label": "Cafe\u0301", "items": [1, True, None]}
        composed = {"items": [1, True, None], "label": "Caf\u00e9"}
        self.assertEqual(compute_plan_id(decomposed), compute_plan_id(composed))
        self.assertNotEqual(invocation_record()["id"], invocation_record()["id"])

    def test_bundle_digest_sorts_canonical_collections_but_preserves_other_arrays(self) -> None:
        bundle = migrated_fixture()
        reversed_entities = deepcopy(bundle)
        reversed_entities["assertions"] = list(reversed(reversed_entities["assertions"]))
        self.assertEqual(
            compute_bundle_digest(bundle),
            compute_bundle_digest(reversed_entities),
        )

        reordered_scope = deepcopy(bundle)
        reordered_scope["plan"]["scope"]["actors"] = ["actor:b", "actor:a"]
        self.assertNotEqual(
            compute_bundle_digest(bundle),
            compute_bundle_digest(reordered_scope),
        )


class MigrationContractTests(unittest.TestCase):
    def test_migration_is_explicit_valid_and_does_not_mutate_source(self) -> None:
        source = load_bundle(FIXTURE)
        original = deepcopy(source)
        migrated = migrate_v01_to_v02(
            source,
            source_artifact_digest=compute_artifact_bytes_digest(FIXTURE.read_bytes()),
            migrated_at=MIGRATED_AT,
        )
        self.assertEqual(source, original)
        self.assertEqual(migrated["schema_version"], "0.2")
        self.assertNotIn("run", migrated)
        self.assertNotIn("facts", migrated)
        self.assertEqual(len(migrated["assertions"]), len(source["facts"]))
        self.assertTrue(migrated["retrievals"])
        self.assertEqual(validate_bundle(migrated), [])
        self.assertIn("Projects and topics", render_bundle(migrated))

    def test_cli_records_exact_source_bytes_and_does_not_rewrite_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "legacy.json"
            output = Path(directory) / "migrated.json"
            raw = FIXTURE.read_bytes() + b"\n"
            source.write_bytes(raw)
            loaded = load_bundle(source)
            self.assertEqual(loaded["schema_version"], "0.1")
            self.assertEqual(
                cli_main(["migrate", str(source), "--output", str(output)]),
                0,
            )
            migrated = load_bundle(output)
            from hashlib import sha256

            self.assertEqual(
                migrated["migration"]["source_artifact_digest"],
                f"artifact:sha256:{sha256(raw).hexdigest()}",
            )

    def test_invalid_legacy_bundle_cannot_be_migrated(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["run"].pop("run_id")
        with self.assertRaises(MigrationError):
            migrate_v01_to_v02(
                bundle,
                source_artifact_digest=compute_artifact_bytes_digest(FIXTURE.read_bytes()),
                migrated_at=MIGRATED_AT,
            )

    def test_migration_normalizes_retained_timestamps_to_utc_z(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["run"]["window"]["start"] = "2026-07-27T08:00:00+08:00"
        migrated = migrate_v01_to_v02(
            bundle,
            source_artifact_digest=compute_artifact_bytes_digest(FIXTURE.read_bytes()),
            migrated_at="2026-08-09T08:00:00+08:00",
        )
        self.assertEqual(migrated["plan"]["window"]["start"], "2026-07-27T00:00:00.000000Z")
        self.assertEqual(migrated["migration"]["migrated_at"], "2026-08-09T00:00:00.000000Z")
        self.assertEqual(validate_bundle(migrated), [])

    def test_recorded_provider_bundles_with_nullable_fields_migrate(self) -> None:
        cases = (
            (
                GitHubProvider(github_transport(), instance="github.com"),
                request_for("github", "github.com"),
            ),
            (
                GitLabProvider(gitlab_transport(), instance="gitlab.com"),
                request_for("gitlab", "gitlab.com"),
            ),
            (
                GiteeProvider(gitee_transport(), instance="gitee.com"),
                request_for("gitee", "gitee.com"),
            ),
        )
        for provider, request in cases:
            legacy = provider.collect(request)
            raw = json.dumps(legacy, sort_keys=True).encode("utf-8")
            migrated = migrate_v01_to_v02(
                legacy,
                source_artifact_digest=compute_artifact_bytes_digest(raw),
                migrated_at=MIGRATED_AT,
            )
            with self.subTest(provider=request.provider_kind):
                self.assertEqual(validate_bundle(migrated), [])

    def test_safe_unknown_legacy_fields_move_under_provider_extensions(self) -> None:
        source = load_bundle(FIXTURE)
        source["repositories"][0]["description"] = "safe legacy metadata"
        raw = json.dumps(source, sort_keys=True).encode("utf-8")
        migrated = migrate_v01_to_v02(
            source,
            source_artifact_digest=compute_artifact_bytes_digest(raw),
            migrated_at=MIGRATED_AT,
        )
        self.assertEqual(
            migrated["repositories"][0]["extensions"]["github"]["legacy_fields"]["description"],
            "safe legacy metadata",
        )
        self.assertEqual(validate_bundle(migrated), [])


class StrictV02ValidationTests(unittest.TestCase):
    def test_tampering_and_unknown_fields_fail_closed(self) -> None:
        bundle = migrated_fixture()
        bundle["repositories"][0]["full_name"] = "tampered/project"
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("bundle.digest_mismatch", codes)
        self.assertIn("repository.identity", codes)

        bundle = migrated_fixture()
        bundle["repositories"][0]["unexpected"] = True
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("schema.additionalProperties", codes)

    def test_namespaced_extensions_are_accepted_and_covered_by_digest(self) -> None:
        bundle = migrated_fixture()
        old_digest = bundle["bundle_digest"]
        bundle["repositories"][0]["extensions"] = {
            "github": {"database_id": 123}
        }
        self.assertTrue(recompute_allow_publish(bundle))
        self.assertNotEqual(bundle["bundle_digest"], old_digest)
        self.assertEqual(validate_bundle(bundle), [])

    def test_plan_and_invocation_invariants_are_recomputed(self) -> None:
        bundle = migrated_fixture()
        bundle["plan"]["scope"]["repositories"].append("repo:github:github.com:other/project")
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("plan.digest_mismatch", codes)

        bundle = migrated_fixture()
        bundle["invocation"]["started_at"] = "2026-08-10T00:00:00Z"
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("invocation.order", codes)

    def test_plan_providers_and_sources_are_bound_to_bundle_scope(self) -> None:
        bundle = migrated_fixture()
        bundle["plan"]["providers"].append(deepcopy(bundle["plan"]["providers"][0]))
        resign(bundle)
        self.assertIn(
            "plan.provider_duplicate",
            {issue.code for issue in validate_bundle(bundle)},
        )

        bundle = migrated_fixture()
        bundle["plan"]["providers"][0]["selected_sources"] = []
        resign(bundle)
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("plan.sources_mismatch", codes)
        self.assertIn("schema.minItems", codes)

    def test_evidence_retrieval_provider_and_predicate_subject_are_bound(self) -> None:
        bundle = migrated_fixture()
        bundle["retrievals"][0]["provider_id"] = "provider:gitlab:gitlab.com"
        resign(bundle)
        self.assertIn(
            "evidence.retrieval_provider",
            {issue.code for issue in validate_bundle(bundle)},
        )

        bundle = migrated_fixture()
        assertion = next(
            item
            for item in bundle["assertions"]
            if item["subject_type"] == "work_item"
        )
        assertion["predicate"] = "release.published.v1"
        resign(bundle)
        self.assertIn(
            "assertion.predicate_subject",
            {issue.code for issue in validate_bundle(bundle)},
        )

    def test_cache_age_and_mode_specific_provenance_are_verified(self) -> None:
        bundle = migrated_fixture()
        retrieval = bundle["retrievals"][0]
        retrieval.clear()
        retrieval.update(
            {
                "id": "retrieval:cache:fixture",
                "provider_id": bundle["providers"][0]["id"],
                "repository_id": bundle["repositories"][0]["id"],
                "mode": "cache_replay",
                "endpoint_kind": "issues",
                "target_ref": bundle["repositories"][0]["id"],
                "fetched_at": "2026-08-01T00:00:00Z",
                "stored_at": "2026-08-01T00:00:00Z",
                "replayed_at": "2026-08-09T00:00:00Z",
                "cache_age_seconds": 0,
                "cache_ttl_seconds": 60,
            }
        )
        for evidence in bundle["evidence"]:
            evidence["retrieval_id"] = retrieval["id"]
        resign(bundle)
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("retrieval.cache_age_mismatch", codes)
        self.assertIn("retrieval.cache_stale", codes)

        bundle = migrated_fixture()
        bundle["retrievals"][0]["fetched_at"] = "2026-08-09T00:00:00Z"
        resign(bundle)
        self.assertIn(
            "retrieval.mode_fields",
            {issue.code for issue in validate_bundle(bundle)},
        )

    def test_json_diagnostics_validate_v02(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.json"
            path.write_text(json.dumps(migrated_fixture()), encoding="utf-8")
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                status = cli_main(
                    ["validate", str(path), "--diagnostics-format", "json"]
                )
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(stdout.getvalue())["status"], "valid")


if __name__ == "__main__":
    unittest.main()
