from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from git_evidence.cli import main as cli_main
from git_evidence.identity import (
    compute_bundle_digest,
    compute_plan_id,
    invocation_record,
)
from git_evidence.model import BundleLoadError, load_bundle
from git_evidence.validation import recompute_render_eligibility, validate_bundle

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "example_bundle.json"


def canonical_fixture() -> dict[str, object]:
    return deepcopy(load_bundle(FIXTURE))


def resign(bundle: dict[str, object]) -> None:
    bundle["plan_id"] = compute_plan_id(bundle["plan"])
    bundle["bundle_digest"] = compute_bundle_digest(bundle)


class CanonicalIdentityTests(unittest.TestCase):
    def test_plan_digest_normalizes_unicode_and_invocations_are_unique(self) -> None:
        decomposed = {"label": "Cafe\u0301", "items": [1, True, None]}
        composed = {"items": [1, True, None], "label": "Caf\u00e9"}
        self.assertEqual(compute_plan_id(decomposed), compute_plan_id(composed))
        self.assertNotEqual(invocation_record()["id"], invocation_record()["id"])

    def test_bundle_digest_sorts_canonical_collections_but_preserves_other_arrays(
        self,
    ) -> None:
        bundle = canonical_fixture()
        reversed_entities = deepcopy(bundle)
        reversed_entities["assertions"] = list(
            reversed(reversed_entities["assertions"])
        )
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


class StrictV03ValidationTests(unittest.TestCase):
    def test_older_schema_versions_are_neither_loaded_nor_validated(self) -> None:
        for version in ("0.1", "0.2"):
            raw = json.dumps({"schema_version": version})
            with (
                self.subTest(version=version),
                self.assertRaisesRegex(BundleLoadError, "only schema_version 0.3"),
            ):
                load_bundle(StringIO(raw))
            self.assertIn(
                "schema.version",
                {issue.code for issue in validate_bundle({"schema_version": version})},
            )

    def test_cli_has_no_migration_command(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            cli_main(["migrate", "legacy.json"])
        self.assertEqual(caught.exception.code, 2)

    def test_tampering_and_unknown_fields_fail_closed(self) -> None:
        bundle = canonical_fixture()
        bundle["repositories"][0]["full_name"] = "tampered/project"
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("bundle.digest_mismatch", codes)
        self.assertIn("repository.identity", codes)

        bundle = canonical_fixture()
        bundle["repositories"][0]["unexpected"] = True
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("schema.additionalProperties", codes)

    def test_generic_extensions_are_rejected(self) -> None:
        bundle = canonical_fixture()
        bundle["repositories"][0]["extensions"] = {"github": {"database_id": 123}}
        self.assertFalse(recompute_render_eligibility(bundle))
        self.assertIn(
            "schema.additionalProperties",
            {issue.code for issue in validate_bundle(bundle)},
        )

    def test_plan_and_invocation_invariants_are_recomputed(self) -> None:
        bundle = canonical_fixture()
        bundle["plan"]["scope"]["repositories"].append(
            "repo:github:github.com:other/project"
        )
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("plan.digest_mismatch", codes)

        bundle = canonical_fixture()
        bundle["invocation"]["started_at"] = "2026-08-10T00:00:00Z"
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("invocation.order", codes)

    def test_plan_providers_and_sources_are_bound_to_bundle_scope(self) -> None:
        bundle = canonical_fixture()
        bundle["plan"]["providers"].append(deepcopy(bundle["plan"]["providers"][0]))
        resign(bundle)
        self.assertIn(
            "plan.provider_duplicate",
            {issue.code for issue in validate_bundle(bundle)},
        )

        bundle = canonical_fixture()
        bundle["plan"]["providers"][0]["selected_sources"] = []
        resign(bundle)
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("plan.sources_mismatch", codes)
        self.assertIn("schema.minItems", codes)

    def test_evidence_retrieval_provider_and_predicate_subject_are_bound(self) -> None:
        bundle = canonical_fixture()
        evidence = bundle["evidence"][0]
        retrieval = next(
            item
            for item in bundle["retrievals"]
            if item["id"] == evidence["retrieval_id"]
        )
        retrieval["provider_id"] = "provider:gitlab:gitlab.com"
        self.assertNotEqual(evidence["provider_id"], retrieval["provider_id"])
        resign(bundle)
        self.assertIn(
            "evidence.retrieval_provider",
            {issue.code for issue in validate_bundle(bundle)},
        )

        bundle = canonical_fixture()
        assertion = next(
            item for item in bundle["assertions"] if item["subject_type"] == "work_item"
        )
        assertion["predicate"] = "release.published.v1"
        resign(bundle)
        self.assertIn(
            "assertion.predicate_subject",
            {issue.code for issue in validate_bundle(bundle)},
        )

    def test_assertion_event_times_are_bound_to_subject_events(self) -> None:
        cases = (
            ("change_request.observed.v1", "occurred_at"),
            ("change_request.merged.v1", "merged_at"),
        )
        for predicate, subject_time_field in cases:
            with self.subTest(predicate=predicate):
                bundle = canonical_fixture()
                assertion = next(
                    item
                    for item in bundle["assertions"]
                    if item["predicate"] == predicate
                )
                subject = next(
                    item
                    for item in bundle["change_requests"]
                    if item["id"] == assertion["subject_id"]
                )
                self.assertNotEqual("2026-07-31T12:00:00Z", subject[subject_time_field])
                assertion["occurred_at"] = "2026-07-31T12:00:00Z"
                self.assertFalse(recompute_render_eligibility(bundle))
                self.assertIn(
                    "assertion.event_time",
                    {issue.code for issue in validate_bundle(bundle)},
                )

    def test_every_observed_entity_has_an_assertion(self) -> None:
        for subject_type in ("work_item", "commit", "release"):
            with self.subTest(subject_type=subject_type):
                bundle = canonical_fixture()
                position = next(
                    index
                    for index, assertion in enumerate(bundle["assertions"])
                    if assertion["subject_type"] == subject_type
                    and assertion["predicate"].endswith(".observed.v1")
                )
                bundle["assertions"].pop(position)
                self.assertFalse(recompute_render_eligibility(bundle))
                self.assertIn(
                    "assertion.observation_missing",
                    {issue.code for issue in validate_bundle(bundle)},
                )

    def test_commit_evidence_native_identity_is_bound_to_sha(self) -> None:
        bundle = canonical_fixture()
        evidence = next(
            item for item in bundle["evidence"] if item["subject_type"] == "commit"
        )
        evidence["native_identity"]["value"] = "f" * 40
        self.assertFalse(recompute_render_eligibility(bundle))
        self.assertIn(
            "evidence.commit_native_identity",
            {issue.code for issue in validate_bundle(bundle)},
        )

    def test_plan_timezone_must_be_a_valid_iana_identifier(self) -> None:
        bundle = canonical_fixture()
        bundle["plan"]["window"]["timezone"] = "Mars/Olympus"
        bundle["plan_id"] = compute_plan_id(bundle["plan"])
        self.assertFalse(recompute_render_eligibility(bundle))
        self.assertIn(
            "window.timezone",
            {issue.code for issue in validate_bundle(bundle)},
        )

    def test_cache_age_and_mode_specific_provenance_are_verified(self) -> None:
        bundle = canonical_fixture()
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

        bundle = canonical_fixture()
        bundle["retrievals"][0]["fetched_at"] = "2026-08-09T00:00:00Z"
        resign(bundle)
        self.assertIn(
            "retrieval.mode_fields",
            {issue.code for issue in validate_bundle(bundle)},
        )

    def test_json_diagnostics_validate_v03(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.json"
            path.write_text(json.dumps(canonical_fixture()), encoding="utf-8")
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                status = cli_main(
                    ["validate", str(path), "--diagnostics-format", "json"]
                )
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(stdout.getvalue())["status"], "valid")


if __name__ == "__main__":
    unittest.main()
