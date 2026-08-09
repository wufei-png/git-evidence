from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from git_evidence.collect import collect_config
from git_evidence.config import validate_collection_config
from git_evidence.providers import GiteeProvider, GitHubProvider, GitLabProvider
from git_evidence.providers.transport import new_response_correlation_key
from git_evidence.render import render_bundle
from git_evidence.validation import recompute_allow_publish, validate_bundle
from tests.test_contract import (
    WINDOW_END,
    WINDOW_START,
    gitee_transport,
    github_transport,
    gitlab_transport,
)


class V02CollectionTests(unittest.TestCase):
    def test_response_correlation_keys_do_not_depend_on_object_lifetimes(self) -> None:
        keys = [new_response_correlation_key() for _ in range(1000)]
        self.assertEqual(len(keys), len(set(keys)))

    def _collect(
        self,
        *,
        window_start: object = WINDOW_START,
        window_end: object = WINDOW_END,
    ) -> dict[str, object]:
        adapters = {
            "github": (GitHubProvider, github_transport(), "github.com"),
            "gitlab": (GitLabProvider, gitlab_transport(), "gitlab.com"),
            "gitee": (GiteeProvider, gitee_transport(), "gitee.com"),
        }

        def factory(
            kind: str, instance: str, options: dict[str, object], token: str | None
        ) -> object:
            del options, token
            provider, transport, _ = adapters[kind]
            return provider(transport, instance=instance)

        config = {
            "window": {"start": window_start, "end": window_end, "timezone": "UTC"},
            "scope": {
                "repositories": [
                    {
                        "provider_ref": f"public-{kind}",
                        "owner": "example",
                        "name": "project",
                    }
                    for kind, (_, _, instance) in adapters.items()
                ],
                "actors": [],
            },
            "providers": {
                f"public-{kind}": {"kind": kind, "instance": instance}
                for kind, (_, _, instance) in adapters.items()
            },
        }
        return collect_config(
            validate_collection_config(config), provider_factory=factory
        )

    def test_collects_strict_v02_with_response_and_native_provenance(self) -> None:
        bundle = self._collect()
        self.assertEqual(bundle["schema_version"], "0.2")
        self.assertNotIn("run", bundle)
        self.assertNotIn("facts", bundle)
        self.assertNotIn("allow_publish", bundle["coverage"])
        self.assertTrue(bundle["coverage"]["render_eligible"])
        self.assertEqual(validate_bundle(bundle), [])
        self.assertEqual(
            {item["mode"] for item in bundle["retrievals"]},
            {"recorded_replay"},
        )
        retrieval_ids = {item["id"] for item in bundle["retrievals"]}
        self.assertTrue(bundle["evidence"])
        self.assertTrue(bundle["assertions"])
        self.assertTrue(
            all(item["retrieval_id"] in retrieval_ids for item in bundle["evidence"])
        )
        self.assertTrue(
            all(
                item["native_identity"]["state"] == "known"
                for item in bundle["evidence"]
            )
        )

    def test_plan_identity_is_stable_while_invocations_are_unique(self) -> None:
        first = self._collect()
        second = self._collect()
        self.assertEqual(first["plan_id"], second["plan_id"])
        self.assertNotEqual(first["invocation"]["id"], second["invocation"]["id"])
        self.assertNotEqual(first["bundle_digest"], second["bundle_digest"])

    def test_equivalent_timestamp_types_have_one_plan_identity(self) -> None:
        strings = self._collect()
        start = datetime.fromisoformat(WINDOW_START)
        end = datetime.fromisoformat(WINDOW_END)
        datetimes = self._collect(window_start=start, window_end=end)
        offset = timezone(timedelta(hours=8))
        offsets = self._collect(
            window_start=start.astimezone(offset),
            window_end=end.astimezone(offset),
        )
        self.assertEqual(strings["plan_id"], datetimes["plan_id"])
        self.assertEqual(strings["plan_id"], offsets["plan_id"])

    def test_missing_provider_provenance_fails_closed(self) -> None:
        transport = github_transport()

        class ProvenanceStrippingProvider:
            def collect(self, request: object) -> dict[str, object]:
                bundle = GitHubProvider(transport).collect(request)  # type: ignore[arg-type]
                bundle["retrievals"] = []
                for evidence in bundle["evidence"]:
                    evidence.pop("retrieval_id", None)
                    evidence.pop("native_identity", None)
                return bundle

        config = {
            "window": {"start": WINDOW_START, "end": WINDOW_END, "timezone": "UTC"},
            "scope": {
                "repositories": [
                    {
                        "provider_ref": "public-github",
                        "owner": "example",
                        "name": "project",
                    }
                ],
                "actors": [],
            },
            "providers": {
                "public-github": {"kind": "github", "instance": "github.com"}
            },
        }
        bundle = collect_config(
            validate_collection_config(config),
            provider_factory=lambda *args: ProvenanceStrippingProvider(),
        )
        self.assertFalse(bundle["coverage"]["render_eligible"])
        self.assertEqual(
            {item["failure_class"] for item in bundle["coverage"]["group_failures"]},
            {"malformed_response"},
        )

    def test_renderer_keeps_stable_evidence_references_without_urls(self) -> None:
        bundle = self._collect()
        retrieval_id = bundle["evidence"][0]["retrieval_id"]
        next(item for item in bundle["retrievals"] if item["id"] == retrieval_id)[
            "target_ref"
        ] = "https://api.example.test/private/repository"
        recompute_allow_publish(bundle)
        report = render_bundle(bundle, allow_source_urls=False)
        self.assertIn("[E1]", report)
        self.assertIn("## Evidence index", report)
        self.assertIn("invocation_id", report)
        self.assertIn("bundle_digest", report)
        self.assertIn("render-policy-v1", report)
        self.assertNotIn("](<https://", report)
        self.assertNotIn("https://api.example.test", report)
        self.assertIn(r"source_ref=\[hidden\]", report)


if __name__ == "__main__":
    unittest.main()
