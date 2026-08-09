from __future__ import annotations

import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from git_evidence.config import ConfigError, load_collection_config, load_report_config
from git_evidence.model import load_bundle
from git_evidence.privacy import sanitize_public_url
from git_evidence.providers import PROVIDER_REGISTRY, ProviderRegistryError
from git_evidence.render import render_bundle
from git_evidence.validation import validate_bundle

FIXTURE = ROOT / "fixtures" / "example_bundle.json"


class P2ContractTests(unittest.TestCase):
    def test_collection_and_report_loaders_materialize_typed_toml(self) -> None:
        collection_config = """
[window]
start = 2026-07-27T00:00:00Z
end = 2026-08-03T00:00:00Z
timezone = "UTC"

[scope]
actors = []

[[scope.repositories]]
provider_ref = "public-github"
owner = "example"
name = "project"

[providers.public-github]
kind = "github"
instance = "github.com"
"""
        report_config = """
[report]
profile = "timeline"
language = "en"

[report.privacy]
actor_display = "anonymous"
allow_source_urls = true
auth_redaction = true
"""
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "collection.toml"
            first.write_text(collection_config, encoding="utf-8")
            self.assertEqual(
                load_collection_config(first).repositories[0].target.provider_kind,
                "github",
            )
            self.assertEqual(load_report_config(first).profile, "project-first")

            second = Path(directory) / "report.toml"
            second.write_text(report_config, encoding="utf-8")
            report = load_report_config(second)
            self.assertEqual(report.profile, "timeline")
            with self.assertRaises(ConfigError):
                load_collection_config(second)

    def test_provider_registry_creates_known_provider_and_rejects_unknown(self) -> None:
        provider = PROVIDER_REGISTRY.create(
            "github",
            instance="github.com",
            provider_config={},
            token=None,
            runtime_options={},
        )
        self.assertEqual(provider.probe()["kind"], "github")
        with self.assertRaises(ProviderRegistryError):
            PROVIDER_REGISTRY.registration("unknown")

    def test_privacy_gate_rejects_auth_bearing_evidence_urls(self) -> None:
        bundle = load_bundle(FIXTURE)
        unsafe = deepcopy(bundle)
        unsafe_url = "https://example.test/issues/7?access_token=fixture-secret&view=full#comment-1"
        unsafe["evidence"][0]["url"] = unsafe_url
        self.assertEqual(
            sanitize_public_url(unsafe_url),
            "https://example.test/issues/7?view=full#comment-1",
        )
        self.assertTrue(
            any(issue.code == "privacy.auth_url" for issue in validate_bundle(unsafe))
        )
        with self.assertRaises(ValueError):
            render_bundle(unsafe)


if __name__ == "__main__":
    unittest.main()
