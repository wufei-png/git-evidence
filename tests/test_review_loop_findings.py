from __future__ import annotations

from copy import deepcopy
from io import BytesIO
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from git_evidence.cli import main as cli_main
from git_evidence.collect import _merge_bundles, collect_config
from git_evidence.config import ConfigError, provider_runtime_options, validate_collection_config, validate_report_config
from git_evidence.model import load_bundle
from git_evidence.privacy import (
    PrivacyError,
    is_sensitive_field,
    sanitize_public_payload,
)
from git_evidence.providers.github import GitHubProvider
from git_evidence.providers.resource_base import in_window_or_malformed, parse_timestamp
from git_evidence.providers.transport import ApiResponse, LocalResponseCache, UrllibTransport
from git_evidence.validation import validate_bundle

from test_contract import WINDOW_END, WINDOW_START, github_transport, request_for


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "example_bundle.json"


class ReviewLoopFindingTests(unittest.TestCase):
    def test_group_failure_cannot_coexist_with_publishable_ledger(self) -> None:
        bundle = load_bundle(FIXTURE)
        failure = {
            "provider": "github",
            "instance": "github.com",
            "repository": bundle["repositories"][0]["id"],
            "source": "commits",
            "failure_class": "rate_limited",
        }
        bundle["coverage"]["group_failures"] = [failure]
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("coverage.group_failure_contradiction", codes)
        self.assertIn("coverage.group_failure_fatal", codes)
        self.assertIn("coverage.publish_blocked", codes)

    def test_fact_evidence_subject_and_provider_provenance_are_required(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["evidence"][0].pop("subject_id")
        self.assertIn("fact.evidence_subject", {issue.code for issue in validate_bundle(bundle)})

        bundle = load_bundle(FIXTURE)
        bundle["evidence"][0]["provider_id"] = "provider:gitlab:gitlab.com"
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("evidence.provenance", codes)
        self.assertIn("fact.evidence_provenance", codes)

    def test_internal_api_failure_has_group_ledger_and_preserves_siblings(self) -> None:
        transport = github_transport()
        transport.responses.pop("/repos/example/project/issues")
        bundle = GitHubProvider(transport).collect(request_for("github", "github.com"))
        self.assertFalse(bundle["coverage"]["allow_publish"])
        self.assertTrue(bundle["work_items"] == [])
        self.assertGreater(len(bundle["change_requests"]), 0)
        self.assertTrue(
            any(
                item["source"] == "work_items" and item["failure_class"] == "fixture_missing"
                for item in bundle["coverage"]["group_failures"]
            )
        )

    def test_merge_does_not_silently_drop_duplicate_records(self) -> None:
        bundle = load_bundle(FIXTURE)
        duplicate = deepcopy(bundle)
        merged = _merge_bundles(
            [bundle, duplicate],
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            timezone="UTC",
            repository_ids=[bundle["repositories"][0]["id"]],
            actor_ids=[],
        )
        self.assertEqual(len(merged["facts"]), len(bundle["facts"]))
        self.assertTrue(
            any(
                "duplicate record id" in failure.get("reason", "")
                for failure in merged["coverage"]["group_failures"]
            )
        )
        self.assertFalse(merged["coverage"]["allow_publish"])

    def test_cache_replays_allowlisted_pagination_headers_and_rejects_old_or_unsafe_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            cache = LocalResponseCache(path, ttl_seconds=300, max_entries=10)
            response = ApiResponse(
                "https://example.test/items",
                200,
                {
                    "Link": '<https://example.test/items?page=2>; rel="next"',
                    "X-Next-Page": "2",
                    "X-RateLimit-Remaining": "4",
                    "Authorization": "Bearer should-not-persist",
                },
                [{"id": 1}],
            )
            cache.put("page-1", response, token=None)
            replay = cache.get("page-1")
            self.assertIsNotNone(replay)
            assert replay is not None
            self.assertEqual(replay.headers["link"], '<https://example.test/items?page=2>; rel="next"')
            self.assertEqual(replay.headers["x-next-page"], "2")
            self.assertEqual(replay.headers["x-ratelimit-remaining"], "4")
            self.assertNotIn("authorization", replay.headers)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)

            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["entries"]["old"] = {
                "stored_at": 0,
                "response": {"url": "https://example.test/items", "status_code": 200, "body": []},
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertIsNone(cache.get("old"))
            os.chmod(path, 0o644)
            self.assertIsNone(cache.get("page-1"))

            unsafe_path = Path(directory) / "unsafe.json"
            unsafe_cache = LocalResponseCache(unsafe_path, ttl_seconds=300, max_entries=10)
            unsafe_cache.put(
                "body-secret",
                ApiResponse("https://example.test/items", 200, {}, {"api_key": "secret"}),
                token=None,
            )
            self.assertFalse(unsafe_path.exists())
            unsafe_cache.put(
                "url-secret",
                ApiResponse("https://example.test/items?X-API-Key=secret", 200, {}, []),
                token=None,
            )
            self.assertFalse(unsafe_path.exists())
            unsafe_cache.put(
                "body-url-secret",
                ApiResponse(
                    "https://example.test/items",
                    200,
                    {},
                    {"web_url": "https://example.test/items?access_token=secret"},
                ),
                token=None,
            )
            self.assertFalse(unsafe_path.exists())

    def test_privacy_key_variants_are_canonical_and_rejected(self) -> None:
        for key in ("clientSecret", "X-API-Key", "authHeader", "X-Auth-Token", "github_token"):
            self.assertTrue(is_sensitive_field(key), key)
        self.assertFalse(is_sensitive_field("author"))
        with self.assertRaises(PrivacyError):
            sanitize_public_payload({"clientSecret": "secret"})
        with self.assertRaises(PrivacyError):
            sanitize_public_payload({"X-API-Key": "secret"})

    def test_inline_credentials_are_rejected_recursively_without_rejecting_business_fields(self) -> None:
        base = {
            "window": {"start": WINDOW_START, "end": WINDOW_END, "timezone": "UTC"},
            "scope": {
                "repositories": [
                    {"provider": "github", "instance": "github.com", "owner": "example", "name": "project"}
                ]
            },
            "providers": {"github": {"token_env": "GITHUB_TOKEN"}},
        }
        safe = deepcopy(base)
        safe["providers"]["github"]["business"] = {"author": "synthetic", "tokenized_name": "safe"}
        validate_collection_config(safe)
        for secret_key in ("github_token", "clientSecret", "X-API-Key", "authHeader"):
            unsafe = deepcopy(base)
            unsafe["providers"]["github"]["nested"] = {secret_key: "secret"}
            with self.subTest(secret_key=secret_key), self.assertRaises(ConfigError):
                validate_collection_config(unsafe)
        unsafe_alias = deepcopy(base)
        unsafe_alias["providers"]["github"] = {"tokenEnv": "secret-value"}
        with self.assertRaises(ConfigError):
            validate_collection_config(unsafe_alias)

    def test_report_privacy_type_errors_are_config_errors_and_cli_status_two(self) -> None:
        with self.assertRaises(ConfigError):
            validate_report_config({"privacy": {"actor_display": []}})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.yml"
            path.write_text("report:\n  privacy:\n    actor_display: []\n", encoding="utf-8")
            result = cli_main(["render", str(FIXTURE), "--config", str(path)])
            self.assertEqual(result, 2)

    def test_provider_privacy_failure_is_not_reclassified_as_malformed(self) -> None:
        class LeakyProvider:
            def collect(self, request: object) -> dict[str, object]:
                del request
                return {"token": "must-not-cross-public-boundary"}

        config = {
            "window": {"start": WINDOW_START, "end": WINDOW_END, "timezone": "UTC"},
            "scope": {
                "repositories": [
                    {"provider": "github", "instance": "github.com", "owner": "example", "name": "project"}
                ],
                "actors": [],
            },
            "providers": {"github": {}},
        }
        bundle = collect_config(config, provider_factory=lambda *args: LeakyProvider())
        self.assertTrue(
            any(
                failure["failure_class"] == "privacy_violation"
                for failure in bundle["coverage"]["group_failures"]
            )
        )

    def test_retry_budget_preserves_primary_remote_failure(self) -> None:
        error = HTTPError(
            "https://example.test/items",
            429,
            "rate limited",
            {"Retry-After": "0"},
            BytesIO(b"rate limited"),
        )
        transport = UrllibTransport(
            "https://example.test",
            max_requests=1,
            max_retries=2,
            retry_backoff=0,
            sleep_fn=lambda _: None,
        )
        with patch("git_evidence.providers.transport.urlopen", side_effect=[error]):
            with self.assertRaises(Exception) as caught:
                transport.get("/items")
        self.assertEqual(caught.exception.failure_class, "rate_limited")
        self.assertEqual(caught.exception.failure_classes, ("rate_limited", "budget_exhausted"))
        self.assertTrue(transport.metrics()["budget_exhausted"])

    def test_naive_provider_timestamps_are_not_accepted(self) -> None:
        self.assertIsNone(parse_timestamp("2026-07-28T08:00:00"))
        request = request_for("github", "github.com")
        self.assertTrue(in_window_or_malformed({"occurred_at": "2026-07-28T08:00:00"}, request, "occurred_at"))
        transport = github_transport()
        transport.responses["/repos/example/project/issues"][0].body[0]["created_at"] = "2026-07-28T08:00:00Z"
        transport.responses["/repos/example/project/issues"][0].body[0]["updated_at"] = "2026-07-01T08:00:00Z"
        bundle = GitHubProvider(transport).collect(request)
        self.assertEqual(bundle["work_items"], [])

    def test_runtime_and_transport_budgets_are_finite_and_bounded(self) -> None:
        for key, value in (
            ("timeout_seconds", float("inf")),
            ("max_retries", 11),
            ("max_pages", 1001),
            ("max_requests", 10_001),
            ("retry_backoff_seconds", 61),
            ("retry_jitter_seconds", 61),
            ("retry_after_max_seconds", 301),
        ):
            with self.subTest(key=key), self.assertRaises(ConfigError):
                provider_runtime_options("github", {key: value})
        with self.assertRaises(ConfigError):
            provider_runtime_options("github", {"cache": {"ttl_seconds": 86_401}})
        with self.assertRaises(ConfigError):
            provider_runtime_options("github", {"cache": {"max_entries": 10_001}})
        with self.assertRaises(ValueError):
            UrllibTransport("https://example.test", timeout=301)
        with self.assertRaises(ValueError):
            UrllibTransport("https://example.test", max_retries=11)
        with self.assertRaises(ValueError):
            UrllibTransport("https://example.test", max_requests=10_001)


if __name__ == "__main__":
    unittest.main()
