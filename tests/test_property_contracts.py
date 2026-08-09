from __future__ import annotations

import itertools
import json
import os
import random
import string
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlencode

from git_evidence.model import load_bundle
from git_evidence.privacy import (
    AUTH_QUERY_NAMES,
    has_auth_material,
    redact_public_url,
    sanitize_public_url,
)
from git_evidence.providers.base import (
    OPTIONAL_COVERAGE_WARNING_CODE,
    RepositoryTarget,
    merge_optional_coverage_warning,
    validate_instance,
)
from git_evidence.providers.transport import LocalResponseCache
from git_evidence.validation import has_blocking_core_coverage

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "example_bundle.json"


class PropertyContractTests(unittest.TestCase):
    def test_generated_auth_urls_are_sanitized_idempotently(self) -> None:
        generator = random.Random(0xE11D3E)
        auth_names = sorted(AUTH_QUERY_NAMES)
        alphabet = string.ascii_letters + string.digits
        for index in range(128):
            secret = "".join(generator.choice(alphabet) for _ in range(24))
            auth_name = generator.choice(auth_names)
            query = urlencode({"view": str(index), auth_name: secret})
            unsafe = f"https://user:{secret}@example.test/items?{query}#section"
            with self.subTest(index=index, auth_name=auth_name):
                sanitized = sanitize_public_url(unsafe)
                self.assertEqual(sanitize_public_url(sanitized), sanitized)
                self.assertFalse(has_auth_material(sanitized))
                self.assertNotIn(secret, sanitized)
                self.assertIn(f"view={index}", sanitized)

                redacted = redact_public_url(unsafe)
                self.assertEqual(redact_public_url(redacted), redacted)
                self.assertNotIn(secret, redacted)
                self.assertIn("%5BREDACTED%5D", redacted)

    def test_instance_and_repository_ids_are_canonical_and_idempotent(self) -> None:
        variants = (
            ("EXAMPLE.test", "example.test"),
            ("https://EXAMPLE.test:443/", "example.test"),
            ("https://example.test/api/", "https://example.test/api"),
            ("http://EXAMPLE.test:80/root/", "http://example.test/root"),
        )
        for raw_instance, expected in variants:
            with self.subTest(raw_instance=raw_instance):
                canonical = validate_instance(raw_instance)
                self.assertEqual(canonical, expected)
                self.assertEqual(validate_instance(canonical), canonical)
                first = RepositoryTarget("github", raw_instance, "owner", "project")
                second = RepositoryTarget("github", canonical, first.owner, first.name)
                self.assertEqual(first.canonical_id, second.canonical_id)

    def test_optional_warning_merge_is_permutation_invariant(self) -> None:
        warnings = (
            {
                "code": OPTIONAL_COVERAGE_WARNING_CODE,
                "source": "activities",
                "provider_id": "provider:github:github.com",
                "repository_id": "repo:github:github.com:example/project",
                "status": "unsupported",
                "failure_class": "provider_not_ready",
                "message": "adapter unavailable",
            },
            {
                "code": OPTIONAL_COVERAGE_WARNING_CODE,
                "source": "activities",
                "provider_id": "provider:github:github.com",
                "repository_id": "repo:github:github.com:example/project",
                "status": "unavailable",
                "failure_class": "rate_limited",
                "message": "remote unavailable for the window",
            },
            {
                "code": OPTIONAL_COVERAGE_WARNING_CODE,
                "source": "activities",
                "provider_id": "provider:github:github.com",
                "repository_id": "repo:github:github.com:example/project",
                "status": "incomplete",
                "failure_class": "malformed_response",
                "message": "some records were malformed",
            },
        )
        results = []
        for order in itertools.permutations(warnings):
            coverage: dict[str, object] = {"warnings": []}
            for warning in order:
                merge_optional_coverage_warning(coverage, warning)
            results.append(json.dumps(coverage, sort_keys=True))
        self.assertEqual(len(set(results)), 1)

    def test_core_blockers_are_monotonic_under_failure_addition(self) -> None:
        bundle = load_bundle(FIXTURE)
        coverage = deepcopy(bundle["coverage"])
        repository_id = bundle["plan"]["scope"]["repositories"][0]
        provider_id = bundle["providers"][0]["id"]
        options = {
            "repository_ids": [repository_id],
            "provider_ids_by_repository": {repository_id: provider_id},
        }
        self.assertFalse(has_blocking_core_coverage(coverage, **options))
        coverage["warnings"].append(
            {
                "code": OPTIONAL_COVERAGE_WARNING_CODE,
                "source": "activities",
                "provider_id": provider_id,
                "repository_id": repository_id,
                "status": "unavailable",
            }
        )
        self.assertFalse(has_blocking_core_coverage(coverage, **options))

        additions = (
            (
                "group_failures",
                {
                    "provider": "github",
                    "instance": "github.com",
                    "repository": repository_id,
                    "source": "commits",
                    "failure_class": "service_error",
                },
            ),
            (
                "fatal",
                {
                    "code": "required_source_failure",
                    "status": "incomplete",
                    "provider": "github",
                    "instance": "github.com",
                    "repository": repository_id,
                    "source": "commits",
                    "failure_class": "service_error",
                },
            ),
        )
        for collection, blocker in additions:
            coverage[collection].append(blocker)
            self.assertTrue(has_blocking_core_coverage(coverage, **options))

    def test_every_truncated_cache_document_fails_closed(self) -> None:
        document = json.dumps(
            {
                "version": 1,
                "entries": {
                    "key": {
                        "stored_at": 1.0,
                        "response": {
                            "url": "https://example.test/items",
                            "status_code": 200,
                            "headers": {},
                            "body": [],
                        },
                    }
                },
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            cache = LocalResponseCache(path, ttl_seconds=60, max_entries=2)
            for length in range(0, len(document), max(1, len(document) // 32)):
                with self.subTest(length=length):
                    path.write_text(document[:length], encoding="utf-8")
                    os.chmod(path, 0o600)
                    self.assertEqual(cache._read(), {"entries": {}})


if __name__ == "__main__":
    unittest.main()
