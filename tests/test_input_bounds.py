from __future__ import annotations

import json
import os
import tempfile
import unittest
from io import BytesIO, StringIO
from pathlib import Path
from typing import Self
from unittest.mock import patch
from urllib.error import HTTPError

from git_evidence.bounds import json_size_with_limit
from git_evidence.collect import _merge_bundles, collect_config
from git_evidence.config import validate_collection_config
from git_evidence.model import BundleLoadError, load_bundle
from git_evidence.providers import GitHubProvider
from git_evidence.providers.base import (
    CollectionRequest,
    ProviderDescriptor,
    RepositoryTarget,
)
from git_evidence.providers.resource_base import BundleBuilder
from git_evidence.providers.transport import (
    ApiError,
    ApiResponse,
    LocalResponseCache,
    MappingTransport,
    ResponseShapeError,
    UrllibTransport,
    paginate,
)
from git_evidence.validation import validate_bundle

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "example_bundle.json"


class FakeHttpResponse:
    def __init__(self, body: bytes, *, headers: dict[str, str] | None = None) -> None:
        self.status = 200
        self.headers = headers or {}
        self.body = body
        self.read_sizes: list[int] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self.body if size < 0 else self.body[:size]


def make_builder() -> tuple[BundleBuilder, RepositoryTarget]:
    target = RepositoryTarget("github", "github.com", "example", "project")
    request = CollectionRequest(
        provider_kind="github",
        instance="github.com",
        repositories=(target,),
        window_start="2026-08-01T00:00:00Z",
        window_end="2026-08-02T00:00:00Z",
        timezone="UTC",
    )
    return (
        BundleBuilder(
            request,
            ProviderDescriptor("github", "GitHub", "REST"),
            MappingTransport({}),
        ),
        target,
    )


class ResponseBoundTests(unittest.TestCase):
    def test_actual_and_declared_response_bytes_are_bounded_while_reading(self) -> None:
        transport = UrllibTransport("https://api.example.test", max_retries=0)
        actual = FakeHttpResponse(b"123456789")
        with (
            patch("git_evidence.providers.transport.MAX_RESPONSE_BYTES", 8),
            patch("git_evidence.providers.transport.urlopen", return_value=actual),
            self.assertRaises(ResponseShapeError) as caught,
        ):
            transport.get("/items")
        self.assertEqual(caught.exception.failure_class, "limit_exceeded")
        self.assertEqual(actual.read_sizes, [9])

        declared = FakeHttpResponse(b"{}", headers={"Content-Length": "9"})
        with (
            patch("git_evidence.providers.transport.MAX_RESPONSE_BYTES", 8),
            patch("git_evidence.providers.transport.urlopen", return_value=declared),
            self.assertRaises(ResponseShapeError) as caught,
        ):
            transport.get("/items")
        self.assertEqual(caught.exception.failure_class, "limit_exceeded")
        self.assertEqual(declared.read_sizes, [])

    def test_compressed_response_is_rejected_and_identity_response_at_limit_passes(
        self,
    ) -> None:
        transport = UrllibTransport("https://api.example.test", max_retries=0)
        compressed = FakeHttpResponse(
            b"compressed", headers={"Content-Encoding": "gzip"}
        )
        with (
            patch("git_evidence.providers.transport.urlopen", return_value=compressed),
            self.assertRaises(ResponseShapeError) as caught,
        ):
            transport.get("/items")
        self.assertEqual(caught.exception.failure_class, "limit_exceeded")
        self.assertEqual(compressed.read_sizes, [])

        body = b'{"x":1}'
        valid = FakeHttpResponse(body, headers={"Content-Length": str(len(body))})
        with (
            patch("git_evidence.providers.transport.MAX_RESPONSE_BYTES", len(body)),
            patch(
                "git_evidence.providers.transport.urlopen", return_value=valid
            ) as opened,
        ):
            response = transport.get("/items")
        self.assertEqual(response.body, {"x": 1})
        self.assertEqual(valid.read_sizes, [len(body) + 1])
        request = opened.call_args.args[0]
        self.assertEqual(request.get_header("Accept-encoding"), "identity")

    def test_json_depth_and_string_size_have_inclusive_valid_boundaries(self) -> None:
        with patch("git_evidence.providers.transport.MAX_JSON_DEPTH", 3):
            self.assertEqual(UrllibTransport._decode_body(b'{"a":[1]}'), {"a": [1]})
            with self.assertRaises(ResponseShapeError) as caught:
                UrllibTransport._decode_body(b"[[[[]]]]")
            self.assertEqual(caught.exception.failure_class, "limit_exceeded")

        with patch("git_evidence.providers.transport.MAX_JSON_STRING_CHARS", 4):
            self.assertEqual(
                UrllibTransport._decode_body(b'{"key":"abcd"}'), {"key": "abcd"}
            )
            for body in (b'{"key":"abcde"}', b'{"abcde":1}'):
                with (
                    self.subTest(body=body),
                    self.assertRaises(ResponseShapeError) as caught,
                ):
                    UrllibTransport._decode_body(body)
                self.assertEqual(caught.exception.failure_class, "limit_exceeded")

    def test_retry_keeps_remote_primary_and_records_later_limit_cause(self) -> None:
        rate_limit = HTTPError(
            "https://api.example.test/items",
            429,
            "rate limited",
            {"Retry-After": "0"},
            BytesIO(b"rate"),
        )
        oversized = FakeHttpResponse(b"123456789")
        transport = UrllibTransport(
            "https://api.example.test",
            max_retries=1,
            retry_backoff=0,
            retry_jitter=0,
            sleep_fn=lambda _: None,
        )
        with (
            patch("git_evidence.providers.transport.MAX_RESPONSE_BYTES", 8),
            patch(
                "git_evidence.providers.transport.urlopen",
                side_effect=[rate_limit, oversized],
            ),
            self.assertRaises(ApiError) as caught,
        ):
            transport.get("/items")
        self.assertEqual(caught.exception.failure_class, "rate_limited")
        self.assertIn("limit_exceeded", caught.exception.failure_classes)


class PageAndEntityBoundTests(unittest.TestCase):
    def test_page_and_paginated_item_limits_keep_valid_siblings_at_boundary(
        self,
    ) -> None:
        page = MappingTransport(
            {
                "/items": ApiResponse(
                    "https://example.test/items?page=1",
                    200,
                    {},
                    [{"id": 1}, {"id": 2}, {"id": 3}],
                )
            }
        )
        with (
            patch("git_evidence.providers.transport.MAX_PAGE_ITEMS", 2),
            self.assertRaises(ResponseShapeError) as caught,
        ):
            paginate(page, "/items", per_page=2)
        self.assertEqual(caught.exception.failure_class, "limit_exceeded")

        valid = MappingTransport(
            {
                "/items": ApiResponse(
                    "https://example.test/items?page=1",
                    200,
                    {},
                    [{"id": 1}, {"id": 2}],
                )
            }
        )
        with patch("git_evidence.providers.transport.MAX_PAGE_ITEMS", 2):
            result = paginate(valid, "/items", per_page=2, max_pages=1)
        self.assertEqual(result.items, [{"id": 1}, {"id": 2}])
        with (
            patch("git_evidence.providers.transport.MAX_PAGE_ITEMS", 2),
            patch("git_evidence.providers.transport.MAX_PAGINATED_ITEMS", 2),
        ):
            exact_total = paginate(valid, "/items", per_page=2, max_pages=1)
        self.assertEqual(len(exact_total.items), 2)

        paginated = MappingTransport(
            {
                "/items": ApiResponse(
                    "https://example.test/items?page=1",
                    200,
                    {"Link": '<https://example.test/items?page=2>; rel="next"'},
                    [{"id": 1}, {"id": 2}],
                ),
                "https://example.test/items?page=2": ApiResponse(
                    "https://example.test/items?page=2",
                    200,
                    {},
                    [{"id": 3}],
                ),
            }
        )
        with (
            patch("git_evidence.providers.transport.MAX_PAGE_ITEMS", 2),
            patch("git_evidence.providers.transport.MAX_PAGINATED_ITEMS", 2),
            self.assertRaises(ResponseShapeError) as caught,
        ):
            paginate(paginated, "/items", per_page=2)
        self.assertEqual(caught.exception.failure_class, "limit_exceeded")

    def test_normalized_entity_and_bundle_size_limits_are_typed(self) -> None:
        builder, target = make_builder()
        with patch("git_evidence.providers.resource_base.MAX_NORMALIZED_ENTITIES", 2):
            builder.add_repository(
                {
                    "id": target.canonical_id,
                    "provider_id": builder.provider_id,
                    "name": "project",
                    "full_name": "example/project",
                },
                target=target,
            )
            with self.assertRaises(ResponseShapeError) as caught:
                builder._add_entity("evidence", {"id": "evidence:overflow"})
        self.assertEqual(caught.exception.failure_class, "limit_exceeded")

        small_builder, _ = make_builder()
        with (
            patch("git_evidence.providers.resource_base.MAX_BUNDLE_BYTES", 100),
            self.assertRaises(ResponseShapeError) as caught,
        ):
            small_builder.finish()
        self.assertEqual(caught.exception.failure_class, "limit_exceeded")

        exact_builder, _ = make_builder()
        exact_builder.bundle["coverage"]["allow_publish"] = False
        exact_size = json_size_with_limit(exact_builder.bundle, max_bytes=1_000_000) + 1
        with patch(
            "git_evidence.providers.resource_base.MAX_BUNDLE_BYTES",
            exact_size,
        ):
            self.assertIs(exact_builder.finish(), exact_builder.bundle)

    def test_limit_failure_becomes_blocking_core_coverage(self) -> None:
        provider = GitHubProvider(MappingTransport({}), instance="github.com")
        with patch("git_evidence.providers.transport.MAX_PAGE_ITEMS", 1):
            result = provider._safe_page(
                "commits",
                lambda: paginate(
                    MappingTransport(
                        {
                            "/items": ApiResponse(
                                "https://example.test/items",
                                200,
                                {},
                                [{"id": 1}, {"id": 2}],
                            )
                        }
                    ),
                    "/items",
                    per_page=1,
                ),
            )
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.diagnostics["failure_class"], "limit_exceeded")
        builder, target = make_builder()
        builder.add_coverage("commits", target, result)
        bundle = builder.finish()
        self.assertFalse(bundle["coverage"]["allow_publish"])
        self.assertTrue(
            any(
                failure["failure_class"] == "limit_exceeded"
                for failure in bundle["coverage"]["fatal"]
                if isinstance(failure, dict)
            )
        )

    def test_collect_config_preserves_typed_provider_limit_failure(self) -> None:
        class OverflowProvider:
            def collect(self, request: CollectionRequest) -> dict[str, object]:
                del request
                raise ResponseShapeError(
                    "provider bundle exceeds limit",
                    failure_class="limit_exceeded",
                )

        config = {
            "window": {
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-02T00:00:00Z",
                "timezone": "UTC",
            },
            "scope": {
                "repositories": [
                    {
                        "provider_ref": "public-github",
                        "owner": "example",
                        "name": "project",
                    }
                ]
            },
            "providers": {
                "public-github": {"kind": "github", "instance": "github.com"}
            },
        }
        bundle = collect_config(
            validate_collection_config(config),
            provider_factory=lambda *args: OverflowProvider(),
        )
        self.assertFalse(bundle["coverage"]["render_eligible"])
        self.assertEqual(
            {
                failure["failure_class"]
                for failure in bundle["coverage"]["group_failures"]
            },
            {"limit_exceeded"},
        )


class AggregateBoundTests(unittest.TestCase):
    def test_aggregate_overflow_returns_a_bounded_typed_diagnostic(self) -> None:
        bundle = load_bundle(FIXTURE)
        prior_failure = {
            "provider": "github",
            "instance": "github.com",
            "repository": bundle["run"]["scope"]["repositories"][0],
            "source": "activities",
            "failure_class": "privacy_violation",
        }
        prior_blocker = {
            **prior_failure,
            "code": "privacy_violation",
            "status": "incomplete",
        }
        bundle["coverage"]["fatal"].append(prior_blocker)
        bundle["coverage"]["group_failures"] = [prior_failure]
        bundle["coverage"]["allow_publish"] = False
        with patch("git_evidence.collect.MAX_BUNDLE_BYTES", 9_000):
            merged = _merge_bundles(
                [bundle],
                window_start=bundle["run"]["window"]["start"],
                window_end=bundle["run"]["window"]["end"],
                timezone=bundle["run"]["window"]["timezone"],
                repository_ids=bundle["run"]["scope"]["repositories"],
                actor_ids=bundle["run"]["scope"]["actors"],
            )
        self.assertEqual(merged["collection"]["failure_class"], "limit_exceeded")
        self.assertFalse(merged["coverage"]["allow_publish"])
        self.assertIn(prior_failure, merged["coverage"]["group_failures"])
        self.assertIn(prior_blocker, merged["coverage"]["fatal"])
        self.assertNotIn(
            "limit_exceeded",
            {
                failure.get("failure_class")
                for failure in merged["coverage"]["group_failures"]
                if isinstance(failure, dict)
            },
        )
        self.assertLessEqual(
            len(json.dumps(merged, ensure_ascii=False, indent=2).encode("utf-8")) + 1,
            9_000,
        )
        codes = {issue.code for issue in validate_bundle(merged)}
        self.assertIn("collection.limit_exceeded", codes)
        self.assertIn("scope.repository_missing", codes)


class ReplayInputBoundTests(unittest.TestCase):
    def test_cache_file_and_replayed_body_cannot_bypass_live_response_limits(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            path.write_bytes(b'{"entries":{}}' + b" " * 32)
            os.chmod(path, 0o600)
            cache = LocalResponseCache(path, ttl_seconds=60, max_entries=2)
            with patch("git_evidence.providers.transport.MAX_CACHE_FILE_BYTES", 16):
                self.assertEqual(cache._read(), {"entries": {}})

            exact_cache = b'{"entries":{}}'
            path.write_bytes(exact_cache)
            os.chmod(path, 0o600)
            with patch(
                "git_evidence.providers.transport.MAX_CACHE_FILE_BYTES",
                len(exact_cache),
            ):
                self.assertEqual(cache._read(), {"entries": {}})

            path.unlink()
            with patch("git_evidence.providers.transport.MAX_RESPONSE_BYTES", 8):
                cache.put(
                    "oversized",
                    ApiResponse("https://example.test/items", 200, {}, "x" * 9),
                    token=None,
                )
            self.assertFalse(path.exists())

            oversized_entry = {
                "version": 1,
                "entries": {
                    "oversized": {
                        "stored_at": 1.0,
                        "response": {
                            "url": "https://example.test/items",
                            "status_code": 200,
                            "headers": {},
                            "body": "x" * 9,
                        },
                    }
                },
            }
            path.write_text(json.dumps(oversized_entry), encoding="utf-8")
            os.chmod(path, 0o600)
            replay = LocalResponseCache(
                path,
                ttl_seconds=60,
                max_entries=2,
                clock=lambda: 2.0,
            )
            with patch("git_evidence.providers.transport.MAX_RESPONSE_BYTES", 8):
                self.assertIsNone(replay.get("oversized"))

    def test_bundle_loader_bounds_stream_bytes_structure_and_entity_count(self) -> None:
        with (
            patch("git_evidence.model.MAX_BUNDLE_BYTES", 8),
            self.assertRaises(BundleLoadError),
        ):
            load_bundle(StringIO('{"value":"long"}'))

        with (
            patch("git_evidence.model.MAX_JSON_DEPTH", 3),
            self.assertRaises(BundleLoadError),
        ):
            load_bundle(StringIO('{"a":{"b":{"c":1}}}'))

        with (
            patch("git_evidence.model.MAX_NORMALIZED_ENTITIES", 1),
            self.assertRaises(BundleLoadError),
        ):
            load_bundle(StringIO('{"providers":[{}],"repositories":[{}]}'))

        with patch("git_evidence.model.MAX_BUNDLE_BYTES", 8):
            self.assertEqual(load_bundle(StringIO('{"é":1}')), {"é": 1})
        with (
            patch("git_evidence.model.MAX_BUNDLE_BYTES", 10),
            self.assertRaises(BundleLoadError),
        ):
            load_bundle(StringIO('{"é":"é"}'))

    def test_decoder_recursion_overflow_is_a_typed_limit_failure(self) -> None:
        body = ("[" * 2_000 + "]" * 2_000).encode("utf-8")
        with self.assertRaises(ResponseShapeError) as caught:
            UrllibTransport._decode_body(body)
        self.assertEqual(caught.exception.failure_class, "limit_exceeded")


if __name__ == "__main__":
    unittest.main()
