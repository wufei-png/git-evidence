from __future__ import annotations

import unittest
from pathlib import Path
from typing import Self
from unittest.mock import patch
from urllib.request import Request

from git_evidence.collect import _merge_bundles
from git_evidence.config import ConfigError, validate_collection_config
from git_evidence.model import load_bundle
from git_evidence.providers import GiteeProvider, GitHubProvider, GitLabProvider
from git_evidence.providers.base import (
    RESOURCE_SOURCES,
    CollectionRequest,
    ProviderDescriptor,
    RepositoryTarget,
)
from git_evidence.providers.resource_base import BundleBuilder, SourceResult
from git_evidence.providers.transport import (
    AllowedApiTarget,
    ApiError,
    ApiResponse,
    MappingTransport,
    ResponseShapeError,
    UrllibTransport,
    _PolicyRedirectHandler,
    paginate,
)
from git_evidence.render import RenderError, render_bundle
from git_evidence.validation import validate_bundle

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "example_bundle.json"


class FakeHttpResponse:
    def __init__(
        self,
        body: bytes,
        *,
        headers: dict[str, str] | None = None,
        status: int = 200,
    ) -> None:
        self.status = status
        self.headers = headers or {}
        self._body = body

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]


def collection_config(
    instance: str,
    *,
    token_env: str | None = None,
    verify_tls: bool = True,
    allow_insecure_loopback: bool = False,
) -> dict[str, object]:
    provider: dict[str, object] = {
        "verify_tls": verify_tls,
        "allow_insecure_loopback": allow_insecure_loopback,
    }
    if token_env is not None:
        provider["token_env"] = token_env
    return {
        "window": {
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-02T00:00:00Z",
            "timezone": "UTC",
        },
        "scope": {
            "repositories": [
                {
                    "provider": "github",
                    "instance": instance,
                    "owner": "example",
                    "name": "project",
                }
            ]
        },
        "providers": {"github": provider},
    }


class RequestTargetPolicyTests(unittest.TestCase):
    def test_absolute_followup_must_stay_in_origin_and_api_prefix(self) -> None:
        transport = UrllibTransport(
            "https://ghe.example/base/api/v3",
            "fixture-token",
        )
        accepted = transport._url(
            "https://ghe.example/base/api/v3/repos/example/project?page=2",
            None,
        )
        self.assertEqual(
            accepted,
            "https://ghe.example/base/api/v3/repos/example/project?page=2",
        )
        rejected = (
            "https://attacker.example/base/api/v3/repos/example/project?page=2",
            "https://127.0.0.1/base/api/v3/repos/example/project?page=2",
            "http://169.254.169.254/latest/meta-data",
            "http://ghe.example/base/api/v3/repos/example/project?page=2",
            "https://ghe.example/api/v3/repos/example/project?page=2",
            "https://ghe.example/base/api/v3/../admin",
            "https://ghe.example/base/api/v3/%252e%252e/admin",
            "https://ghe.example/base/api/v3/%252e%252e%252fadmin",
            "https://ghe.example/base/api/v3/%255cadmin",
            "https://user:password@ghe.example/base/api/v3/repos/example/project",
            "https://ghe.example/base/api/v3/repos/example/project?access_token=foreign",
        )
        for candidate in rejected:
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(ApiError) as caught,
            ):
                transport._url(candidate, None)
            self.assertEqual(caught.exception.failure_class, "request_rejected")
            self.assertNotIn("fixture-token", str(caught.exception))

    def test_query_token_is_never_added_to_rejected_absolute_url(self) -> None:
        transport = UrllibTransport(
            "https://gitee.example/api/v5",
            "fixture-token",
            token_param="access_token",
            max_retries=0,
        )
        with (
            patch("git_evidence.providers.transport.urlopen") as opened,
            self.assertRaises(ApiError),
        ):
            transport.get("https://attacker.example/items?page=2")
        opened.assert_not_called()

    def test_authenticated_and_insecure_transport_preflight(self) -> None:
        with self.assertRaisesRegex(ValueError, "authenticated requests require HTTPS"):
            UrllibTransport(
                "http://127.0.0.1:8080/api",
                "fixture-token",
                allow_insecure_loopback=True,
            )
        with self.assertRaisesRegex(ValueError, "authenticated requests require HTTPS"):
            UrllibTransport(
                "https://api.example.test", "fixture-token", verify_tls=False
            )
        with self.assertRaisesRegex(ValueError, "explicit credentialless loopback"):
            UrllibTransport("http://127.0.0.1:8080/api")
        with self.assertRaisesRegex(ValueError, "explicit credentialless loopback"):
            UrllibTransport(
                "http://internal.example/api",
                allow_insecure_loopback=True,
            )
        loopback = UrllibTransport(
            "http://[::1]:8080/api",
            allow_insecure_loopback=True,
        )
        self.assertEqual(loopback._target_policy.hostname, "::1")
        self.assertEqual(
            loopback._url("/items", None),
            "http://[::1]:8080/api/items",
        )

    def test_config_enforces_same_authenticated_transport_boundary(self) -> None:
        invalid = (
            collection_config(
                "http://127.0.0.1:8080",
                token_env="GITHUB_TOKEN",
                allow_insecure_loopback=True,
            ),
            collection_config(
                "https://ghe.example",
                token_env="GITHUB_TOKEN",
                verify_tls=False,
            ),
            collection_config("http://127.0.0.1:8080"),
            collection_config(
                "http://internal.example",
                allow_insecure_loopback=True,
            ),
        )
        for config in invalid:
            with self.subTest(config=config), self.assertRaises(ConfigError):
                validate_collection_config(config)
        validate_collection_config(
            collection_config(
                "http://127.0.0.1:8080",
                allow_insecure_loopback=True,
            )
        )

    def test_insecure_loopback_bundle_is_diagnostic_and_not_render_eligible(
        self,
    ) -> None:
        transport = UrllibTransport(
            "http://127.0.0.1:8080/api",
            allow_insecure_loopback=True,
        )
        target = RepositoryTarget(
            "github",
            "http://127.0.0.1:8080",
            "example",
            "project",
        )
        request = CollectionRequest(
            provider_kind="github",
            instance="http://127.0.0.1:8080",
            repositories=(target,),
            window_start="2026-08-01T00:00:00Z",
            window_end="2026-08-02T00:00:00Z",
            timezone="UTC",
        )
        builder = BundleBuilder(
            request,
            ProviderDescriptor("github", "GitHub", "REST"),
            transport,
        )
        for source in RESOURCE_SOURCES:
            builder.add_coverage(source, target, SourceResult([], "supported"))
        bundle = builder.finish()
        self.assertFalse(bundle["coverage"]["allow_publish"])
        self.assertEqual(
            bundle["collection"]["group_status"],
            "diagnostic_insecure_transport",
        )
        self.assertTrue(bundle["collection"]["metrics"]["insecure_transport"])
        self.assertTrue(
            all(
                observation["status"] == "incomplete"
                and observation["diagnostics"]["failure_class"] == "insecure_transport"
                for observation in bundle["coverage"]["observations"]
            )
        )

    def test_diagnostic_transport_markers_directly_block_validation_and_rendering(
        self,
    ) -> None:
        for nested in (False, True):
            with self.subTest(nested=nested):
                bundle = load_bundle(FIXTURE)
                diagnostic = {
                    "group_status": "diagnostic_insecure_transport",
                    "metrics": {"insecure_transport": True},
                }
                bundle["collection"] = (
                    {"groups": [diagnostic]} if nested else diagnostic
                )
                bundle["coverage"]["allow_publish"] = True
                self.assertIn(
                    "collection.insecure_transport",
                    {issue.code for issue in validate_bundle(bundle)},
                )
                with self.assertRaises(RenderError):
                    render_bundle(bundle)

    def test_aggregate_preserves_insecure_transport_metric(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["collection"] = {
            "group_status": "diagnostic_insecure_transport",
            "metrics": {"insecure_transport": True},
        }
        # This legacy fixture predates response-level Retrieval provenance;
        # exercise the aggregate metric fold without presenting it as provider output.
        validated = bundle
        self.assertEqual(
            validated["collection"]["group_status"],
            "diagnostic_insecure_transport",
        )
        merged = _merge_bundles(
            [validated],
            window_start=bundle["run"]["window"]["start"],
            window_end=bundle["run"]["window"]["end"],
            timezone=bundle["run"]["window"]["timezone"],
            repository_ids=bundle["run"]["scope"]["repositories"],
            actor_ids=bundle["run"]["scope"]["actors"],
        )
        self.assertTrue(merged["collection"]["metrics"]["insecure_transport"])
        self.assertIn(
            "collection.insecure_transport",
            {issue.code for issue in validate_bundle(merged)},
        )

    def test_redirect_handler_rejects_escape_downgrade_and_cycle(self) -> None:
        policy = AllowedApiTarget.from_base_url("https://api.example.test/v1")
        initial = "https://api.example.test/v1/items?page=1"
        request = Request(initial, headers={"Authorization": "Bearer fixture-token"})
        handler = _PolicyRedirectHandler(policy, initial)
        for target in (
            "https://attacker.example/v1/items?page=2",
            "http://api.example.test/v1/items?page=2",
            "https://api.example.test/admin",
            initial,
        ):
            with self.subTest(target=target), self.assertRaises(ApiError):
                handler.redirect_request(request, None, 302, "Found", {}, target)

        accepted_handler = _PolicyRedirectHandler(policy, initial)
        redirected = accepted_handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://api.example.test/v1/items?page=2",
        )
        self.assertIsNotNone(redirected)
        assert redirected is not None
        self.assertEqual(
            redirected.full_url,
            "https://api.example.test/v1/items?page=2",
        )
        self.assertEqual(redirected.get_header("Authorization"), "Bearer fixture-token")

    def test_redirect_handler_reapplies_only_its_own_query_token(self) -> None:
        policy = AllowedApiTarget.from_base_url(
            "https://api.example.test/v1",
            credential_query_names=("access_token",),
        )
        initial = "https://api.example.test/v1/items?page=1&access_token=fixture-token"
        handler = _PolicyRedirectHandler(
            policy,
            initial,
            token_param="access_token",
            token="fixture-token",
        )
        redirected = handler.redirect_request(
            Request(initial),
            None,
            302,
            "Found",
            {},
            "https://api.example.test/v1/items?page=2",
        )
        self.assertIsNotNone(redirected)
        assert redirected is not None
        self.assertEqual(
            redirected.full_url,
            "https://api.example.test/v1/items?page=2&access_token=fixture-token",
        )
        with self.assertRaises(ApiError):
            handler.redirect_request(
                Request(initial),
                None,
                302,
                "Found",
                {},
                "https://api.example.test/v1/items?page=3&access_token=foreign",
            )

    def test_live_transport_rejects_external_link_before_second_request(self) -> None:
        transport = UrllibTransport(
            "https://api.example.test/v1",
            "fixture-token",
            max_retries=0,
        )
        first = FakeHttpResponse(
            b'[{"id": 1}]',
            headers={"Link": '<https://attacker.example/items?page=2>; rel="next"'},
        )
        with (
            patch(
                "git_evidence.providers.transport.urlopen",
                side_effect=[first],
            ) as opened,
            self.assertRaises(ApiError) as caught,
        ):
            paginate(transport, "/items", per_page=1)
        self.assertEqual(caught.exception.failure_class, "request_rejected")
        self.assertEqual(opened.call_count, 1)

    def test_provider_auth_styles_follow_only_their_actual_api_boundary(self) -> None:
        cases = (
            (
                GitHubProvider(token="fixture-token"),
                "https://api.github.com",
                "Authorization",
            ),
            (
                GitLabProvider(token="fixture-token"),
                "https://gitlab.com/api/v4",
                "Private-token",
            ),
            (GiteeProvider(token="fixture-token"), "https://gitee.com/api/v5", None),
        )
        for provider, api_base, header_name in cases:
            with self.subTest(provider=provider.descriptor.kind):
                responses = [
                    FakeHttpResponse(
                        b'[{"id": 1}]',
                        headers={"Link": f'<{api_base}/items?page=2>; rel="next"'},
                    ),
                    FakeHttpResponse(b"[]"),
                ]
                with patch(
                    "git_evidence.providers.transport.urlopen",
                    side_effect=responses,
                ) as opened:
                    result = paginate(provider.transport, "/items", per_page=1)
                self.assertEqual(result.items, [{"id": 1}])
                self.assertEqual(opened.call_count, 2)
                for call in opened.call_args_list:
                    request = call.args[0]
                    self.assertTrue(request.full_url.startswith(f"{api_base}/"))
                    headers = dict(request.header_items())
                    if header_name is None:
                        self.assertIn("access_token=fixture-token", request.full_url)
                        self.assertNotIn("Authorization", headers)
                        self.assertNotIn("Private-token", headers)
                    else:
                        self.assertIn(header_name, headers)
                        self.assertNotIn("access_token=fixture-token", request.full_url)


class PaginationProgressTests(unittest.TestCase):
    def test_link_cycle_and_page_regression_are_rejected(self) -> None:
        cycle = MappingTransport(
            {
                "/items": ApiResponse(
                    "https://example.test/items?page=1",
                    200,
                    {"Link": '<https://example.test/items?page=1>; rel="next"'},
                    [{"id": 1}],
                )
            }
        )
        with self.assertRaises(ResponseShapeError) as cycle_error:
            paginate(cycle, "/items", per_page=1)
        self.assertEqual(cycle_error.exception.pagination_outcome, "cycle_detected")

        regression = MappingTransport(
            {
                "/items": ApiResponse(
                    "https://example.test/items?page=2",
                    200,
                    {"X-Next-Page": "1"},
                    [{"id": 1}],
                )
            }
        )
        with self.assertRaises(ResponseShapeError):
            paginate(regression, "/items", {"page": 2}, per_page=1)

    def test_two_target_link_cycle_is_rejected(self) -> None:
        transport = MappingTransport(
            {
                "/items": ApiResponse(
                    "https://example.test/items?page=1",
                    200,
                    {"Link": '<https://example.test/items?page=2>; rel="next"'},
                    [{"id": 1}],
                ),
                "https://example.test/items?page=2": ApiResponse(
                    "https://example.test/items?page=2",
                    200,
                    {"Link": '<https://example.test/items?page=1>; rel="next"'},
                    [{"id": 2}],
                ),
            }
        )
        with self.assertRaises(ResponseShapeError) as cycle_error:
            paginate(transport, "/items", per_page=1)
        self.assertEqual(cycle_error.exception.pagination_outcome, "cycle_detected")

    def test_opaque_cursor_cycle_is_rejected(self) -> None:
        transport = MappingTransport(
            {
                "/items": ApiResponse(
                    "https://example.test/items?cursor=start",
                    200,
                    {"Link": '<https://example.test/items?cursor=opaque>; rel="next"'},
                    [{"id": 1}],
                ),
                "https://example.test/items?cursor=opaque": ApiResponse(
                    "https://example.test/items?cursor=opaque",
                    200,
                    {"Link": '<https://example.test/items?cursor=opaque>; rel="next"'},
                    [{"id": 2}],
                ),
            }
        )
        with self.assertRaises(ResponseShapeError) as cycle_error:
            paginate(transport, "/items", per_page=1)
        self.assertEqual(cycle_error.exception.pagination_outcome, "cycle_detected")


if __name__ == "__main__":
    unittest.main()
