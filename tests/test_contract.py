from __future__ import annotations

from io import BytesIO
import json
import sys
import unittest
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from git_evidence.model import load_bundle  # noqa: E402
from git_evidence.collect import collect_config  # noqa: E402
from git_evidence.config import ConfigError, load_config  # noqa: E402
from git_evidence.providers import (  # noqa: E402
    CollectionRequest,
    GiteeProvider,
    GitHubProvider,
    GitLabProvider,
    RepositoryTarget,
    provider_catalog,
)
from git_evidence.providers.transport import (  # noqa: E402
    ApiError,
    ApiResponse,
    MappingTransport,
    ResponseShapeError,
    UrllibTransport,
    failure_class_for_status,
    paginate,
)
from git_evidence.providers.resource_base import (  # noqa: E402
    api_error_diagnostics,
    merge_diagnostics,
)
from git_evidence.render import render_bundle  # noqa: E402
from git_evidence.validation import validate_bundle  # noqa: E402


FIXTURE = ROOT / "fixtures" / "example_bundle.json"
WINDOW_START = "2026-07-27T00:00:00Z"
WINDOW_END = "2026-08-03T00:00:00Z"
EVENT_TIME = "2026-07-30T12:00:00Z"


def response(path: str, body: object, headers: dict[str, str] | None = None) -> ApiResponse:
    return ApiResponse(path, 200, headers or {}, body)


def provider_fixture(name: str) -> dict[str, object]:
    path = ROOT / "fixtures" / "provider_contract" / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


class FakeHttpResponse:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.status = 200
        self.headers = headers or {}
        self._body = body

    def __enter__(self) -> "FakeHttpResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def request_for(provider: str, instance: str, *, include_activity_api: bool = False) -> CollectionRequest:
    target = RepositoryTarget(provider, instance, "example", "project")
    return CollectionRequest(
        provider_kind=provider,
        instance=instance,
        repositories=(target,),
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        timezone="UTC",
        include_activity_api=include_activity_api,
    )


def github_transport() -> MappingTransport:
    root = "/repos/example/project"
    fixture = provider_fixture("github")
    return MappingTransport(
        {
            root: response("", fixture["repository"]),
            f"{root}/issues": response("", fixture["issues"]),
            f"{root}/pulls": response("", fixture["pulls"]),
            f"{root}/issues/1/comments": response("", fixture["issue_comments"]["1"]),
            f"{root}/issues/2/comments": response("", fixture["issue_comments"]["2"]),
            f"{root}/issues/3/comments": response("", fixture["issue_comments"]["3"]),
            f"{root}/pulls/2/reviews": response("", fixture["reviews"]["2"]),
            f"{root}/pulls/3/reviews": response("", fixture["reviews"]["3"]),
            f"{root}/pulls/2/comments": response("", fixture["review_comments"]["2"]),
            f"{root}/pulls/3/comments": response("", fixture["review_comments"]["3"]),
            f"{root}/commits": response("", fixture["commits"]),
            f"{root}/commits/abc123/pulls": response("", fixture["commit_pulls"]["abc123"]),
            f"{root}/commits/def456/pulls": response("", fixture["commit_pulls"]["def456"]),
            f"{root}/commits/multi123/pulls": response("", fixture["commit_pulls"]["multi123"]),
            f"{root}/releases": response("", fixture["releases"]),
            f"{root}/events": response("", fixture["events"]),
        }
    )


def gitlab_transport() -> MappingTransport:
    root = "/projects/example%2Fproject"
    fixture = provider_fixture("gitlab")
    return MappingTransport(
        {
            root: response("", fixture["repository"]),
            f"{root}/issues": response("", fixture["issues"]),
            f"{root}/merge_requests": response("", fixture["merge_requests"]),
            f"{root}/issues/1/notes": response("", fixture["issue_notes"]["1"]),
            f"{root}/merge_requests/2/notes": response("", fixture["merge_request_notes"]["2"]),
            f"{root}/repository/commits": response("", fixture["commits"]),
            f"{root}/repository/commits/abc123/merge_requests": response("", fixture["commit_merge_requests"]["abc123"]),
            f"{root}/releases": response("", fixture["releases"]),
            f"{root}/events": response("", fixture["events"]),
        }
    )


def gitee_transport() -> MappingTransport:
    root = "/repos/example/project"
    fixture = provider_fixture("gitee")
    return MappingTransport(
        {
            root: response("", fixture["repository"]),
            f"{root}/issues": response("", fixture["issues"]),
            f"{root}/pulls": response("", fixture["pulls"]),
            f"{root}/issues/1/comments": response("", fixture["issue_comments"]["1"]),
            f"{root}/issues/2/comments": response("", fixture["issue_comments"]["2"]),
            f"{root}/commits": response("", fixture["commits"]),
            f"{root}/releases": response("", fixture["releases"]),
        }
    )


class ContractTests(unittest.TestCase):
    def test_public_fixture_is_publishable(self) -> None:
        bundle = load_bundle(FIXTURE)
        self.assertEqual(validate_bundle(bundle), [])

    def test_missing_fact_evidence_is_fatal(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["facts"][0]["evidence_ids"] = []
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("fact.evidence", codes)

    def test_ref_change_commit_reference_must_resolve(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["ref_changes"][0]["commit_ids"] = ["commit:missing"]
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("ref_change.commit_ref", codes)

    def test_required_source_failure_blocks_publication(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["coverage"]["observations"][0]["status"] = "incomplete"
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("coverage.required_incomplete", codes)
        with self.assertRaises(ValueError):
            render_bundle(bundle)

    def test_coverage_is_required_for_each_allowlisted_repository(self) -> None:
        bundle = load_bundle(FIXTURE)
        second_repository = "repo:github:github.com:example/second-project"
        bundle["run"]["scope"]["repositories"].append(second_repository)
        bundle["repositories"].append(
            {
                "id": second_repository,
                "provider_id": "provider:github:github.com",
                "full_name": "example/second-project",
                "web_url": "https://github.com/example/second-project",
            }
        )
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("coverage.required_missing", codes)

    def test_entity_outside_allowlist_is_rejected(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["facts"].append(
            {
                "id": "fact:outside",
                "kind": "commit_observed",
                "repository_id": "repo:github:github.com:other/project",
                "summary": "outside",
                "evidence_ids": ["evidence:commit:a"],
            }
        )
        codes = {issue.code for issue in validate_bundle(bundle)}
        self.assertIn("scope.entity_outside", codes)

    def test_profiles_render_offline(self) -> None:
        bundle = load_bundle(FIXTURE)
        for profile in ("project-first", "timeline", "release-focused", "actor-summary"):
            report = render_bundle(bundle, profile=profile)
            self.assertIn("Engineering Activity Report", report)
            self.assertIn("github.com/example/project", report)
        release_report = render_bundle(bundle, profile="release-focused")
        self.assertEqual(release_report.count("## Releases and changes"), 1)
        self.assertIn("anonymous actor", render_bundle(bundle, profile="actor-summary"))

    def test_provider_catalog_exposes_three_contracts(self) -> None:
        self.assertEqual([item.kind for item in provider_catalog()], ["gitee", "github", "gitlab"])
        for descriptor in provider_catalog():
            self.assertIn("repositories", descriptor.resource_sources)
            self.assertIn("ref_changes", descriptor.activity_sources)
            self.assertEqual(descriptor.implementation_status, "experimental")

    def test_resource_collectors_replay_shared_minimum_contract(self) -> None:
        providers = (
            ("github", "github.com", GitHubProvider(github_transport())),
            ("gitlab", "gitlab.com", GitLabProvider(gitlab_transport())),
            ("gitee", "gitee.com", GiteeProvider(gitee_transport())),
        )
        for kind, instance, provider in providers:
            with self.subTest(provider=kind):
                self.assertEqual(provider.probe()["kind"], kind)
                self.assertEqual(provider.probe()["instance"], instance)
                bundle = provider.collect(request_for(kind, instance))
                self.assertEqual(validate_bundle(bundle), [])
                self.assertEqual(bundle["coverage"]["allow_publish"], True)
                self.assertEqual(len(bundle["repositories"]), 1)
                self.assertGreaterEqual(len(bundle["facts"]), 5)
                self.assertGreaterEqual(len(bundle["interactions"]), 1)
                self.assertEqual(
                    {item["source"] for item in bundle["coverage"]["observations"] if item["source"] in {"activities", "ref_changes"}},
                    {"activities", "ref_changes"},
                )
                self.assertTrue(all(item["status"] == "unavailable" for item in bundle["coverage"]["observations"] if item["source"] in {"activities", "ref_changes"}))

    def test_gitee_pull_request_query_uses_supported_parameters(self) -> None:
        transport = gitee_transport()
        bundle = GiteeProvider(transport).collect(request_for("gitee", "gitee.com"))
        self.assertEqual(validate_bundle(bundle), [])
        pull_calls = [
            params
            for path, params in transport.calls
            if path == "/repos/example/project/pulls"
        ]
        self.assertTrue(pull_calls)
        self.assertNotIn("sort", dict(pull_calls[0]))
        self.assertNotIn("direction", dict(pull_calls[0]))

    def test_provider_coverage_preserves_rate_limit_diagnostics_from_nested_requests(self) -> None:
        transport = github_transport()
        path = "/repos/example/project/issues/1/comments"
        recorded = transport.responses[path][0]
        transport.responses[path] = [
            ApiResponse(
                recorded.url,
                recorded.status_code,
                {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "123"},
                recorded.body,
            )
        ]
        bundle = GitHubProvider(transport).collect(request_for("github", "github.com"))
        interaction_coverage = [
            item
            for item in bundle["coverage"]["observations"]
            if item["source"] == "interactions"
        ]
        self.assertEqual(len(interaction_coverage), 1)
        self.assertEqual(
            interaction_coverage[0]["diagnostics"],
            {"rate_limit": {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "123"}},
        )

    def test_optional_activity_produces_explicit_ref_evidence_and_conservative_association(self) -> None:
        github_bundle = GitHubProvider(github_transport()).collect(
            request_for("github", "github.com", include_activity_api=True)
        )
        self.assertEqual(validate_bundle(github_bundle), [])
        github_ref = github_bundle["ref_changes"][0]
        self.assertEqual(github_ref["change_association"], "linked")
        self.assertEqual(
            github_ref["change_request_ids"],
            ["change_request:github:github.com:example/project:2"],
        )
        self.assertEqual(
            github_ref["commit_ids"],
            ["commit:github:github.com:example/project:abc123"],
        )
        self.assertEqual(
            {item["change_association"] for item in github_bundle["ref_changes"]},
            {"linked", "unlinked", "ambiguous"},
        )
        ambiguous_ref = next(
            item for item in github_bundle["ref_changes"] if item["change_association"] == "ambiguous"
        )
        self.assertEqual(
            ambiguous_ref["change_request_ids"],
            [
                "change_request:github:github.com:example/project:2",
                "change_request:github:github.com:example/project:3",
            ],
        )
        self.assertEqual(
            {item["status"] for item in github_bundle["coverage"]["observations"] if item["source"] == "ref_changes"},
            {"incomplete"},
        )

        gitlab_activity_transport = gitlab_transport()
        gitlab_bundle = GitLabProvider(gitlab_activity_transport).collect(
            request_for("gitlab", "gitlab.com", include_activity_api=True)
        )
        self.assertEqual(validate_bundle(gitlab_bundle), [])
        event_calls = [
            params
            for path, params in gitlab_activity_transport.calls
            if path == "/projects/example%2Fproject/events"
        ]
        self.assertTrue(event_calls)
        self.assertEqual(dict(event_calls[0])["after"], "2026-07-26")
        self.assertEqual(dict(event_calls[0])["before"], "2026-08-03")
        self.assertEqual(gitlab_bundle["ref_changes"][0]["change_association"], "linked")
        self.assertEqual(
            gitlab_bundle["ref_changes"][0]["change_request_ids"],
            ["change_request:gitlab:gitlab.com:example/project:2"],
        )
        self.assertTrue(any(item.get("ref") is None for item in gitlab_bundle["ref_changes"]))
        self.assertTrue(
            any(
                "bulk" in item.get("note", "")
                for item in gitlab_bundle["coverage"]["observations"]
                if item["source"] == "ref_changes"
            )
        )

        gitee_bundle = GiteeProvider(gitee_transport()).collect(
            request_for("gitee", "gitee.com", include_activity_api=True)
        )
        self.assertEqual(validate_bundle(gitee_bundle), [])
        self.assertEqual(gitee_bundle["ref_changes"], [])
        self.assertTrue(
            all(
                item["status"] == "unsupported"
                for item in gitee_bundle["coverage"]["observations"]
                if item["source"] in {"activities", "ref_changes"}
            )
        )

    def test_association_api_failure_keeps_ref_unknown_and_exposes_diagnostic(self) -> None:
        transport = github_transport()
        transport.responses.pop("/repos/example/project/commits/abc123/pulls")
        bundle = GitHubProvider(transport).collect(
            request_for("github", "github.com", include_activity_api=True)
        )
        self.assertEqual(validate_bundle(bundle), [])
        self.assertEqual(bundle["ref_changes"][0]["change_association"], "unknown")
        ref_coverage = next(
            item
            for item in bundle["coverage"]["observations"]
            if item["source"] == "ref_changes"
        )
        self.assertEqual(
            ref_coverage["diagnostics"]["commit_association"]["failure_classes"],
            ["fixture_missing"],
        )

    def test_collect_config_aggregates_multiple_provider_groups(self) -> None:
        transports = {
            "github": github_transport(),
            "gitlab": gitlab_transport(),
        }

        def factory(kind: str, instance: str, options: dict[str, object], token: str | None) -> object:
            if kind == "github":
                return GitHubProvider(transports[kind], instance=instance)
            return GitLabProvider(transports[kind], instance=instance)

        config = {
            "window": {"start": WINDOW_START, "end": WINDOW_END, "timezone": "UTC"},
            "scope": {
                "repositories": [
                    {"provider": "github", "instance": "github.com", "owner": "example", "name": "project"},
                    {"provider": "gitlab", "instance": "gitlab.com", "owner": "example", "name": "project"},
                ]
            },
            "providers": {"github": {}, "gitlab": {}},
        }
        bundle = collect_config(config, provider_factory=factory)
        self.assertEqual(validate_bundle(bundle), [])
        self.assertEqual(len(bundle["providers"]), 2)
        self.assertEqual(len(bundle["repositories"]), 2)
        self.assertEqual(
            bundle["run"]["scope"]["repositories"],
            [
                "repo:github:github.com:example/project",
                "repo:gitlab:gitlab.com:example/project",
            ],
        )

    def test_pagination_does_not_call_a_full_page_complete(self) -> None:
        transport = MappingTransport({"/items": response("", [{"id": index} for index in range(100)])})
        result = paginate(transport, "/items", {}, per_page=100, max_pages=1)
        self.assertFalse(result.complete)
        self.assertEqual(result.pages, 1)
        self.assertEqual(len(result.items), 100)

    def test_query_token_is_redacted_from_transport_urls(self) -> None:
        fixture_token = "fixture" + "-token"
        transport = UrllibTransport(
            "https://api.example.test/v5",
            fixture_token,
            token_param="access_token",
        )
        url = transport._url("/repos/example/project", {"page": 1})
        self.assertIn("access_token=" + fixture_token, url)
        self.assertNotIn(fixture_token, transport._redact_url(url))
        self.assertIn("access_token=%5BREDACTED%5D", transport._redact_url(url))

    def test_transport_retries_rate_limit_and_reports_safe_response(self) -> None:
        fixture_token = "fixture" + "-token"
        retry_error = HTTPError(
            "https://api.example.test/repos/example/project?access_token=" + fixture_token,
            429,
            "Too Many Requests",
            {"Retry-After": "0"},
            BytesIO((fixture_token + " was rate limited").encode()),
        )
        transport = UrllibTransport(
            "https://api.example.test",
            fixture_token,
            token_param="access_token",
            max_retries=1,
            retry_backoff=0,
        )
        with patch(
            "git_evidence.providers.transport.urlopen",
            side_effect=[retry_error, FakeHttpResponse(b'{"ok": true}', {"X-RateLimit-Remaining": "3"})],
        ) as urlopen:
            result = transport.get("/repos/example/project")
        self.assertEqual(urlopen.call_count, 2)
        self.assertNotIn(fixture_token, result.url)
        self.assertEqual(result.body, {"ok": True})

    def test_transport_terminal_statuses_preserve_failure_class(self) -> None:
        cases = (
            (401, "permission_denied"),
            (403, "permission_denied"),
            (429, "rate_limited"),
            (500, "service_error"),
            (503, "service_error"),
        )
        for status_code, expected_class in cases:
            with self.subTest(status_code=status_code):
                error = HTTPError(
                    "https://api.example.test/repos/example/project",
                    status_code,
                    "failure",
                    {},
                    BytesIO(b"provider failure"),
                )
                transport = UrllibTransport(
                    "https://api.example.test",
                    max_retries=0,
                    retry_backoff=0,
                )
                with patch(
                    "git_evidence.providers.transport.urlopen",
                    side_effect=[error],
                ):
                    with self.assertRaises(ApiError) as caught:
                        transport.get("/repos/example/project")
                self.assertEqual(caught.exception.failure_class, expected_class)
                self.assertEqual(
                    api_error_diagnostics(caught.exception)["failure_class"],
                    expected_class,
                )
                self.assertEqual(caught.exception.status_code, status_code)

    def test_failure_classes_distinguish_operational_causes(self) -> None:
        self.assertEqual(failure_class_for_status(401), "permission_denied")
        self.assertEqual(failure_class_for_status(403), "permission_denied")
        self.assertEqual(failure_class_for_status(429), "rate_limited")
        self.assertEqual(failure_class_for_status(503), "service_error")
        self.assertEqual(
            api_error_diagnostics(ApiError("forbidden", 403)),
            {
                "attempts": 1,
                "retryable": False,
                "failure_class": "permission_denied",
                "status_code": 403,
            },
        )
        self.assertEqual(
            api_error_diagnostics(ResponseShapeError("bad shape"))["failure_class"],
            "malformed_response",
        )

    def test_aggregated_diagnostics_preserve_multiple_failure_classes(self) -> None:
        diagnostics: dict[str, object] = {}
        merge_diagnostics(diagnostics, {"failure_class": "permission_denied", "status_code": 403})
        self.assertEqual(diagnostics["failure_class"], "permission_denied")
        merge_diagnostics(diagnostics, {"failure_class": "rate_limited", "status_code": 429})
        self.assertNotIn("failure_class", diagnostics)
        self.assertEqual(
            diagnostics["failure_classes"],
            ["permission_denied", "rate_limited"],
        )

    def test_pagination_preserves_rate_limit_diagnostics(self) -> None:
        transport = MappingTransport(
            {
                "/items": response(
                    "",
                    [{"id": 1}],
                    {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "123"},
                )
            }
        )
        result = paginate(transport, "/items", {}, per_page=100)
        self.assertEqual(
            result.diagnostics,
            {"rate_limit": {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "123"}},
        )

    def test_config_requires_explicit_allowlist_and_aware_window(self) -> None:
        config = load_config(ROOT / "config.example.yml")
        self.assertEqual(config["scope"]["repositories"][0]["provider"], "github")
        bad = dict(config)
        bad["scope"] = {"repositories": []}
        temporary = ROOT / "tests" / ".tmp-invalid-config.yml"
        try:
            temporary.write_text(
                "window:\n"
                "  start: 2026-07-27T00:00:00Z\n"
                "  end: 2026-08-03T00:00:00Z\n"
                "  timezone: UTC\n"
                "scope:\n"
                "  repositories: []\n"
                "providers: {}\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(temporary)
        finally:
            temporary.unlink(missing_ok=True)

    def test_config_rejects_unknown_provider(self) -> None:
        temporary = ROOT / "tests" / ".tmp-unknown-provider.yml"
        try:
            temporary.write_text(
                "window:\n"
                "  start: 2026-07-27T00:00:00Z\n"
                "  end: 2026-08-03T00:00:00Z\n"
                "  timezone: UTC\n"
                "scope:\n"
                "  repositories:\n"
                "    - provider: unknown\n"
                "      instance: example.invalid\n"
                "      owner: example\n"
                "      name: project\n"
                "providers:\n"
                "  unknown: {}\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(temporary)
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
