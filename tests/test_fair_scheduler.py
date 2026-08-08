from __future__ import annotations

import unittest
from collections.abc import Mapping
from typing import Any

from test_contract import (
    WINDOW_END,
    WINDOW_START,
    gitee_transport,
    github_transport,
    gitlab_transport,
    request_for,
)

from git_evidence.providers.base import CollectionRequest, RepositoryTarget
from git_evidence.providers.gitee import GiteeProvider
from git_evidence.providers.github import GitHubProvider
from git_evidence.providers.gitlab import GitLabProvider
from git_evidence.providers.transport import ApiError, ApiResponse, MappingTransport


def response(url: str, body: Any) -> ApiResponse:
    return ApiResponse(url, 200, {}, body)


def two_repository_request(
    *,
    reverse: bool = False,
    include_activity_api: bool = False,
    max_requests: int = 1000,
) -> CollectionRequest:
    targets = [
        RepositoryTarget("github", "github.com", "a", "large"),
        RepositoryTarget("github", "github.com", "z", "small"),
    ]
    if reverse:
        targets.reverse()
    return CollectionRequest(
        provider_kind="github",
        instance="github.com",
        repositories=tuple(targets),
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        timezone="UTC",
        include_activity_api=include_activity_api,
        max_requests=max_requests,
    )


def fair_transport(*, with_issues: bool = False) -> MappingTransport:
    responses: dict[str, ApiResponse | list[ApiResponse]] = {}
    for owner, name in (("a", "large"), ("z", "small")):
        root = f"/repos/{owner}/{name}"
        responses[root] = response(
            f"https://api.github.com{root}",
            {
                "full_name": f"{owner}/{name}",
                "name": name,
                "html_url": f"https://github.com/{owner}/{name}",
            },
        )
        issue_body = []
        if with_issues:
            issue_body = [
                {
                    "id": 1,
                    "number": 1,
                    "title": f"{name} issue",
                    "state": "open",
                    "updated_at": "2026-07-28T00:00:00Z",
                }
            ]
        responses[f"{root}/issues"] = response(
            f"https://api.github.com{root}/issues?page=1", issue_body
        )
        responses[f"{root}/pulls"] = response(
            f"https://api.github.com{root}/pulls?page=1", []
        )
        responses[f"{root}/commits"] = response(
            f"https://api.github.com{root}/commits?page=1", []
        )
        responses[f"{root}/releases"] = response(
            f"https://api.github.com{root}/releases?page=1", []
        )
        responses[f"{root}/events"] = response(
            f"https://api.github.com{root}/events?page=1", []
        )
        if with_issues:
            responses[f"{root}/issues/1/comments"] = response(
                f"https://api.github.com{root}/issues/1/comments?page=1", []
            )
    return MappingTransport(responses)


def large_first_page_transport() -> MappingTransport:
    transport = fair_transport()
    path = "/repos/a/large/issues"
    full_out_of_window_page = [
        {
            "id": index,
            "number": index,
            "title": f"issue {index}",
            "state": "open",
            "updated_at": (
                "2026-07-28T00:00:00Z"
                if index == 1
                else "2020-01-01T00:00:00Z"
            ),
        }
        for index in range(1, 101)
    ]
    transport.responses[path] = [
        response(f"https://api.github.com{path}?page=1", full_out_of_window_page),
        response(f"https://api.github.com{path}?page=2", []),
    ]
    comment_path = "/repos/a/large/issues/1/comments"
    transport.responses[comment_path] = [
        response(f"https://api.github.com{comment_path}?page=1", [])
    ]
    return transport


class BudgetTransport(MappingTransport):
    def __init__(
        self,
        responses: Mapping[str, list[ApiResponse] | ApiResponse],
        *,
        max_requests: int,
    ) -> None:
        super().__init__(responses)
        self.max_requests = max_requests

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> ApiResponse:
        if self._metrics.request_count >= self.max_requests:
            self.calls.append((path, params))
            self._metrics.budget_exhausted = True
            raise ApiError(
                "request budget exhausted",
                attempts=1,
                retryable=False,
                failure_class="budget_exhausted",
            )
        return super().get(path, params)


class FairSchedulerTests(unittest.TestCase):
    def test_large_repository_page_two_waits_for_every_first_core_page(self) -> None:
        transport = large_first_page_transport()
        GitHubProvider(transport).collect(two_repository_request())

        paths = [path for path, _ in transport.calls]
        expected_first_round = [
            "/repos/a/large",
            "/repos/z/small",
            "/repos/a/large/issues",
            "/repos/a/large/pulls",
            "/repos/a/large/commits",
            "/repos/a/large/releases",
            "/repos/z/small/issues",
            "/repos/z/small/pulls",
            "/repos/z/small/commits",
            "/repos/z/small/releases",
        ]
        self.assertEqual(paths[:10], expected_first_round)
        self.assertEqual(paths[10], "/repos/a/large/issues")

    def test_repository_permutation_has_identical_schedule(self) -> None:
        first = large_first_page_transport()
        second = large_first_page_transport()
        GitHubProvider(first).collect(two_repository_request())
        GitHubProvider(second).collect(two_repository_request(reverse=True))
        self.assertEqual(first.calls, second.calls)

    def test_interactions_are_fair_and_optional_runs_last(self) -> None:
        transport = fair_transport(with_issues=True)
        GitHubProvider(transport).collect(
            two_repository_request(include_activity_api=True)
        )

        paths = [path for path, _ in transport.calls]
        first_comment = paths.index("/repos/a/large/issues/1/comments")
        second_comment = paths.index("/repos/z/small/issues/1/comments")
        first_optional = min(
            paths.index("/repos/a/large/events"),
            paths.index("/repos/z/small/events"),
        )
        self.assertLess(first_comment, second_comment)
        self.assertLess(second_comment, first_optional)

    def test_runtime_budget_exhaustion_is_scoped_to_unfinished_source(self) -> None:
        recorded = large_first_page_transport()
        transport = BudgetTransport(recorded.responses, max_requests=10)
        bundle = GitHubProvider(transport).collect(
            two_repository_request(max_requests=10)
        )

        observations = {
            (item["repository_id"], item["source"]): item
            for item in bundle["coverage"]["observations"]
        }
        large = "repo:github:github.com:a/large"
        small = "repo:github:github.com:z/small"
        self.assertEqual(observations[(large, "work_items")]["status"], "incomplete")
        self.assertEqual(
            observations[(large, "work_items")]["diagnostics"]["failure_class"],
            "budget_exhausted",
        )
        self.assertEqual(observations[(small, "work_items")]["status"], "supported")
        self.assertEqual(len(bundle["work_items"]), 1)
        self.assertFalse(bundle["coverage"]["allow_publish"])

    def test_incomplete_parent_makes_interactions_incomplete(self) -> None:
        cases = (
            (
                "github",
                "github.com",
                GitHubProvider,
                github_transport,
                "/repos/example/project/issues",
            ),
            (
                "gitlab",
                "gitlab.com",
                GitLabProvider,
                gitlab_transport,
                "/projects/example%2Fproject/issues",
            ),
            (
                "gitee",
                "gitee.com",
                GiteeProvider,
                gitee_transport,
                "/repos/example/project/issues",
            ),
        )
        for (
            provider_kind,
            instance,
            provider_type,
            transport_factory,
            issue_path,
        ) in cases:
            with self.subTest(provider=provider_kind):
                transport = transport_factory()
                transport.responses.pop(issue_path)
                bundle = provider_type(transport).collect(
                    request_for(provider_kind, instance)
                )
                interactions = next(
                    item
                    for item in bundle["coverage"]["observations"]
                    if item["source"] == "interactions"
                )
                self.assertEqual(interactions["status"], "incomplete")
                self.assertEqual(
                    interactions["diagnostics"]["dependency"]["failure_class"],
                    "fixture_missing",
                )


if __name__ == "__main__":
    unittest.main()
