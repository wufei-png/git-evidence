from __future__ import annotations

import unittest

from git_evidence.collect import collect_config
from git_evidence.config import (
    PlanBudgetInfeasibleConfigError,
    validate_collection_config,
)
from git_evidence.providers.base import CollectionRequest, RepositoryTarget


def config_for(
    repositories: list[dict[str, str]],
    *,
    max_requests: int,
) -> dict[str, object]:
    return {
        "window": {
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-02T00:00:00Z",
            "timezone": "UTC",
        },
        "scope": {"repositories": repositories},
        "providers": {"github": {"max_requests": max_requests}},
    }


def repository(owner: str, name: str, *, instance: str = "github.com") -> dict[str, str]:
    return {
        "provider": "github",
        "instance": instance,
        "owner": owner,
        "name": name,
    }


class FairPreflightTests(unittest.TestCase):
    def test_infeasible_group_is_typed_and_fails_before_provider_creation(self) -> None:
        config = config_for(
            [repository("zeta", "project"), repository("alpha", "project")],
            max_requests=9,
        )
        with self.assertRaises(PlanBudgetInfeasibleConfigError) as caught:
            validate_collection_config(config)
        self.assertEqual(caught.exception.code, "plan_budget_infeasible")
        self.assertIn("minimum is 10", str(caught.exception))

        called = False

        def factory(*args: object) -> object:
            nonlocal called
            called = True
            return object()

        with self.assertRaises(PlanBudgetInfeasibleConfigError):
            collect_config(config, provider_factory=factory)
        self.assertFalse(called)

    def test_budget_is_scoped_per_provider_instance_group(self) -> None:
        config = config_for(
            [
                repository("alpha", "project", instance="ghe-a.example"),
                repository("beta", "project", instance="ghe-b.example"),
            ],
            max_requests=5,
        )
        validated = validate_collection_config(config)
        self.assertEqual(len(validated["scope"]["repositories"]), 2)

    def test_config_and_request_repository_order_is_canonical(self) -> None:
        repositories = [
            repository("a", "z"),
            repository("a-", "a"),
            repository("zeta", "project"),
        ]
        expected = [
            ("a-", "a"),
            ("a", "z"),
            ("zeta", "project"),
        ]
        for permutation in (repositories, list(reversed(repositories))):
            with self.subTest(permutation=permutation):
                validated = validate_collection_config(
                    config_for(permutation, max_requests=15)
                )
                self.assertEqual(
                    [
                        (item["owner"], item["name"])
                        for item in validated["scope"]["repositories"]
                    ],
                    expected,
                )

                targets = tuple(
                    RepositoryTarget(
                        item["provider"],
                        item["instance"],
                        item["owner"],
                        item["name"],
                    )
                    for item in permutation
                )
                request = CollectionRequest(
                    provider_kind="github",
                    instance="github.com",
                    repositories=targets,
                    window_start="2026-08-01T00:00:00Z",
                    window_end="2026-08-02T00:00:00Z",
                    timezone="UTC",
                    max_requests=15,
                )
                self.assertEqual(
                    [(item.owner, item.name) for item in request.repositories],
                    expected,
                )

    def test_failed_collection_scope_and_diagnostics_keep_canonical_order(self) -> None:
        repositories = [repository("a", "z"), repository("a-", "a")]

        class FailedProvider:
            def collect(self, request: CollectionRequest) -> dict[str, object]:
                del request
                raise RuntimeError("fixture failure")

        for permutation in (repositories, list(reversed(repositories))):
            with self.subTest(permutation=permutation):
                bundle = collect_config(
                    config_for(permutation, max_requests=10),
                    provider_factory=lambda *args: FailedProvider(),
                )
                expected_ids = [
                    "repo:github:github.com:a-/a",
                    "repo:github:github.com:a/z",
                ]
                self.assertEqual(bundle["run"]["scope"]["repositories"], expected_ids)
                diagnostic_order = list(
                    dict.fromkeys(
                        failure["repository"]
                        for failure in bundle["coverage"]["group_failures"]
                    )
                )
                self.assertEqual(diagnostic_order, expected_ids)

    def test_direct_request_rejects_infeasible_budget(self) -> None:
        targets = (
            RepositoryTarget("github", "github.com", "alpha", "project"),
            RepositoryTarget("github", "github.com", "beta", "project"),
        )
        with self.assertRaisesRegex(ValueError, "plan_budget_infeasible"):
            CollectionRequest(
                provider_kind="github",
                instance="github.com",
                repositories=targets,
                window_start="2026-08-01T00:00:00Z",
                window_end="2026-08-02T00:00:00Z",
                timezone="UTC",
                max_requests=9,
            )

    def test_direct_request_rejects_empty_repository_scope(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-empty allowlist"):
            CollectionRequest(
                provider_kind="github",
                instance="github.com",
                repositories=(),
                window_start="2026-08-01T00:00:00Z",
                window_end="2026-08-02T00:00:00Z",
                timezone="UTC",
            )


if __name__ == "__main__":
    unittest.main()
