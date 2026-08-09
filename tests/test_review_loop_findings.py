from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Self
from unittest.mock import patch
from urllib.error import HTTPError

from test_contract import (
    WINDOW_END,
    WINDOW_START,
    gitee_transport,
    github_transport,
    gitlab_transport,
    request_for,
    rewrite_transport_urls,
    validate_output,
)

from git_evidence.cli import main as cli_main
from git_evidence.collect import _merge_bundles, collect_config
from git_evidence.config import (
    ConfigError,
    validate_collection_config,
    validate_report_config,
)
from git_evidence.model import load_bundle
from git_evidence.privacy import (
    PrivacyError,
    is_sensitive_field,
    sanitize_public_payload,
)
from git_evidence.providers.base import (
    CollectionRequest,
    RepositoryTarget,
    append_optional_coverage_warning,
    instance_web_base,
)
from git_evidence.providers.gitee import GiteeProvider
from git_evidence.providers.github import GitHubProvider
from git_evidence.providers.gitlab import GitLabProvider
from git_evidence.providers.resource_base import (
    in_window_or_malformed,
    merge_diagnostics,
    parse_timestamp,
)
from git_evidence.providers.transport import (
    ApiError,
    ApiResponse,
    LocalResponseCache,
    MappingTransport,
    ResponseShapeError,
    UrllibTransport,
    paginate,
)
from git_evidence.validation import has_blocking_core_coverage

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "example_bundle.json"


class ReviewLoopFindingTests(unittest.TestCase):
    def test_instance_authority_rejects_credentials_query_and_fragment(self) -> None:
        base = {
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
        for unsafe in (
            "https://user:password@example.test",
            "https://example.test?tenant=one",
            "https://example.test#fragment",
        ):
            with self.subTest(instance=unsafe):
                invalid = deepcopy(base)
                invalid["providers"]["public-github"]["instance"] = unsafe
                with self.assertRaises(ConfigError):
                    validate_collection_config(invalid)
                with self.assertRaises(ValueError):
                    RepositoryTarget("github", unsafe, "example", "project")
                with self.assertRaises(ValueError):
                    instance_web_base(unsafe)
                with self.assertRaises(ValueError):
                    GitHubProvider(github_transport(), instance=unsafe)

        safe_base = "https://gitlab.example/base"
        self.assertEqual(instance_web_base(safe_base), safe_base)
        self.assertEqual(
            GitLabProvider(gitlab_transport(), instance=safe_base).instance,
            safe_base,
        )
        with self.assertRaises(ValueError):
            CollectionRequest(
                provider_kind="github",
                instance="github.com",
                repositories=(
                    RepositoryTarget("github", "other.example", "example", "project"),
                ),
                window_start=WINDOW_START,
                window_end=WINDOW_END,
                timezone="UTC",
            )

    def test_provider_collect_requires_instance_and_target_binding(self) -> None:
        provider = GitHubProvider(github_transport(), instance="github.com")
        request = request_for("github", "github.com")
        mismatched_instance = SimpleNamespace(
            provider_kind="github",
            instance="other.example",
            repositories=request.repositories,
            max_pages=request.max_pages,
        )
        with self.assertRaises(ValueError):
            provider.collect(mismatched_instance)

        mismatched_target = SimpleNamespace(
            provider_kind="github",
            instance="github.com",
            repositories=(
                RepositoryTarget("github", "other.example", "example", "project"),
            ),
            max_pages=request.max_pages,
        )
        with self.assertRaises(ValueError):
            provider.collect(mismatched_target)

    def test_repository_root_non_success_status_blocks_all_provider_sources(
        self,
    ) -> None:
        cases = (
            (
                "github",
                "github.com",
                GitHubProvider,
                github_transport(),
                "/repos/example/project",
            ),
            (
                "gitlab",
                "gitlab.com",
                GitLabProvider,
                gitlab_transport(),
                "/projects/example%2Fproject",
            ),
            (
                "gitee",
                "gitee.com",
                GiteeProvider,
                gitee_transport(),
                "/repos/example/project",
            ),
        )
        for provider_kind, instance, provider_type, transport, root in cases:
            with self.subTest(provider=provider_kind):
                transport.responses[root][0] = ApiResponse(
                    root,
                    500,
                    {
                        "Retry-After": "7",
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "123",
                    },
                    {"id": 1, "name": "project"},
                )
                bundle = provider_type(transport).collect(
                    request_for(provider_kind, instance)
                )
                self.assertFalse(bundle["coverage"]["render_eligible"])
                observations = {
                    item["source"]: item for item in bundle["coverage"]["observations"]
                }
                resource_observations = {
                    source: observations[source]
                    for source in (
                        "repositories",
                        "work_items",
                        "change_request_observations",
                        "change_request_merges",
                        "interactions",
                        "commits",
                        "releases",
                    )
                }
                self.assertEqual(
                    set(resource_observations),
                    {
                        "repositories",
                        "work_items",
                        "change_request_observations",
                        "change_request_merges",
                        "interactions",
                        "commits",
                        "releases",
                    },
                )
                self.assertTrue(
                    all(
                        item["status"] == "incomplete"
                        for item in resource_observations.values()
                    )
                )
                self.assertTrue(
                    all(
                        item["diagnostics"]["failure_class"] == "service_error"
                        for item in resource_observations.values()
                    )
                )
                self.assertEqual(
                    resource_observations["repositories"]["diagnostics"]["status_code"],
                    500,
                )
                self.assertEqual(
                    resource_observations["repositories"]["diagnostics"][
                        "retry_after_seconds"
                    ],
                    7.0,
                )
                self.assertEqual(
                    resource_observations["repositories"]["diagnostics"]["rate_limit"][
                        "x-ratelimit-remaining"
                    ],
                    "0",
                )

    def test_repository_auth_failure_has_no_placeholder_repository(self) -> None:
        cases = (
            (
                "github",
                "github.com",
                GitHubProvider,
                github_transport(),
                "/repos/example/project",
            ),
            (
                "gitlab",
                "gitlab.com",
                GitLabProvider,
                gitlab_transport(),
                "/projects/example%2Fproject",
            ),
            (
                "gitee",
                "gitee.com",
                GiteeProvider,
                gitee_transport(),
                "/repos/example/project",
            ),
        )
        for provider_kind, instance, provider_type, transport, root in cases:
            with self.subTest(provider=provider_kind):
                transport.responses[root][0] = ApiResponse(
                    root, 401, {}, {"message": "unauthorized"}
                )
                bundle = provider_type(transport).collect(
                    request_for(provider_kind, instance)
                )
                self.assertEqual(bundle["repositories"], [])
                self.assertFalse(bundle["coverage"]["render_eligible"])
                repository_observation = next(
                    item
                    for item in bundle["coverage"]["observations"]
                    if item["source"] == "repositories"
                )
                self.assertEqual(
                    repository_observation["diagnostics"]["failure_class"],
                    "permission_denied",
                )
                self.assertIn(
                    "coverage.required_missing",
                    {issue.code for issue in validate_output(bundle)},
                )

    def test_repository_root_identity_mismatch_blocks_without_placeholder(self) -> None:
        cases = (
            (
                "github",
                "github.com",
                GitHubProvider,
                "/repos/example/project",
                "full_name",
            ),
            (
                "gitlab",
                "gitlab.com",
                GitLabProvider,
                "/projects/example%2Fproject",
                "path_with_namespace",
            ),
            (
                "gitee",
                "gitee.com",
                GiteeProvider,
                "/repos/example/project",
                "full_name",
            ),
        )
        for provider_kind, instance, provider_type, root, identity_field in cases:
            for field in (identity_field, "name"):
                with self.subTest(provider=provider_kind, field=field):
                    transport = {
                        "github": github_transport,
                        "gitlab": gitlab_transport,
                        "gitee": gitee_transport,
                    }[provider_kind]()
                    transport.responses[root][0].body[field] = (
                        "other/project" if field == identity_field else "other-project"
                    )
                    bundle = provider_type(transport).collect(
                        request_for(provider_kind, instance)
                    )
                    self.assertEqual(bundle["repositories"], [])
                    self.assertFalse(bundle["coverage"]["render_eligible"])
                    repository_observation = next(
                        item
                        for item in bundle["coverage"]["observations"]
                        if item["source"] == "repositories"
                    )
                    self.assertEqual(
                        repository_observation["diagnostics"]["failure_class"],
                        "malformed_response",
                    )
                    self.assertTrue(has_blocking_core_coverage(bundle["coverage"]))
                    self.assertIn(
                        "coverage.render_blocked",
                        {issue.code for issue in validate_output(bundle)},
                    )

    def test_repository_root_url_identity_and_shape_are_fail_closed(self) -> None:
        cases = (
            (
                "github",
                GitHubProvider,
                github_transport,
                "/repos/example/project",
                "html_url",
            ),
            (
                "gitlab",
                GitLabProvider,
                gitlab_transport,
                "/projects/example%2Fproject",
                "web_url",
            ),
            (
                "gitee",
                GiteeProvider,
                gitee_transport,
                "/repos/example/project",
                "html_url",
            ),
        )
        for provider_kind, provider_type, transport_factory, root, url_field in cases:
            for value in (
                f"https://{provider_kind}.com/other/project",
                "not-a-url",
            ):
                with self.subTest(provider=provider_kind, value=value):
                    transport = transport_factory()
                    transport.responses[root][0].body[url_field] = value
                    bundle = provider_type(transport).collect(
                        request_for(provider_kind, f"{provider_kind}.com")
                    )
                    repository_observation = next(
                        item
                        for item in bundle["coverage"]["observations"]
                        if item["source"] == "repositories"
                    )
                    self.assertEqual(repository_observation["status"], "incomplete")
                    self.assertEqual(
                        repository_observation["diagnostics"]["failure_class"],
                        "malformed_response",
                    )
                    self.assertEqual(bundle["repositories"], [])
                    self.assertFalse(bundle["coverage"]["render_eligible"])

    def test_custom_instances_reject_public_root_and_native_urls(self) -> None:
        cases = (
            (
                "github",
                GitHubProvider,
                github_transport,
                "/repos/example/project",
                "html_url",
                "https://ghe.example/base",
            ),
            (
                "gitlab",
                GitLabProvider,
                gitlab_transport,
                "/projects/example%2Fproject",
                "web_url",
                "https://glt.example/base",
            ),
            (
                "gitee",
                GiteeProvider,
                gitee_transport,
                "/repos/example/project",
                "html_url",
                "https://gte.example/base",
            ),
        )
        for (
            provider_kind,
            provider_type,
            transport_factory,
            root,
            url_field,
            instance,
        ) in cases:
            with self.subTest(provider=provider_kind, boundary="root"):
                transport = transport_factory()
                bundle = provider_type(transport, instance=instance).collect(
                    request_for(provider_kind, instance)
                )
                self.assertEqual(bundle["repositories"], [])
                self.assertFalse(bundle["coverage"]["render_eligible"])
                self.assertEqual(
                    next(
                        item
                        for item in bundle["coverage"]["observations"]
                        if item["source"] == "repositories"
                    )["diagnostics"]["failure_class"],
                    "malformed_response",
                )

            with self.subTest(provider=provider_kind, boundary="native"):
                transport = transport_factory()
                rewrite_transport_urls(
                    transport, f"https://{provider_kind}.com", instance
                )
                transport.responses[f"{root}/issues"][0].body[0][url_field] = (
                    f"{instance}/other/project/issues/1"
                )
                bundle = provider_type(transport, instance=instance).collect(
                    request_for(provider_kind, instance)
                )
                work_items = next(
                    item
                    for item in bundle["coverage"]["observations"]
                    if item["source"] == "work_items"
                )
                self.assertEqual(work_items["status"], "incomplete")
                self.assertEqual(
                    work_items["diagnostics"]["failure_class"], "malformed_response"
                )
                self.assertFalse(bundle["coverage"]["render_eligible"])

    def test_supported_core_operational_diagnostics_close_gate_during_collection(
        self,
    ) -> None:
        provider = GitHubProvider(github_transport())
        original_normalize_page = provider._normalize_scheduled_page

        def normalize_page(task: object, page: object) -> object:
            result = original_normalize_page(task, page)
            if task.source == "commits":
                result.diagnostics = {
                    "child_diagnostics": [{"failure_classes": ["permission_denied"]}],
                }
            return result

        with patch.object(
            provider, "_normalize_scheduled_page", side_effect=normalize_page
        ):
            bundle = provider.collect(request_for("github", "github.com"))
        commits = next(
            item
            for item in bundle["coverage"]["observations"]
            if item["source"] == "commits"
        )
        self.assertEqual(commits["status"], "incomplete")
        self.assertFalse(bundle["coverage"]["render_eligible"])
        self.assertTrue(has_blocking_core_coverage(bundle["coverage"]))
        self.assertTrue(
            any(
                failure["source"] == "commits"
                and failure["failure_class"] == "permission_denied"
                for failure in bundle["coverage"]["group_failures"]
            )
        )
        self.assertTrue(
            any(
                failure["source"] == "commits"
                for failure in bundle["coverage"]["fatal"]
            )
        )

    def test_handwritten_supported_core_failure_diagnostics_are_rejected(self) -> None:
        for failure_class in (
            "permission_denied",
            "malformed_response",
            "unexpected_normalizer_error",
        ):
            with self.subTest(failure_class=failure_class):
                bundle = load_bundle(FIXTURE)
                commit_observation = next(
                    item
                    for item in bundle["coverage"]["observations"]
                    if item["source"] == "commits"
                )
                commit_observation["status"] = "supported"
                commit_observation["diagnostics"] = {
                    "child_diagnostics": [{"failure_classes": [failure_class]}],
                }
                self.assertTrue(has_blocking_core_coverage(bundle["coverage"]))
                codes = {issue.code for issue in validate_output(bundle)}
                self.assertIn("coverage.supported_operational_failure", codes)
                self.assertIn("coverage.render_blocked", codes)

    def test_supported_optional_operational_diagnostics_do_not_close_gate(self) -> None:
        bundle = GitHubProvider(github_transport()).collect(
            request_for("github", "github.com", include_activity_api=True)
        )
        for observation in bundle["coverage"]["observations"]:
            if observation["source"] in {"activities", "ref_changes"}:
                observation["status"] = "supported"
                observation["diagnostics"] = {
                    "child_diagnostics": [{"failure_classes": ["permission_denied"]}],
                }
        bundle["providers"][0]["capabilities"]["activities"] = "supported"
        bundle["providers"][0]["capabilities"]["ref_changes"] = "supported"
        bundle["coverage"]["warnings"] = []
        self.assertTrue(bundle["coverage"]["render_eligible"])
        self.assertEqual(validate_output(bundle), [])

    def test_validator_rejects_optional_privacy_without_fatal_ledger(self) -> None:
        bundle = load_bundle(FIXTURE)
        repository_id = bundle["repositories"][0]["id"]
        provider_id = bundle["repositories"][0]["provider_id"]
        bundle["coverage"]["observations"].append(
            {
                "source": "activities",
                "provider_id": provider_id,
                "repository_id": repository_id,
                "status": "incomplete",
                "diagnostics": {
                    "child_diagnostics": [{"failure_class": "privacy_violation"}]
                },
            }
        )
        bundle["coverage"]["warnings"].append(
            {
                "code": "optional_coverage_warning",
                "source": "activities",
                "provider_id": provider_id,
                "repository_id": repository_id,
                "status": "incomplete",
                "failure_class": "privacy_violation",
                "message": "activity privacy boundary failed",
            }
        )
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("coverage.optional_privacy_fatal", codes)
        self.assertIn("coverage.render_blocked", codes)

    def test_optional_privacy_collection_is_fatal_but_typed_optional_failures_warn(
        self,
    ) -> None:
        provider = GitHubProvider(github_transport())
        with patch.object(
            provider,
            "_collect_activity",
            side_effect=PrivacyError("activity payload crossed the public boundary"),
        ):
            bundle = provider.collect(
                request_for("github", "github.com", include_activity_api=True)
            )
        self.assertFalse(bundle["coverage"]["render_eligible"])
        self.assertTrue(
            all(
                any(
                    failure["source"] == source
                    and failure["failure_class"] == "privacy_violation"
                    for failure in bundle["coverage"]["fatal"]
                )
                for source in ("activities", "ref_changes")
            )
        )
        self.assertIn(
            "coverage.fatal", {issue.code for issue in validate_output(bundle)}
        )

    def test_optional_warning_enrichment_is_single_and_monotonic(self) -> None:
        for statuses in (("unavailable", "incomplete"), ("incomplete", "unavailable")):
            with self.subTest(statuses=statuses):
                coverage = {"warnings": [], "observations": []}
                for index, status in enumerate(statuses):
                    observation = {
                        "source": "activities",
                        "provider_id": "provider:github:github.com",
                        "repository_id": "repo:github:github.com:example/project",
                        "status": status,
                        "note": f"failure {index}",
                        "diagnostics": (
                            {"failure_class": "permission_denied"}
                            if index == 0
                            else {
                                "child_diagnostics": [
                                    {"failure_classes": ["service_error"]}
                                ]
                            }
                        ),
                    }
                    coverage["observations"].append(observation)
                    append_optional_coverage_warning(coverage, observation)
                self.assertEqual(len(coverage["warnings"]), 1)
                warning = coverage["warnings"][0]
                self.assertEqual(warning["status"], "incomplete")
                self.assertEqual(
                    warning["failure_classes"], ["permission_denied", "service_error"]
                )
                self.assertIn("failure 0", warning["message"])
                self.assertIn("failure 1", warning["message"])
                self.assertEqual(
                    [observation["status"] for observation in coverage["observations"]],
                    ["incomplete", "incomplete"],
                )

    def test_optional_warning_must_cover_duplicate_observation_diagnostics(
        self,
    ) -> None:
        bundle = load_bundle(FIXTURE)
        original = next(
            observation
            for observation in bundle["coverage"]["observations"]
            if observation["source"] == "ref_changes"
        )
        duplicate = deepcopy(original)
        duplicate["diagnostics"] = {
            "child_diagnostics": [{"failure_classes": ["service_error"]}],
        }
        bundle["coverage"]["observations"].append(duplicate)
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("coverage.warning_diagnostics", codes)

        warning = next(
            warning
            for warning in bundle["coverage"]["warnings"]
            if warning["source"] == "ref_changes"
        )
        warning.pop("failure_class", None)
        warning["failure_classes"] = ["service_error"]
        self.assertNotIn(
            "coverage.warning_diagnostics",
            {issue.code for issue in validate_output(bundle)},
        )

    def test_group_failure_cannot_coexist_with_render_eligible_ledger(self) -> None:
        bundle = load_bundle(FIXTURE)
        failure = {
            "provider": "github",
            "instance": "github.com",
            "repository": bundle["repositories"][0]["id"],
            "source": "commits",
            "failure_class": "rate_limited",
        }
        bundle["coverage"]["group_failures"] = [failure]
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("coverage.group_failure_contradiction", codes)
        self.assertIn("coverage.group_failure_fatal", codes)
        self.assertIn("coverage.render_blocked", codes)

    def test_coverage_observation_requires_registered_provider_provenance(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["coverage"]["observations"][0].pop("provider_id")
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("coverage.provider_required", codes)
        self.assertIn("coverage.required_missing", codes)

        bundle = load_bundle(FIXTURE)
        bundle["coverage"]["observations"][0]["provider_id"] = (
            "provider:gitlab:gitlab.com"
        )
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("coverage.provider_unknown", codes)
        self.assertIn("coverage.required_missing", codes)

    def test_fact_evidence_subject_and_provider_provenance_are_required(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["evidence"][0].pop("subject_id")
        self.assertIn(
            "assertion.evidence_subject",
            {issue.code for issue in validate_output(bundle)},
        )

        bundle = load_bundle(FIXTURE)
        bundle["evidence"][0]["provider_id"] = "provider:gitlab:gitlab.com"
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("evidence.provenance", codes)
        self.assertIn("evidence.retrieval_provider", codes)

    def test_validator_checks_canonical_repository_identity_and_url(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["repositories"][0]["full_name"] = "other/project"
        self.assertIn(
            "repository.identity", {issue.code for issue in validate_output(bundle)}
        )

        bundle = load_bundle(FIXTURE)
        bundle["repositories"][0]["web_url"] = "https://github.com/other/project"
        self.assertIn(
            "repository.url_identity", {issue.code for issue in validate_output(bundle)}
        )

    def test_foreign_optional_activity_is_dropped_without_pseudo_ref_change(
        self,
    ) -> None:
        transport = github_transport()
        transport.responses["/repos/example/project/events"][0].body[0]["repo"][
            "name"
        ] = "other/project"
        bundle = GitHubProvider(transport).collect(
            request_for("github", "github.com", include_activity_api=True)
        )
        self.assertTrue(bundle["coverage"]["render_eligible"])
        self.assertFalse(
            any(item["id"].endswith(":event-1") for item in bundle["ref_changes"])
        )
        self.assertTrue(
            all(
                observation["status"] == "incomplete"
                for observation in bundle["coverage"]["observations"]
                if observation["source"] in {"activities", "ref_changes"}
            )
        )
        self.assertEqual(validate_output(bundle), [])

    def test_internal_api_failure_has_group_ledger_and_preserves_siblings(self) -> None:
        transport = github_transport()
        transport.responses.pop("/repos/example/project/issues")
        bundle = GitHubProvider(transport).collect(request_for("github", "github.com"))
        self.assertFalse(bundle["coverage"]["render_eligible"])
        self.assertTrue(bundle["work_items"] == [])
        self.assertGreater(len(bundle["change_requests"]), 0)
        self.assertTrue(
            any(
                item["source"] == "work_items"
                and item["failure_class"] == "fixture_missing"
                for item in bundle["coverage"]["group_failures"]
            )
        )

    def test_merge_does_not_silently_drop_duplicate_records(self) -> None:
        bundle = GitHubProvider(github_transport()).collect(
            request_for("github", "github.com")
        )
        duplicate = deepcopy(bundle)
        merged = _merge_bundles(
            [bundle, duplicate],
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            timezone="UTC",
            repository_ids=[bundle["repositories"][0]["id"]],
            actor_ids=[],
        )
        self.assertEqual(len(merged["assertions"]), len(bundle["assertions"]))
        self.assertTrue(
            any(
                "duplicate record id" in failure.get("reason", "")
                for failure in merged["coverage"]["group_failures"]
            )
        )
        self.assertFalse(merged["coverage"]["render_eligible"])

    def test_merge_ignores_optional_only_provider_gate(self) -> None:
        bundle = GitHubProvider(github_transport()).collect(
            request_for("github", "github.com")
        )
        bundle["coverage"]["render_eligible"] = False
        merged = _merge_bundles(
            [bundle],
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            timezone="UTC",
            repository_ids=[bundle["repositories"][0]["id"]],
            actor_ids=[],
        )
        self.assertTrue(merged["coverage"]["render_eligible"])
        self.assertEqual(validate_output(merged), [])

    def test_merge_blocks_missing_core_coverage(self) -> None:
        bundle = GitHubProvider(github_transport()).collect(
            request_for("github", "github.com")
        )
        bundle["coverage"]["observations"] = [
            observation
            for observation in bundle["coverage"]["observations"]
            if observation["source"] != "commits"
        ]
        merged = _merge_bundles(
            [bundle],
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            timezone="UTC",
            repository_ids=[bundle["repositories"][0]["id"]],
            actor_ids=[],
        )
        self.assertFalse(merged["coverage"]["render_eligible"])
        self.assertIn(
            "coverage.required_missing",
            {issue.code for issue in validate_output(merged)},
        )
        self.assertIn(
            "coverage.render_blocked",
            {issue.code for issue in validate_output(merged)},
        )

    def test_validation_scopes_core_gate_per_repository(self) -> None:
        first = GitHubProvider(github_transport()).collect(
            request_for("github", "github.com")
        )
        second_instance = "https://ghe.example/base"
        second_transport = github_transport()
        rewrite_transport_urls(second_transport, "https://github.com", second_instance)
        second = GitHubProvider(second_transport, instance=second_instance).collect(
            request_for("github", second_instance)
        )
        repository_ids = [
            first["repositories"][0]["id"],
            second["repositories"][0]["id"],
        ]
        merged = _merge_bundles(
            [first, second],
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            timezone="UTC",
            repository_ids=repository_ids,
            actor_ids=[],
        )

        merged["coverage"]["observations"] = [
            observation
            for observation in merged["coverage"]["observations"]
            if not (
                observation.get("repository_id") == repository_ids[1]
                and observation.get("source") == "commits"
            )
        ]
        merged["coverage"]["render_eligible"] = True

        # An unscoped check sees the first repository's commits and would
        # incorrectly allow this multi-repository bundle.
        self.assertFalse(has_blocking_core_coverage(merged["coverage"]))
        provider_ids = {
            repository["id"]: repository["provider_id"]
            for repository in merged["repositories"]
        }
        self.assertTrue(
            has_blocking_core_coverage(
                merged["coverage"],
                repository_ids=repository_ids,
                provider_ids_by_repository=provider_ids,
            )
        )
        codes = {issue.code for issue in validate_output(merged)}
        self.assertIn("coverage.required_missing", codes)
        self.assertIn("coverage.render_blocked", codes)

    def test_cache_replays_allowlisted_pagination_headers_and_rejects_old_or_unsafe_entries(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            cache = LocalResponseCache(path, ttl_seconds=300, max_entries=10)
            response = ApiResponse(
                "https://example.test/items",
                200,
                {
                    "Link": '<https://example.test/items?page=2> ; rel = "next"',
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
            self.assertEqual(
                replay.headers["link"],
                '<https://example.test/items?page=2> ; rel = "next"',
            )
            self.assertEqual(replay.headers["x-next-page"], "2")
            self.assertEqual(replay.headers["x-ratelimit-remaining"], "4")
            self.assertNotIn("authorization", replay.headers)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)

            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["entries"]["old"] = {
                "stored_at": 0,
                "response": {
                    "url": "https://example.test/items",
                    "status_code": 200,
                    "body": [],
                },
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertIsNone(cache.get("old"))
            os.chmod(path, 0o644)
            self.assertIsNone(cache.get("page-1"))

            unsafe_path = Path(directory) / "unsafe.json"
            unsafe_cache = LocalResponseCache(
                unsafe_path, ttl_seconds=300, max_entries=10
            )
            unsafe_cache.put(
                "body-secret",
                ApiResponse(
                    "https://example.test/items", 200, {}, {"api_key": "secret"}
                ),
                token=None,
            )
            self.assertFalse(unsafe_path.exists())
            unsafe_cache.put(
                "status-error",
                ApiResponse("https://example.test/items", 500, {}, []),
                token=None,
            )
            self.assertIsNone(unsafe_cache.get("status-error"))
            unsafe_cache.put(
                "bool-status",
                ApiResponse("https://example.test/items", True, {}, []),
                token=None,
            )
            self.assertIsNone(unsafe_cache.get("bool-status"))
            unsafe_cache.put(
                "header-secret",
                ApiResponse(
                    "https://example.test/items", 200, {"X-Next-Page": "secret"}, []
                ),
                token="secret",
            )
            self.assertFalse(unsafe_path.exists())
            unsafe_cache.put(
                "header-invalid",
                ApiResponse(
                    "https://example.test/items",
                    200,
                    {"X-RateLimit-Remaining": "Bearer secret"},
                    [],
                ),
                token=None,
            )
            self.assertFalse(unsafe_path.exists())

            status_entry = Path(directory) / "status-entry.json"
            status_cache = LocalResponseCache(
                status_entry, ttl_seconds=300, max_entries=10
            )
            status_cache.put(
                "valid",
                ApiResponse("https://example.test/items", 200, {}, []),
                token=None,
            )
            payload = json.loads(status_entry.read_text(encoding="utf-8"))
            payload["entries"]["valid"]["response"]["status_code"] = 500
            status_entry.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(status_entry, 0o600)
            self.assertIsNone(status_cache.get("valid"))

            with self.assertRaises(ApiError):
                paginate(
                    MappingTransport(
                        {
                            "/items": ApiResponse(
                                "https://example.test/items", 500, {}, []
                            )
                        }
                    ),
                    "/items",
                )
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

    def test_cache_rejects_nonfinite_stored_at_and_clock_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nonfinite.json"
            cache = LocalResponseCache(path, ttl_seconds=300, max_entries=10)
            response = ApiResponse("https://example.test/items", 200, {}, [])
            for literal in ("NaN", "Infinity", "-Infinity"):
                path.write_text(
                    '{"version": 1, "entries": {"bad": {'
                    f'"stored_at": {literal}, '
                    '"response": {"url": "https://example.test/items", '
                    '"status_code": 200, "headers": {}, "body": []}}}}',
                    encoding="utf-8",
                )
                os.chmod(path, 0o600)
                self.assertIsNone(cache.get("bad"))
                cache.put("good", response, token=None)
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.assertNotIn("bad", payload["entries"])

            negative = json.loads(path.read_text(encoding="utf-8"))
            negative["entries"]["negative"] = {
                "stored_at": -1,
                "response": {
                    "url": "https://example.test/items",
                    "status_code": 200,
                    "headers": {},
                    "body": [],
                },
            }
            path.write_text(json.dumps(negative), encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertIsNone(cache.get("negative"))

            invalid_clock_path = Path(directory) / "invalid-clock.json"
            invalid_clock = LocalResponseCache(
                invalid_clock_path,
                ttl_seconds=300,
                max_entries=10,
                clock=lambda: float("nan"),
            )
            invalid_clock.put("entry", response, token=None)
            self.assertFalse(invalid_clock_path.exists())

    def test_custom_token_param_is_redacted_and_not_cached(self) -> None:
        token = "custom-secret"
        transport = UrllibTransport(
            "https://example.test",
            token,
            token_param="custom_credential",
            max_retries=0,
            retry_backoff=0,
            retry_jitter=0,
            sleep_fn=lambda _: None,
        )
        raw_url = transport._url("/items", None)
        self.assertIn("custom_credential=custom-secret", raw_url)
        self.assertNotIn(token, transport._redact_url(raw_url))

        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "cache.json"
            cache = LocalResponseCache(
                cache_path,
                ttl_seconds=300,
                max_entries=10,
                credential_query_names=("custom_credential",),
            )
            cache.put("secret", ApiResponse(raw_url, 200, {}, []), token=token)
            self.assertFalse(cache_path.exists())

        error = HTTPError(raw_url, 401, "unauthorized", {}, BytesIO(b"custom-secret"))
        with (
            patch("git_evidence.providers.transport.urlopen", side_effect=[error]),
            self.assertRaises(ApiError) as caught,
        ):
            transport.get("/items")
        self.assertNotIn(token, str(caught.exception))

    def test_nested_auth_urls_are_rejected_but_redacted_urls_and_plain_text_are_safe(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested.json"
            cache = LocalResponseCache(path, ttl_seconds=300, max_entries=10)
            cache.put(
                "nested-secret",
                ApiResponse(
                    "https://example.test/items",
                    200,
                    {},
                    {
                        "_links": {
                            "self": "https://example.test/items?access_token=secret"
                        }
                    },
                ),
                token=None,
            )
            self.assertFalse(path.exists())
            cache.put(
                "nested-redacted",
                ApiResponse(
                    "https://example.test/items",
                    200,
                    {},
                    {
                        "_links": {
                            "self": "https://example.test/items?access_token=%5BREDACTED%5D"
                        }
                    },
                ),
                token=None,
            )
            self.assertIsNotNone(cache.get("nested-redacted"))
            cache.put(
                "plain",
                ApiResponse(
                    "https://example.test/items",
                    200,
                    {},
                    {"note": "ordinary text mentioning access_token=not-a-url"},
                ),
                token=None,
            )
            self.assertIsNotNone(cache.get("plain"))

    def test_merge_diagnostics_preserves_distinct_child_transport_details(self) -> None:
        diagnostics: dict[str, object] = {}
        merge_diagnostics(
            diagnostics,
            {
                "failure_class": "permission_denied",
                "status_code": 403,
                "attempts": 1,
                "retry_after_seconds": 2.0,
                "rate_limit": {"x-ratelimit-remaining": "0"},
            },
        )
        merge_diagnostics(
            diagnostics,
            {
                "failure_class": "rate_limited",
                "status_code": 429,
                "attempts": 2,
                "retry_after_seconds": 4.0,
                "rate_limit": {"x-ratelimit-remaining": "1"},
            },
        )
        self.assertEqual(diagnostics["status_code"], 403)
        self.assertEqual(diagnostics["attempts"], 1)
        self.assertEqual(diagnostics["retry_after_seconds"], 2.0)
        self.assertEqual(diagnostics["rate_limit"], {"x-ratelimit-remaining": "0"})
        self.assertEqual(
            {child["status_code"] for child in diagnostics["child_diagnostics"]},
            {403, 429},
        )
        self.assertEqual(
            set(diagnostics["failure_classes"]),
            {"permission_denied", "rate_limited"},
        )

    def test_paginate_non_success_preserves_retry_and_rate_limit_diagnostics(
        self,
    ) -> None:
        transport = MappingTransport(
            {
                "/items": ApiResponse(
                    "https://example.test/items",
                    429,
                    {
                        "Retry-After": "5",
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "123",
                    },
                    [],
                )
            }
        )
        with self.assertRaises(ApiError) as caught:
            paginate(transport, "/items")
        self.assertEqual(caught.exception.failure_class, "rate_limited")
        self.assertEqual(caught.exception.retry_after, 5.0)
        self.assertEqual(caught.exception.rate_limit["retry-after"], "5")
        self.assertEqual(caught.exception.rate_limit["x-ratelimit-remaining"], "0")

    def test_shared_link_parser_follows_spaced_next_and_rejects_malformed_header(
        self,
    ) -> None:
        transport = MappingTransport(
            {
                "/items": [
                    ApiResponse(
                        "https://example.test/items?page=1",
                        200,
                        {"Link": '<https://example.test/items?page=2> ; rel = "next"'},
                        [{"id": 1}],
                    ),
                ],
                "https://example.test/items?page=2": ApiResponse(
                    "https://example.test/items?page=2",
                    200,
                    {},
                    [],
                ),
            }
        )
        result = paginate(transport, "/items", per_page=2)
        self.assertTrue(result.complete)
        self.assertEqual(len(result.items), 1)
        self.assertEqual(len(transport.calls), 2)
        with self.assertRaises(ResponseShapeError):
            paginate(
                MappingTransport(
                    {
                        "/bad": ApiResponse(
                            "https://example.test/bad",
                            200,
                            {"Link": "not-a-link"},
                            [],
                        )
                    }
                ),
                "/bad",
            )

    def test_privacy_key_variants_are_canonical_and_rejected(self) -> None:
        for key in (
            "clientSecret",
            "X-API-Key",
            "authHeader",
            "X-Auth-Token",
            "github_token",
        ):
            self.assertTrue(is_sensitive_field(key), key)
        self.assertFalse(is_sensitive_field("author"))
        with self.assertRaises(PrivacyError):
            sanitize_public_payload({"clientSecret": "secret"})
        with self.assertRaises(PrivacyError):
            sanitize_public_payload({"X-API-Key": "secret"})

    def test_inline_credentials_and_unknown_provider_fields_are_rejected(self) -> None:
        base = {
            "window": {"start": WINDOW_START, "end": WINDOW_END, "timezone": "UTC"},
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
                "public-github": {
                    "kind": "github",
                    "instance": "github.com",
                    "token_env": "GITHUB_TOKEN",
                }
            },
        }
        unknown = deepcopy(base)
        unknown["providers"]["public-github"]["business"] = {
            "author": "synthetic",
            "tokenized_name": "safe",
        }
        with self.assertRaisesRegex(ConfigError, "unknown key"):
            validate_collection_config(unknown)
        for secret_key in ("github_token", "clientSecret", "X-API-Key", "authHeader"):
            unsafe = deepcopy(base)
            unsafe["providers"]["public-github"]["nested"] = {secret_key: "secret"}
            with self.subTest(secret_key=secret_key), self.assertRaises(ConfigError):
                validate_collection_config(unsafe)
        unsafe_alias = deepcopy(base)
        unsafe_alias["providers"]["github"] = {"tokenEnv": "secret-value"}
        with self.assertRaises(ConfigError):
            validate_collection_config(unsafe_alias)

    def test_report_privacy_type_errors_are_config_errors_and_cli_status_two(
        self,
    ) -> None:
        with self.assertRaises(ConfigError):
            validate_report_config({"report": {"privacy": {"actor_display": []}}})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.toml"
            path.write_text(
                '[report.privacy]\nactor_display = "invalid"\n', encoding="utf-8"
            )
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
            provider_factory=lambda *args: LeakyProvider(),
        )
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
        with (
            patch("git_evidence.providers.transport.urlopen", side_effect=[error]),
            self.assertRaises(Exception) as caught,
        ):
            transport.get("/items")
        self.assertEqual(caught.exception.failure_class, "rate_limited")
        self.assertEqual(
            caught.exception.failure_classes, ("rate_limited", "budget_exhausted")
        )
        self.assertTrue(transport.metrics()["budget_exhausted"])

    def test_retry_aggregation_keeps_primary_when_later_response_is_malformed(
        self,
    ) -> None:
        error = HTTPError(
            "https://example.test/items",
            429,
            "rate limited",
            {"Retry-After": "0"},
            BytesIO(b"rate limited"),
        )

        class InvalidJsonResponse:
            status = 200

            def __init__(self) -> None:
                self.headers: dict[str, str] = {}

            def __enter__(self) -> Self:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, size: int = -1) -> bytes:
                body = b"not-json"
                return body if size < 0 else body[:size]

        transport = UrllibTransport(
            "https://example.test",
            max_requests=3,
            max_retries=1,
            retry_backoff=0,
            retry_jitter=0,
            sleep_fn=lambda _: None,
        )
        with (
            patch(
                "git_evidence.providers.transport.urlopen",
                side_effect=[error, InvalidJsonResponse()],
            ),
            self.assertRaises(ApiError) as caught,
        ):
            transport.get("/items")
        self.assertEqual(caught.exception.failure_class, "rate_limited")
        self.assertEqual(
            caught.exception.failure_classes,
            ("rate_limited", "malformed_response"),
        )
        self.assertEqual(caught.exception.attempts, 2)

    def test_malformed_later_pagination_target_keeps_accepted_page(self) -> None:
        transport = github_transport()
        issues_path = "/repos/example/project/issues"
        next_url = "https://api.github.com/repos/example/project/issues?page=2"
        first = transport.responses[issues_path][0]
        transport.responses[issues_path] = [
            ApiResponse(
                "https://api.github.com/repos/example/project/issues?page=1",
                200,
                {"Link": f'<{next_url}>; rel="next"'},
                first.body,
            )
        ]
        transport.responses[next_url] = [
            ApiResponse(
                "https://api.github.com/repos/example/project/issues?page=%FF",
                200,
                {},
                [],
            )
        ]

        bundle = GitHubProvider(transport).collect(request_for("github", "github.com"))
        self.assertEqual(len(bundle["work_items"]), 1)
        observation = next(
            item
            for item in bundle["coverage"]["observations"]
            if item["source"] == "work_items"
        )
        self.assertEqual(observation["status"], "incomplete")
        self.assertIn("malformed_response", json.dumps(observation["diagnostics"]))

    def test_commit_association_rejects_bad_candidates_and_keeps_valid_siblings(
        self,
    ) -> None:
        github = github_transport()
        github.responses[
            "/repos/example/project/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/pulls"
        ][0].body.extend([{"number": {"not": "a number"}}, {"number": 7}])
        github_provider = GitHubProvider(github)
        target = request_for("github", "github.com").repositories[0]
        candidates, result = github_provider._commit_change_request_candidates(
            target, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        self.assertEqual(
            candidates[-1], "change_request:github:github.com:example/project:7"
        )
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.diagnostics["failure_class"], "malformed_response")
        self.assertEqual(result.diagnostics["dropped_count"], 1)

        gitlab = gitlab_transport()
        gitlab.responses[
            "/projects/example%2Fproject/repository/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/merge_requests"
        ][0].body.extend([{"iid": {"not": "an iid"}}, {"iid": 8}])
        gitlab_provider = GitLabProvider(gitlab)
        target = request_for("gitlab", "gitlab.com").repositories[0]
        candidates, result = gitlab_provider._commit_change_request_candidates(
            target, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        self.assertEqual(
            candidates[-1], "change_request:gitlab:gitlab.com:example/project:8"
        )
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.diagnostics["failure_class"], "malformed_response")
        self.assertEqual(result.diagnostics["dropped_count"], 1)

    def test_same_group_duplicate_records_mark_source_incomplete(self) -> None:
        transport = github_transport()
        issues = transport.responses["/repos/example/project/issues"][0].body
        issues.append(deepcopy(issues[0]))
        bundle = GitHubProvider(transport).collect(request_for("github", "github.com"))
        work_item_observation = next(
            item
            for item in bundle["coverage"]["observations"]
            if item["source"] == "work_items"
        )
        self.assertEqual(work_item_observation["status"], "incomplete")
        self.assertEqual(
            work_item_observation["diagnostics"]["failure_class"], "malformed_response"
        )
        self.assertEqual(work_item_observation["diagnostics"]["duplicate_count"], 1)
        self.assertFalse(bundle["coverage"]["render_eligible"])
        self.assertEqual(
            len(bundle["work_items"]),
            len({item["id"] for item in bundle["work_items"]}),
        )

    def test_duplicate_change_request_blocks_both_core_event_surfaces(self) -> None:
        transport = github_transport()
        pulls = transport.responses["/repos/example/project/pulls"][0].body
        pulls.append(deepcopy(pulls[0]))
        bundle = GitHubProvider(transport).collect(request_for("github", "github.com"))
        observations = {
            item["source"]: item for item in bundle["coverage"]["observations"]
        }
        for source in (
            "change_request_observations",
            "change_request_merges",
        ):
            self.assertEqual(observations[source]["status"], "incomplete")
            self.assertEqual(
                observations[source]["diagnostics"]["failure_class"],
                "malformed_response",
            )
        self.assertFalse(bundle["coverage"]["render_eligible"])

    def test_collect_config_validates_direct_library_entry(self) -> None:
        config = {
            "window": {"start": WINDOW_END, "end": WINDOW_START, "timezone": "UTC"},
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
        called = False

        def factory(*args: object) -> object:
            nonlocal called
            called = True
            return object()

        with self.assertRaises(TypeError):
            collect_config(config, provider_factory=factory)
        self.assertFalse(called)

    def test_naive_provider_timestamps_are_not_accepted(self) -> None:
        self.assertIsNone(parse_timestamp("2026-07-28T08:00:00"))
        request = request_for("github", "github.com")
        self.assertTrue(
            in_window_or_malformed(
                {"occurred_at": "2026-07-28T08:00:00"}, request, "occurred_at"
            )
        )
        transport = github_transport()
        transport.responses["/repos/example/project/issues"][0].body[0][
            "created_at"
        ] = "2026-07-28T08:00:00Z"
        transport.responses["/repos/example/project/issues"][0].body[0][
            "updated_at"
        ] = "2026-07-01T08:00:00Z"
        bundle = GitHubProvider(transport).collect(request)
        self.assertEqual(bundle["work_items"], [])

    def test_runtime_and_transport_budgets_are_finite_and_bounded(self) -> None:
        base = {
            "window": {"start": WINDOW_START, "end": WINDOW_END, "timezone": "UTC"},
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
                config = deepcopy(base)
                config["providers"]["public-github"]["transport"] = {key: value}
                validate_collection_config(config)
        with self.assertRaises(ConfigError):
            config = deepcopy(base)
            config["providers"]["public-github"]["cache"] = {"ttl_seconds": 86_401}
            validate_collection_config(config)
        with self.assertRaises(ConfigError):
            config = deepcopy(base)
            config["providers"]["public-github"]["cache"] = {"max_entries": 10_001}
            validate_collection_config(config)
        with self.assertRaises(ValueError):
            UrllibTransport("https://example.test", timeout=301)
        with self.assertRaises(ValueError):
            UrllibTransport("https://example.test", max_retries=11)
        with self.assertRaises(ValueError):
            UrllibTransport("https://example.test", max_requests=10_001)


if __name__ == "__main__":
    unittest.main()
