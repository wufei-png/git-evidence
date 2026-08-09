from __future__ import annotations

import json
import sys
import unittest
from copy import deepcopy
from io import BytesIO, StringIO
from pathlib import Path
from typing import Self
from unittest.mock import patch
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from git_evidence.cli import main as cli_main
from git_evidence.collect import collect_config
from git_evidence.config import (
    ConfigError,
    load_collection_config,
    validate_collection_config,
)
from git_evidence.identity import compute_plan_id
from git_evidence.model import load_bundle
from git_evidence.privacy import PrivacyError
from git_evidence.providers import (
    CollectionRequest,
    GiteeProvider,
    GitHubProvider,
    GitLabProvider,
    RepositoryTarget,
    provider_catalog,
)
from git_evidence.providers.base import (
    ProviderNotReady,
    git_object_id_algorithm,
    merge_capability_status,
)
from git_evidence.providers.resource_base import (
    api_error_diagnostics,
    merge_diagnostics,
)
from git_evidence.providers.transport import (
    ApiError,
    ApiResponse,
    MappingTransport,
    ResponseShapeError,
    UrllibTransport,
    failure_class_for_status,
    paginate,
)
from git_evidence.render import render_bundle
from git_evidence.validation import (
    ValidationIssue,
    compute_render_eligibility,
    recompute_render_eligibility,
    validate_bundle,
    validate_provider_fragment,
)

FIXTURE = ROOT / "fixtures" / "example_bundle.json"
WINDOW_START = "2026-07-27T00:00:00Z"
WINDOW_END = "2026-08-03T00:00:00Z"
EVENT_TIME = "2026-07-30T12:00:00Z"


def validate_output(value: dict[str, object]) -> list[ValidationIssue]:
    if value.get("fragment_version") == "0.3":
        return validate_provider_fragment(value)
    return validate_bundle(value)


def response(
    path: str, body: object, headers: dict[str, str] | None = None
) -> ApiResponse:
    return ApiResponse(path, 200, headers or {}, body)


def provider_fixture(name: str) -> dict[str, object]:
    path = ROOT / "fixtures" / "provider_contract" / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def rewrite_transport_urls(
    transport: MappingTransport, source: str, replacement: str
) -> None:
    def rewrite(value: object) -> object:
        if isinstance(value, str):
            return value.replace(source, replacement)
        if isinstance(value, list):
            for index, child in enumerate(value):
                value[index] = rewrite(child)
            return value
        if isinstance(value, dict):
            for key, child in value.items():
                value[key] = rewrite(child)
            return value
        return value

    for responses in transport.responses.values():
        for recorded in responses:
            rewrite(recorded.body)


class FakeHttpResponse:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.status = 200
        self.headers = headers or {}
        self._body = body

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]


def request_for(
    provider: str,
    instance: str,
    *,
    include_activity_api: bool = False,
    actor_ids: tuple[str, ...] = (),
) -> CollectionRequest:
    target = RepositoryTarget(provider, instance, "example", "project")
    return CollectionRequest(
        provider_kind=provider,
        instance=instance,
        repositories=(target,),
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        timezone="UTC",
        include_activity_api=include_activity_api,
        actor_ids=actor_ids,
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
            f"{root}/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/pulls": response(
                "", fixture["commit_pulls"]["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            ),
            f"{root}/commits/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/pulls": response(
                "", fixture["commit_pulls"]["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
            ),
            f"{root}/commits/cccccccccccccccccccccccccccccccccccccccc/pulls": response(
                "", fixture["commit_pulls"]["cccccccccccccccccccccccccccccccccccccccc"]
            ),
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
            f"{root}/merge_requests/2/notes": response(
                "", fixture["merge_request_notes"]["2"]
            ),
            f"{root}/repository/commits": response("", fixture["commits"]),
            f"{root}/repository/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/merge_requests": response(
                "",
                fixture["commit_merge_requests"][
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ],
            ),
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
            f"{root}/pulls/2/comments": response("", fixture["issue_comments"]["2"]),
            f"{root}/commits": response("", fixture["commits"]),
            f"{root}/releases": response("", fixture["releases"]),
        }
    )


class ContractTests(unittest.TestCase):
    def test_public_fixture_is_render_eligible(self) -> None:
        bundle = load_bundle(FIXTURE)
        self.assertEqual(validate_output(bundle), [])

    def test_publication_decision_is_authoritatively_recomputed(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["interactions"][0]["subject_id"] = "work_item:missing"
        bundle["coverage"]["render_eligible"] = True
        self.assertFalse(compute_render_eligibility(bundle))
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("interaction.subject_missing", codes)
        self.assertIn("coverage.render_mismatch", codes)
        self.assertFalse(recompute_render_eligibility(bundle))
        self.assertFalse(bundle["coverage"]["render_eligible"])

    def test_validation_issues_are_structured_for_automation(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["invocation"].pop("id")
        issue = next(
            item for item in validate_output(bundle) if item.code == "schema.required"
        )
        self.assertEqual(
            set(issue.as_dict()),
            {"code", "severity", "path", "scope", "message", "remediation"},
        )
        self.assertEqual(issue.severity, "error")
        self.assertTrue(issue.path.startswith("$"))
        self.assertTrue(issue.remediation)

    def test_capability_and_revision_contracts_are_conservative(self) -> None:
        self.assertEqual(
            merge_capability_status(
                merge_capability_status(None, "incomplete"), "supported"
            ),
            "incomplete",
        )
        self.assertEqual(
            merge_capability_status(
                merge_capability_status(None, "supported"), "incomplete"
            ),
            "incomplete",
        )
        self.assertEqual(git_object_id_algorithm("a" * 40), "sha1")
        self.assertEqual(git_object_id_algorithm("b" * 64), "sha256")
        self.assertIsNone(git_object_id_algorithm("abc123"))
        self.assertIsNone(git_object_id_algorithm(f" {'a' * 40} "))

        bundle = load_bundle(FIXTURE)
        bundle["providers"][0]["capabilities"]["invented"] = "supported"
        self.assertIn(
            "coverage.capability_source",
            {issue.code for issue in validate_output(bundle)},
        )

    def test_typed_blocker_must_resolve_to_its_observation(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["coverage"]["fatal"] = [
            {
                "code": "required_source_incomplete",
                "provider": "github",
                "instance": "github.com",
                "repository": "repo:github:github.com:example/missing",
                "source": "commits",
                "status": "incomplete",
            }
        ]
        bundle["coverage"]["render_eligible"] = False
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("coverage.fatal_scope", codes)
        self.assertIn("coverage.fatal_observation", codes)

    def test_optional_coverage_warning_is_required_by_the_machine_contract(
        self,
    ) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["coverage"]["warnings"] = []
        self.assertIn(
            "coverage.warning_missing",
            {issue.code for issue in validate_output(bundle)},
        )
        report = render_bundle(load_bundle(FIXTURE))
        self.assertIn("### Coverage warnings", report)
        self.assertIn("optional\\_coverage\\_warning", report)
        self.assertIn(r"provider=provider:github:github\.com", report)
        self.assertIn(r"repository=repo:github:github\.com:example/project", report)

    def test_invocation_id_must_be_a_non_empty_string(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["invocation"].pop("id")
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("schema.required", codes)

    def test_occurred_at_uses_half_open_run_window(self) -> None:
        bundle = load_bundle(FIXTURE)
        assertion = bundle["assertions"][0]
        subject = next(
            item
            for item in bundle["change_requests"]
            if item["id"] == assertion["subject_id"]
        )
        subject_time_field = (
            "merged_at"
            if assertion["predicate"] == "change_request.merged.v1"
            else "occurred_at"
        )
        assertion["occurred_at"] = WINDOW_START
        subject[subject_time_field] = WINDOW_START
        recompute_render_eligibility(bundle)
        self.assertEqual(validate_output(bundle), [])

        assertion["occurred_at"] = WINDOW_END
        subject[subject_time_field] = WINDOW_END
        recompute_render_eligibility(bundle)
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("entity.timestamp_window", codes)
        with self.assertRaises(ValueError):
            render_bundle(bundle)

    def test_fact_evidence_subject_must_match_fact_kind_and_repository(self) -> None:
        bundle = load_bundle(FIXTURE)
        commit_evidence = next(
            evidence
            for evidence in bundle["evidence"]
            if evidence["subject_type"] == "commit"
        )
        bundle["assertions"][0]["evidence_ids"] = [commit_evidence["id"]]
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("assertion.evidence_subject", codes)

    def test_required_sources_cannot_be_reduced_below_resource_contract(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["coverage"]["required_sources"] = ["repositories"]
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("coverage.required_source_contract", codes)
        with self.assertRaises(ValueError):
            render_bundle(bundle)

    def test_schema_shape_and_format_errors_are_fatal(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["assertions"] = {}
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("schema.type", codes)
        self.assertIn("collection.shape", codes)

        bundle = load_bundle(FIXTURE)
        bundle["plan"]["window"]["start"] = "2026-07-27"
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("schema.format", codes)

    def test_missing_fact_evidence_is_fatal(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["assertions"][0]["evidence_ids"] = []
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("assertion.evidence", codes)

    def test_ref_change_commit_reference_must_resolve(self) -> None:
        bundle = GitHubProvider(github_transport()).collect(
            request_for("github", "github.com", include_activity_api=True)
        )
        bundle["ref_changes"][0]["commit_ids"] = ["commit:missing"]
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("ref_change.commit_ref", codes)

    def test_required_source_failure_blocks_publication(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["coverage"]["observations"][0]["status"] = "incomplete"
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("coverage.required_incomplete", codes)
        with self.assertRaises(ValueError):
            render_bundle(bundle)

    def test_coverage_is_required_for_each_allowlisted_repository(self) -> None:
        bundle = load_bundle(FIXTURE)
        second_repository = "repo:github:github.com:example/second-project"
        bundle["plan"]["scope"]["repositories"].append(second_repository)
        bundle["repositories"].append(
            {
                "id": second_repository,
                "provider_id": "provider:github:github.com",
                "full_name": "example/second-project",
                "web_url": "https://github.com/example/second-project",
            }
        )
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("coverage.required_missing", codes)

    def test_entity_outside_allowlist_is_rejected(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["assertions"][0]["repository_id"] = (
            "repo:github:github.com:other/project"
        )
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("scope.entity_outside", codes)

    def test_scope_requires_repository_ownership_for_all_scoped_entities(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["assertions"][0].pop("repository_id", None)
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("assertion.repository", codes)

        bundle = load_bundle(FIXTURE)
        bundle["repositories"].append(
            {
                "id": "repo:github:github.com:other/project",
                "provider_id": "provider:github:github.com",
                "full_name": "other/project",
            }
        )
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("scope.entity_outside", codes)

    def test_required_sources_must_be_nonempty_known_unique_values(self) -> None:
        cases = (
            ([], "coverage.required_sources_empty"),
            (["not-a-source"], "coverage.required_source_unknown"),
            (["commits", "commits"], "coverage.required_sources_duplicate"),
        )
        for required_sources, expected_code in cases:
            with self.subTest(required_sources=required_sources):
                bundle = load_bundle(FIXTURE)
                bundle["coverage"]["required_sources"] = required_sources
                codes = {issue.code for issue in validate_output(bundle)}
                self.assertIn(expected_code, codes)

    def test_actor_allowlist_is_carried_and_narrows_attributed_records(self) -> None:
        bundle = GitHubProvider(github_transport()).collect(
            request_for(
                "github",
                "github.com",
                actor_ids=("actor:github:github.com:999",),
            )
        )
        self.assertEqual(bundle["scope"]["actors"], ["actor:github:github.com:999"])
        self.assertEqual(bundle["actors"], [])
        self.assertTrue(
            any(
                assertion["predicate"] == "release.observed.v1"
                for assertion in bundle["assertions"]
            )
        )
        self.assertTrue(all("actor_id" not in fact for fact in bundle["assertions"]))
        self.assertEqual(validate_output(bundle), [])

    def test_actor_filtered_parent_is_retained_only_as_interaction_structure(
        self,
    ) -> None:
        cases = (
            (
                "github",
                "github.com",
                GitHubProvider,
                github_transport,
                "/repos/example/project/issues",
                "user",
            ),
            (
                "gitlab",
                "gitlab.com",
                GitLabProvider,
                gitlab_transport,
                "/projects/example%2Fproject/issues",
                "author",
            ),
            (
                "gitee",
                "gitee.com",
                GiteeProvider,
                gitee_transport,
                "/repos/example/project/issues",
                "user",
            ),
        )
        for (
            kind,
            instance,
            provider_type,
            transport_factory,
            path,
            actor_field,
        ) in cases:
            with self.subTest(provider=kind):
                transport = transport_factory()
                transport.responses[path][0].body[0][actor_field] = {
                    "id": 8,
                    "login": "other-user",
                    "username": "other-user",
                }
                bundle = provider_type(transport).collect(
                    request_for(
                        kind,
                        instance,
                        actor_ids=(f"actor:{kind}:{instance}:7",),
                    )
                )
                interaction = next(
                    item
                    for item in bundle["interactions"]
                    if item["subject_type"] == "work_item"
                )
                subject = next(
                    item
                    for item in bundle["work_items"]
                    if item["id"] == interaction["subject_id"]
                )
                self.assertEqual(
                    set(subject),
                    {"id", "kind", "repository_id", "number"},
                )
                self.assertFalse(
                    any(
                        assertion["subject_id"] == subject["id"]
                        for assertion in bundle["assertions"]
                    )
                )
                self.assertEqual(validate_output(bundle), [])

    def test_actor_allowlist_and_references_are_enforced_during_validation(
        self,
    ) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["plan"]["scope"]["actors"] = ["actor:github:github.com:42"]
        bundle["assertions"][0]["actor_id"] = "actor:github:github.com:999"
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("scope.actor_outside", codes)
        self.assertIn("scope.actor_ref_missing", codes)

        bundle = load_bundle(FIXTURE)
        bundle["plan"]["scope"]["actors"] = ["actor:github:github.com:999"]
        codes = {issue.code for issue in validate_output(bundle)}
        self.assertIn("scope.actor_outside", codes)

    def test_profiles_render_offline(self) -> None:
        bundle = load_bundle(FIXTURE)
        for profile in (
            "project-first",
            "timeline",
            "release-focused",
            "actor-summary",
        ):
            report = render_bundle(bundle, profile=profile)
            self.assertIn("Engineering Activity Report", report)
            self.assertIn("github.com/example/project", report)
        release_report = render_bundle(bundle, profile="release-focused")
        self.assertEqual(release_report.count("## Releases and changes"), 1)
        self.assertIn("anonymous actor", render_bundle(bundle, profile="actor-summary"))

    def test_timeline_sorts_instants_and_groups_in_plan_timezone(self) -> None:
        bundle = load_bundle(FIXTURE)
        observed = [
            assertion
            for assertion in bundle["assertions"]
            if assertion["predicate"] == "commit.observed.v1"
        ]
        subjects = {item["id"]: item for item in bundle["commits"]}
        subjects[observed[0]["subject_id"]]["title"] = "Later instant"
        subjects[observed[1]["subject_id"]]["title"] = "Earlier instant"
        observed[0]["occurred_at"] = "2026-07-31T03:30:00Z"
        observed[1]["occurred_at"] = "2026-07-30T23:00:00Z"
        subjects[observed[0]["subject_id"]]["occurred_at"] = observed[0]["occurred_at"]
        subjects[observed[1]["subject_id"]]["occurred_at"] = observed[1]["occurred_at"]
        bundle["plan"]["window"]["timezone"] = "Asia/Tokyo"
        bundle["plan_id"] = compute_plan_id(bundle["plan"])
        recompute_render_eligibility(bundle)

        report = render_bundle(bundle, profile="timeline")
        self.assertLess(report.index("Earlier instant"), report.index("Later instant"))
        self.assertIn("### 2026-07-31", report)

    def test_entity_ids_may_contain_none_as_a_substring(self) -> None:
        transport = github_transport()
        release = transport.responses["/repos/example/project/releases"][0].body[0]
        release["id"] = "vNone"
        release["tag_name"] = "vNone"
        release["html_url"] = "https://github.com/example/project/releases/tag/vNone"
        bundle = GitHubProvider(transport).collect(request_for("github", "github.com"))
        self.assertEqual(validate_output(bundle), [])
        self.assertTrue(any("vNone" in release["id"] for release in bundle["releases"]))

    def test_renderer_only_displays_explicit_identity_map(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["actors"][0]["display_name"] = "Leaked bundle name"
        self.assertIn(
            "schema.additionalProperties",
            {issue.code for issue in validate_output(bundle)},
        )

        bundle = load_bundle(FIXTURE)
        anonymous = render_bundle(bundle, profile="actor-summary")
        self.assertNotIn("Leaked bundle name", anonymous)

        labeled = render_bundle(
            bundle,
            profile="actor-summary",
            display_actor_names=True,
            actor_labels={"actor:github:github.com:7": "Alice"},
        )
        self.assertIn("Alice", labeled)
        self.assertNotIn("Leaked bundle name", labeled)

        escaped = render_bundle(
            bundle,
            profile="actor-summary",
            display_actor_names=True,
            actor_labels={
                "actor:github:github.com:7": "<script>alert(1)</script> `raw`"
            },
        )
        self.assertNotIn("<script>", escaped)
        self.assertNotIn("`raw`", escaped)
        self.assertIn("&lt;script&gt;", escaped)

    def test_renderer_escapes_untrusted_subject_text(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["change_requests"][0]["title"] = (
            "<script>alert(1)</script> `raw` **bold** [link]"
        )
        recompute_render_eligibility(bundle)
        report = render_bundle(bundle)
        self.assertNotIn("<script>", report)
        self.assertNotIn("`raw`", report)
        self.assertNotIn("**bold**", report)
        self.assertNotIn("[link]", report)
        self.assertIn("&lt;script&gt;", report)

    def test_render_cli_reads_explicit_identity_map_from_config(self) -> None:
        temporary = ROOT / "tests" / ".tmp-render-config.toml"
        temporary.write_text(
            '[report]\nprofile = "actor-summary"\n'
            "display_actor_names = true\n"
            "[report.actor_labels]\n"
            '"actor:github:github.com:7" = "Alice"\n',
            encoding="utf-8",
        )
        output = StringIO()
        try:
            with patch("sys.stdout", output):
                self.assertEqual(
                    cli_main(["render", str(FIXTURE), "--config", str(temporary)]), 0
                )
        finally:
            temporary.unlink(missing_ok=True)
        self.assertIn("Alice", output.getvalue())

    def test_collect_cli_writes_invalid_diagnostic_bundle_before_failure(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["coverage"]["required_sources"] = ["repositories"]
        output_path = ROOT / "tests" / ".tmp-invalid-collect-bundle.json"
        output_path.unlink(missing_ok=True)
        stderr = StringIO()
        try:
            with (
                patch("git_evidence.cli.load_collection_config", return_value={}),
                patch("git_evidence.cli.collect_config", return_value=bundle),
                patch("sys.stderr", stderr),
            ):
                result = cli_main(
                    [
                        "collect",
                        "--config",
                        "ignored-config.toml",
                        "--output",
                        str(output_path),
                    ]
                )
            self.assertEqual(result, 1)
            self.assertTrue(output_path.exists())
            self.assertIn("coverage.required_source_contract", stderr.getvalue())
            codes = {issue.code for issue in validate_bundle(load_bundle(output_path))}
            self.assertIn("coverage.required_source_contract", codes)
        finally:
            output_path.unlink(missing_ok=True)

    def test_provider_catalog_exposes_three_contracts(self) -> None:
        self.assertEqual(
            [item.kind for item in provider_catalog()], ["gitee", "github", "gitlab"]
        )
        for descriptor in provider_catalog():
            self.assertIn("repositories", descriptor.resource_sources)
            self.assertIn("ref_changes", descriptor.activity_sources)
            self.assertEqual(descriptor.implementation_status, "experimental")

    def test_offline_bundle_validation_does_not_require_collector_registration(
        self,
    ) -> None:
        serialized = json.dumps(load_bundle(FIXTURE)).replace(
            ":github:github.com",
            ":forge:github.com",
        )
        bundle = json.loads(serialized)
        bundle["providers"][0]["kind"] = "forge"
        bundle["plan"]["providers"][0]["kind"] = "forge"
        bundle["plan_id"] = compute_plan_id(bundle["plan"])
        recompute_render_eligibility(bundle)
        self.assertEqual(validate_output(bundle), [])

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
                self.assertEqual(validate_output(bundle), [])
                self.assertEqual(bundle["coverage"]["render_eligible"], True)
                self.assertEqual(len(bundle["repositories"]), 1)
                self.assertGreaterEqual(len(bundle["assertions"]), 5)
                self.assertGreaterEqual(len(bundle["interactions"]), 1)
                self.assertTrue(
                    all(
                        item["subject_type"] in {"work_item", "change_request"}
                        and item["subject_id"]
                        in {
                            subject["id"]
                            for subject in (
                                bundle["work_items"] + bundle["change_requests"]
                            )
                        }
                        for item in bundle["interactions"]
                    )
                )
                self.assertTrue(
                    all(item["hash_algorithm"] == "sha1" for item in bundle["commits"])
                )
                self.assertEqual(
                    {
                        item["source"]
                        for item in bundle["coverage"]["observations"]
                        if item["source"] in {"activities", "ref_changes"}
                    },
                    {"activities", "ref_changes"},
                )
                self.assertTrue(
                    all(
                        item["status"] == "unavailable"
                        for item in bundle["coverage"]["observations"]
                        if item["source"] in {"activities", "ref_changes"}
                    )
                )
                self.assertEqual(
                    {warning["source"] for warning in bundle["coverage"]["warnings"]},
                    {"activities", "ref_changes"},
                )

    def test_native_item_repository_url_mismatch_is_malformed_for_all_providers(
        self,
    ) -> None:
        cases = (
            (
                "github",
                GitHubProvider,
                github_transport,
                "/repos/example/project/issues",
                (
                    ("html_url", "https://github.com/other/project/issues/1"),
                    ("url", "https://api.github.com/repos/other/project/issues/1"),
                    ("repository_url", "https://api.github.com/repos/other/project"),
                ),
            ),
            (
                "gitlab",
                GitLabProvider,
                gitlab_transport,
                "/projects/example%2Fproject/issues",
                (
                    ("web_url", "https://gitlab.com/other/project/-/issues/1"),
                    (
                        "url",
                        "https://gitlab.com/api/v4/projects/other%2Fproject/issues/1",
                    ),
                    (
                        "repository_url",
                        "https://gitlab.com/api/v4/projects/other%2Fproject",
                    ),
                    ("path_with_namespace", "other/project"),
                ),
            ),
            (
                "gitee",
                GiteeProvider,
                gitee_transport,
                "/repos/example/project/issues",
                (
                    ("html_url", "https://gitee.com/other/project/issues/1"),
                    ("url", "https://gitee.com/api/v5/repos/other/project/issues/1"),
                    ("repository_url", "https://gitee.com/api/v5/repos/other/project"),
                ),
            ),
        )
        for provider_kind, provider_type, transport_factory, path, fields in cases:
            for field, foreign_url in fields:
                with self.subTest(provider=provider_kind, field=field):
                    transport = transport_factory()
                    transport.responses[path][0].body[0][field] = foreign_url
                    bundle = provider_type(transport).collect(
                        request_for(provider_kind, f"{provider_kind}.com")
                    )
                    observation = next(
                        item
                        for item in bundle["coverage"]["observations"]
                        if item["source"] == "work_items"
                    )
                    self.assertEqual(observation["status"], "incomplete")
                    self.assertEqual(
                        observation["diagnostics"]["failure_class"],
                        "malformed_response",
                    )
                    self.assertFalse(bundle["coverage"]["render_eligible"])
                    self.assertNotIn(
                        foreign_url, {item.get("url") for item in bundle["evidence"]}
                    )

    def test_github_base_repository_identity_mismatch_is_malformed(self) -> None:
        transport = github_transport()
        for pull in transport.responses["/repos/example/project/pulls"][0].body:
            pull["base"] = {
                "repo": {
                    "full_name": "other/project",
                    "name": "project",
                    "owner": {"login": "other"},
                }
            }
        bundle = GitHubProvider(transport).collect(request_for("github", "github.com"))
        observation = next(
            item
            for item in bundle["coverage"]["observations"]
            if item["source"] == "change_request_observations"
        )
        self.assertEqual(
            observation["diagnostics"]["failure_class"], "malformed_response"
        )
        self.assertFalse(bundle["change_requests"])

    def test_gitee_git_suffix_is_accepted_for_root_and_native_urls(self) -> None:
        transport = gitee_transport()
        transport.responses["/repos/example/project"][0].body["html_url"] = (
            "https://gitee.com/example/project.git"
        )
        transport.responses["/repos/example/project/issues"][0].body[0]["html_url"] = (
            "https://gitee.com/example/project.git/issues/1"
        )
        bundle = GiteeProvider(transport).collect(request_for("gitee", "gitee.com"))

        self.assertEqual(validate_output(bundle), [])
        self.assertTrue(bundle["coverage"]["render_eligible"])
        self.assertEqual(
            bundle["repositories"][0]["web_url"],
            "https://gitee.com/example/project.git",
        )
        self.assertEqual(
            next(item for item in bundle["work_items"] if item["number"] == 1)[
                "web_url"
            ],
            "https://gitee.com/example/project.git/issues/1",
        )

    def test_github_pull_self_link_href_mapping_is_repository_identity_url(
        self,
    ) -> None:
        transport = github_transport()
        transport.responses["/repos/example/project/pulls"][0].body[0]["_links"] = {
            "self": {"href": "https://api.github.com/repos/example/project/pulls/2"}
        }
        bundle = GitHubProvider(transport).collect(request_for("github", "github.com"))

        self.assertEqual(validate_output(bundle), [])
        self.assertTrue(bundle["coverage"]["render_eligible"])
        self.assertIn(2, {item["number"] for item in bundle["change_requests"]})

    def test_root_2xx_non_object_is_malformed_for_all_providers(self) -> None:
        cases = (
            ("github", GitHubProvider, github_transport, "/repos/example/project"),
            ("gitlab", GitLabProvider, gitlab_transport, "/projects/example%2Fproject"),
            ("gitee", GiteeProvider, gitee_transport, "/repos/example/project"),
        )
        for provider_kind, provider_type, transport_factory, path in cases:
            with self.subTest(provider=provider_kind):
                transport = transport_factory()
                recorded = transport.responses[path][0]
                transport.responses[path] = [
                    ApiResponse(
                        recorded.url, recorded.status_code, recorded.headers, []
                    )
                ]
                bundle = provider_type(transport).collect(
                    request_for(provider_kind, f"{provider_kind}.com")
                )
                repository_observation = next(
                    item
                    for item in bundle["coverage"]["observations"]
                    if item["source"] == "repositories"
                )
                self.assertEqual(
                    repository_observation["diagnostics"]["failure_class"],
                    "malformed_response",
                )
                self.assertFalse(bundle["coverage"]["render_eligible"])
                self.assertEqual(bundle["repositories"], [])

    def test_gitlab_root_numeric_self_link_is_not_repository_identity_url(self) -> None:
        transport = gitlab_transport()
        rewrite_transport_urls(transport, "https://gitlab.com", "https://jihulab.com")
        transport.responses["/projects/example%2Fproject"][0].body["_links"] = {
            "self": {"href": "https://jihulab.com/api/v4/projects/358282"}
        }
        bundle = GitLabProvider(transport, instance="jihulab.com").collect(
            request_for("gitlab", "jihulab.com")
        )

        self.assertEqual(validate_output(bundle), [])
        self.assertTrue(bundle["coverage"]["render_eligible"])
        self.assertEqual(len(bundle["repositories"]), 1)
        self.assertTrue(
            all(
                item["status"] == "supported"
                for item in bundle["coverage"]["observations"]
                if item["source"]
                in {
                    "repositories",
                    "work_items",
                    "change_request_observations",
                    "change_request_merges",
                    "commits",
                    "releases",
                    "interactions",
                }
            )
        )

    def test_gitee_pull_request_query_uses_supported_parameters(self) -> None:
        transport = gitee_transport()
        bundle = GiteeProvider(transport).collect(request_for("gitee", "gitee.com"))
        self.assertEqual(validate_output(bundle), [])
        pull_calls = [
            params
            for path, params in transport.calls
            if path == "/repos/example/project/pulls"
        ]
        self.assertTrue(pull_calls)
        self.assertNotIn("sort", dict(pull_calls[0]))
        self.assertNotIn("direction", dict(pull_calls[0]))
        paths = [path for path, _ in transport.calls]
        self.assertIn("/repos/example/project/pulls/2/comments", paths)
        self.assertNotIn("/repos/example/project/issues/2/comments", paths)

    def test_gitlab_merge_in_window_is_not_hidden_by_later_update(self) -> None:
        transport = gitlab_transport()
        merge_path = "/projects/example%2Fproject/merge_requests"
        transport.responses[merge_path][0].body[0]["updated_at"] = (
            "2026-08-04T12:00:00Z"
        )
        bundle = GitLabProvider(transport).collect(request_for("gitlab", "gitlab.com"))
        params = next(params for path, params in transport.calls if path == merge_path)
        self.assertNotIn("updated_before", dict(params))
        merged = next(
            item for item in bundle["change_requests"] if item["state"] == "merged"
        )
        self.assertTrue(
            any(
                assertion["subject_id"] == merged["id"]
                and assertion["predicate"] == "change_request.merged.v1"
                for assertion in bundle["assertions"]
            )
        )

    def test_provider_coverage_preserves_rate_limit_diagnostics_from_nested_requests(
        self,
    ) -> None:
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
            {
                "rate_limit": {
                    "x-ratelimit-remaining": "0",
                    "x-ratelimit-reset": "123",
                },
                "pagination": {
                    "complete": True,
                    "outcome": "link_exhausted",
                },
            },
        )

    def test_optional_activity_produces_explicit_ref_evidence_and_conservative_association(
        self,
    ) -> None:
        github_bundle = GitHubProvider(github_transport()).collect(
            request_for("github", "github.com", include_activity_api=True)
        )
        self.assertEqual(validate_output(github_bundle), [])
        github_ref = github_bundle["ref_changes"][0]
        self.assertEqual(github_ref["change_association"], "linked")
        self.assertEqual(
            github_ref["change_request_ids"],
            ["change_request:github:github.com:example/project:2"],
        )
        self.assertEqual(
            github_ref["commit_ids"],
            [
                "commit:github:github.com:example/project:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ],
        )
        self.assertEqual(
            {item["change_association"] for item in github_bundle["ref_changes"]},
            {"linked", "unlinked", "ambiguous"},
        )
        ambiguous_ref = next(
            item
            for item in github_bundle["ref_changes"]
            if item["change_association"] == "ambiguous"
        )
        self.assertEqual(
            ambiguous_ref["change_request_ids"],
            [
                "change_request:github:github.com:example/project:2",
                "change_request:github:github.com:example/project:3",
            ],
        )
        self.assertEqual(
            {
                item["status"]
                for item in github_bundle["coverage"]["observations"]
                if item["source"] == "ref_changes"
            },
            {"incomplete"},
        )

        gitlab_activity_transport = gitlab_transport()
        gitlab_bundle = GitLabProvider(gitlab_activity_transport).collect(
            request_for("gitlab", "gitlab.com", include_activity_api=True)
        )
        self.assertEqual(validate_output(gitlab_bundle), [])
        event_calls = [
            params
            for path, params in gitlab_activity_transport.calls
            if path == "/projects/example%2Fproject/events"
        ]
        self.assertTrue(event_calls)
        self.assertEqual(dict(event_calls[0])["after"], "2026-07-26")
        self.assertEqual(dict(event_calls[0])["before"], "2026-08-03")
        self.assertEqual(
            gitlab_bundle["ref_changes"][0]["change_association"], "linked"
        )
        self.assertEqual(
            gitlab_bundle["ref_changes"][0]["change_request_ids"],
            ["change_request:gitlab:gitlab.com:example/project:2"],
        )
        self.assertTrue(
            any(item.get("ref") is None for item in gitlab_bundle["ref_changes"])
        )
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
        self.assertEqual(validate_output(gitee_bundle), [])
        self.assertEqual(gitee_bundle["ref_changes"], [])
        self.assertTrue(
            all(
                item["status"] == "unsupported"
                for item in gitee_bundle["coverage"]["observations"]
                if item["source"] in {"activities", "ref_changes"}
            )
        )

    def test_partial_commit_association_is_unknown_even_with_multiple_candidates(
        self,
    ) -> None:
        transport = github_transport()
        transport.responses["/repos/example/project/events"][0].body.append(
            {
                "id": "event-partial",
                "type": "PushEvent",
                "created_at": EVENT_TIME,
                "actor": {"id": 7, "login": "synthetic-user"},
                "payload": {
                    "ref": "refs/heads/partial",
                    "size": 2,
                    "commits": [
                        {"sha": "cccccccccccccccccccccccccccccccccccccccc"},
                        {"sha": "missing-sha"},
                    ],
                },
            }
        )
        bundle = GitHubProvider(transport).collect(
            request_for("github", "github.com", include_activity_api=True)
        )
        partial = next(
            item
            for item in bundle["ref_changes"]
            if item["id"].endswith(":event-partial")
        )
        self.assertEqual(partial["change_association"], "unknown")

    def test_association_api_failure_keeps_ref_unknown_and_exposes_diagnostic(
        self,
    ) -> None:
        transport = github_transport()
        transport.responses.pop(
            "/repos/example/project/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/pulls"
        )
        bundle = GitHubProvider(transport).collect(
            request_for("github", "github.com", include_activity_api=True)
        )
        self.assertTrue(bundle["coverage"]["render_eligible"])
        self.assertTrue(
            any(
                failure["source"] == "ref_changes"
                and failure["failure_class"] == "fixture_missing"
                for failure in bundle["coverage"]["group_failures"]
            )
        )
        self.assertEqual(validate_output(bundle), [])
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
        self.assertTrue(
            any(
                warning["source"] == "ref_changes"
                and warning["failure_class"] == "fixture_missing"
                for warning in bundle["coverage"]["warnings"]
            )
        )
        self.assertTrue(bundle["coverage"]["warnings"])

    def test_optional_activity_permission_and_transport_failures_are_render_eligible_warnings(
        self,
    ) -> None:
        for status_code, failure_class in (
            (403, "permission_denied"),
            (503, "service_error"),
        ):
            with self.subTest(status_code=status_code):
                transport = github_transport()
                event_path = "/repos/example/project/events"
                transport.responses[event_path] = [
                    ApiResponse(event_path, status_code, {}, {"error": "blocked"})
                ]
                bundle = GitHubProvider(transport).collect(
                    request_for("github", "github.com", include_activity_api=True)
                )
                self.assertTrue(bundle["coverage"]["render_eligible"])
                self.assertEqual(validate_output(bundle), [])
                self.assertTrue(
                    all(
                        item["status"] == "supported"
                        for item in bundle["coverage"]["observations"]
                        if item["source"]
                        in {
                            "repositories",
                            "work_items",
                            "change_request_observations",
                            "change_request_merges",
                            "interactions",
                            "commits",
                            "releases",
                        }
                    )
                )
                self.assertTrue(
                    any(
                        warning["source"] == "activities"
                        and warning["failure_class"] == failure_class
                        for warning in bundle["coverage"]["warnings"]
                    )
                )

    def test_optional_activity_typed_exceptions_preserve_class_and_core_snapshot(
        self,
    ) -> None:
        cases = (
            (RuntimeError("synthetic activity failure"), "unexpected_error", True),
            (
                ProviderNotReady("activity collector is not ready"),
                "provider_not_ready",
                True,
            ),
            (
                PrivacyError("activity payload crossed the public boundary"),
                "privacy_violation",
                False,
            ),
        )
        for error, failure_class, render_eligible in cases:
            with self.subTest(failure_class=failure_class):
                provider = GitHubProvider(github_transport())
                with patch.object(provider, "_collect_activity", side_effect=error):
                    bundle = provider.collect(
                        request_for("github", "github.com", include_activity_api=True)
                    )
                self.assertGreater(len(bundle["repositories"]), 0)
                self.assertGreater(len(bundle["commits"]), 0)
                self.assertEqual(bundle["coverage"]["render_eligible"], render_eligible)
                warnings = bundle["coverage"]["warnings"]
                self.assertEqual(
                    {warning["source"] for warning in warnings},
                    {"activities", "ref_changes"},
                )
                self.assertTrue(
                    all(
                        warning["failure_class"] == failure_class
                        for warning in warnings
                    )
                )
                if render_eligible:
                    self.assertEqual(validate_output(bundle), [])
                else:
                    self.assertIn(
                        "coverage.render_blocked",
                        {issue.code for issue in validate_output(bundle)},
                    )

    def test_optional_activity_malformed_source_shape_preserves_core_snapshot(
        self,
    ) -> None:
        provider = GitHubProvider(github_transport())
        with patch.object(
            provider,
            "_collect_activity",
            return_value={"activities": None, "ref_changes": {"items": []}},
        ):
            bundle = provider.collect(
                request_for("github", "github.com", include_activity_api=True)
            )
        self.assertGreater(len(bundle["repositories"]), 0)
        self.assertGreater(len(bundle["commits"]), 0)
        self.assertTrue(bundle["coverage"]["render_eligible"])
        self.assertEqual(validate_output(bundle), [])
        self.assertEqual(
            {
                warning["source"]: warning["failure_class"]
                for warning in bundle["coverage"]["warnings"]
                if warning["source"] in {"activities", "ref_changes"}
            },
            {"activities": "malformed_response", "ref_changes": "malformed_response"},
        )

    def test_collect_cli_returns_render_eligible_for_optional_group_failure(
        self,
    ) -> None:
        bundle = load_bundle(FIXTURE)
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch("git_evidence.cli.load_collection_config", return_value={}),
            patch("git_evidence.cli.collect_config", return_value=bundle),
            patch("sys.stdout", stdout),
            patch("sys.stderr", stderr),
        ):
            result = cli_main(["collect", "--config", "ignored-config.toml"])
        self.assertEqual(result, 0)
        self.assertIn("render eligible with coverage warnings", stderr.getvalue())

    def test_collect_config_preserves_core_gate_when_optional_group_fails(self) -> None:
        transport = github_transport()
        transport.responses.pop(
            "/repos/example/project/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/pulls"
        )
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
                "public-github": {
                    "kind": "github",
                    "instance": "github.com",
                    "include_activity_api": True,
                }
            },
        }

        def factory(
            kind: str, instance: str, options: dict[str, object], token: str | None
        ) -> object:
            del kind, options, token
            return GitHubProvider(transport, instance=instance)

        bundle = collect_config(
            validate_collection_config(config), provider_factory=factory
        )
        self.assertTrue(bundle["coverage"]["render_eligible"])
        self.assertEqual(validate_output(bundle), [])
        self.assertTrue(
            any(
                item["source"] == "ref_changes"
                for item in bundle["coverage"]["warnings"]
            )
        )

    def test_commit_sha_mismatch_blocks_core_publication(self) -> None:
        transport = github_transport()
        provider = GitHubProvider(transport)
        target = request_for("github", "github.com").repositories[0]
        mismatched_commit = {
            "id": "commit:github:github.com:example/project:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "repository_id": target.canonical_id,
            "occurred_at": EVENT_TIME,
            "title": "Mismatched commit",
            "_native_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }
        with patch.object(
            provider, "_normalize_commit", return_value=mismatched_commit
        ):
            bundle = provider.collect(request_for("github", "github.com"))
        self.assertFalse(bundle["coverage"]["render_eligible"])
        self.assertTrue(
            any(
                issue.code == "coverage.render_blocked"
                for issue in validate_output(bundle)
            )
        )
        commits = next(
            item
            for item in bundle["coverage"]["observations"]
            if item["source"] == "commits"
        )
        self.assertEqual(commits["status"], "incomplete")
        self.assertEqual(commits["diagnostics"]["failure_class"], "malformed_response")
        self.assertTrue(bundle["coverage"]["fatal"])
        self.assertTrue(
            all(
                {
                    "code",
                    "provider",
                    "instance",
                    "repository",
                    "source",
                    "status",
                }
                <= blocker.keys()
                for blocker in bundle["coverage"]["fatal"]
            )
        )
        self.assertIn(
            "coverage.required_incomplete",
            {issue.code for issue in validate_output(bundle)},
        )
        self.assertEqual(bundle["commits"], [])

    def test_canonical_commit_sha_mismatch_is_not_render_eligible(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["commits"][0]["sha"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        self.assertIn(
            "commit.sha_mismatch", {issue.code for issue in validate_output(bundle)}
        )

    def test_canonical_commit_sentinel_sha_is_not_verifiable(self) -> None:
        for sentinel in ("None", "null", "unknown", "N/A"):
            with self.subTest(sentinel=sentinel):
                bundle = load_bundle(FIXTURE)
                commit = bundle["commits"][0]
                previous_id = commit["id"]
                commit_id = f"{previous_id.rsplit(':', 1)[0]}:{sentinel}"
                commit["id"] = commit_id
                commit["sha"] = sentinel
                for ref_change in bundle["ref_changes"]:
                    ref_change["commit_ids"] = [
                        commit_id if value == previous_id else value
                        for value in ref_change.get("commit_ids", [])
                    ]
                for evidence in bundle["evidence"]:
                    if evidence.get("subject_id") == previous_id:
                        evidence["subject_id"] = commit_id
                self.assertIn(
                    "commit.sha_unverifiable",
                    {issue.code for issue in validate_output(bundle)},
                )

    def test_repository_scoped_canonical_ids_bind_to_repository(self) -> None:
        for collection_key in (
            "work_items",
            "change_requests",
            "interactions",
            "commits",
            "ref_changes",
            "releases",
        ):
            with self.subTest(collection=collection_key):
                bundle = (
                    GitHubProvider(github_transport()).collect(
                        request_for("github", "github.com", include_activity_api=True)
                    )
                    if collection_key == "ref_changes"
                    else load_bundle(FIXTURE)
                )
                item = bundle[collection_key][0]
                item["id"] = item["id"].replace(
                    ":example/project:", ":other/project:", 1
                )
                self.assertIn(
                    "entity.repository_binding",
                    {issue.code for issue in validate_output(bundle)},
                )

    def test_assertions_remain_bound_to_the_allowlisted_repository(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["assertions"][0]["repository_id"] = (
            "repo:github:github.com:other/project"
        )
        self.assertIn(
            "scope.entity_outside", {issue.code for issue in validate_output(bundle)}
        )

    def test_repository_binding_handles_instance_path_and_colon_native_id(self) -> None:
        instance = "https://ghe.example/base"
        transport = github_transport()
        rewrite_transport_urls(transport, "https://github.com", instance)
        bundle = GitHubProvider(transport, instance=instance).collect(
            request_for("github", instance)
        )
        self.assertEqual(validate_output(bundle), [])
        self.assertTrue(
            any(":issue_comment:" in item["id"] for item in bundle["interactions"])
        )

    def test_collect_config_aggregates_multiple_provider_groups(self) -> None:
        transports = {
            "github": github_transport(),
            "gitlab": gitlab_transport(),
        }

        def factory(
            kind: str, instance: str, options: dict[str, object], token: str | None
        ) -> object:
            if kind == "github":
                return GitHubProvider(transports[kind], instance=instance)
            return GitLabProvider(transports[kind], instance=instance)

        config = {
            "window": {"start": WINDOW_START, "end": WINDOW_END, "timezone": "UTC"},
            "scope": {
                "repositories": [
                    {
                        "provider_ref": "public-github",
                        "owner": "example",
                        "name": "project",
                    },
                    {
                        "provider_ref": "public-gitlab",
                        "owner": "example",
                        "name": "project",
                    },
                ],
                "actors": ["actor:github:github.com:999"],
            },
            "providers": {
                "public-github": {"kind": "github", "instance": "github.com"},
                "public-gitlab": {"kind": "gitlab", "instance": "gitlab.com"},
            },
        }
        bundle = collect_config(
            validate_collection_config(config), provider_factory=factory
        )
        self.assertEqual(validate_output(bundle), [])
        self.assertEqual(len(bundle["providers"]), 2)
        self.assertEqual(len(bundle["repositories"]), 2)
        self.assertEqual(
            bundle["plan"]["scope"]["repositories"],
            [
                "repo:github:github.com:example/project",
                "repo:gitlab:gitlab.com:example/project",
            ],
        )
        self.assertEqual(
            bundle["plan"]["scope"]["actors"], ["actor:github:github.com:999"]
        )

    def test_collect_config_contains_malformed_bundle_failure_with_successful_sibling(
        self,
    ) -> None:
        transports = {"github": github_transport()}

        class MalformedProvider:
            def collect(self, request: CollectionRequest) -> dict[str, object]:
                del request
                return {"repositories": None}

        def factory(
            kind: str, instance: str, options: dict[str, object], token: str | None
        ) -> object:
            del options, token
            if kind == "github":
                return GitHubProvider(transports[kind], instance=instance)
            return MalformedProvider()

        config = {
            "window": {"start": WINDOW_START, "end": WINDOW_END, "timezone": "UTC"},
            "scope": {
                "repositories": [
                    {
                        "provider_ref": "public-github",
                        "owner": "example",
                        "name": "project",
                    },
                    {
                        "provider_ref": "public-gitlab",
                        "owner": "example",
                        "name": "project",
                    },
                ],
                "actors": [],
            },
            "providers": {
                "public-github": {"kind": "github", "instance": "github.com"},
                "public-gitlab": {"kind": "gitlab", "instance": "gitlab.com"},
            },
        }

        bundle = collect_config(
            validate_collection_config(config), provider_factory=factory
        )
        self.assertEqual(
            [item["id"] for item in bundle["repositories"]],
            ["repo:github:github.com:example/project"],
        )
        self.assertFalse(bundle["coverage"]["render_eligible"])
        self.assertEqual(
            {
                failure["failure_class"]
                for failure in bundle["coverage"]["group_failures"]
            },
            {"malformed_response"},
        )
        self.assertTrue(
            any(
                issue.code == "coverage.render_blocked"
                for issue in validate_output(bundle)
            )
        )

        stdout = StringIO()
        stderr = StringIO()
        with (
            patch("git_evidence.cli.load_collection_config", return_value={}),
            patch("git_evidence.cli.collect_config", return_value=bundle),
            patch("sys.stdout", stdout),
            patch("sys.stderr", stderr),
        ):
            result = cli_main(["collect", "--config", "ignored-config.toml"])
        self.assertEqual(result, 3)
        self.assertIn("coverage.render_blocked", stderr.getvalue())
        self.assertIn("one or more provider groups failed", stderr.getvalue())
        self.assertEqual(
            json.loads(stdout.getvalue())["coverage"]["render_eligible"], False
        )

    def test_pagination_does_not_call_a_full_page_complete(self) -> None:
        transport = MappingTransport(
            {"/items": response("", [{"id": index} for index in range(100)])}
        )
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
            "https://api.example.test/repos/example/project?access_token="
            + fixture_token,
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
            side_effect=[
                retry_error,
                FakeHttpResponse(b'{"ok": true}', {"X-RateLimit-Remaining": "3"}),
            ],
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
                with (
                    patch(
                        "git_evidence.providers.transport.urlopen",
                        side_effect=[error],
                    ),
                    self.assertRaises(ApiError) as caught,
                ):
                    transport.get("/repos/example/project")
                self.assertEqual(caught.exception.failure_class, expected_class)
                self.assertEqual(
                    api_error_diagnostics(caught.exception)["failure_class"],
                    expected_class,
                )
                self.assertEqual(caught.exception.status_code, status_code)

    def test_terminal_http_errors_preserve_only_safe_rate_limit_headers(self) -> None:
        error = HTTPError(
            "https://api.example.test/repos/example/project",
            429,
            "Too Many Requests",
            {
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "123",
                "Set-Cookie": "session=private",
            },
            BytesIO(b"rate limited"),
        )
        transport = UrllibTransport(
            "https://api.example.test", max_retries=0, retry_backoff=0
        )
        with (
            patch("git_evidence.providers.transport.urlopen", side_effect=[error]),
            self.assertRaises(ApiError) as caught,
        ):
            transport.get("/repos/example/project")
        self.assertEqual(
            caught.exception.rate_limit,
            {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "123"},
        )
        self.assertEqual(
            api_error_diagnostics(caught.exception)["rate_limit"],
            {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "123"},
        )

    def test_transport_converts_timeout_oserror_and_urlerror_to_network_diagnostics(
        self,
    ) -> None:
        token = "secret-token"
        failures = (
            TimeoutError("request timed out"),
            OSError("access_token=" + token),
            URLError("access_token=" + token),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                transport = UrllibTransport(
                    "https://api.example.test",
                    token,
                    token_param="access_token",
                    max_retries=0,
                    retry_backoff=0,
                )
                with (
                    patch(
                        "git_evidence.providers.transport.urlopen",
                        side_effect=[failure],
                    ),
                    self.assertRaises(ApiError) as caught,
                ):
                    transport.get("/repos/example/project")
                self.assertEqual(caught.exception.failure_class, "network_error")
                self.assertNotIn(token, str(caught.exception))

    def test_malformed_commit_items_are_skipped_and_mark_the_source_incomplete(
        self,
    ) -> None:
        github = github_transport()
        github.responses["/repos/example/project/commits"][0].body[0]["commit"][
            "message"
        ] = ""
        github_bundle = GitHubProvider(github).collect(
            request_for("github", "github.com")
        )
        github_coverage = next(
            item
            for item in github_bundle["coverage"]["observations"]
            if item["source"] == "commits"
        )
        self.assertEqual(github_coverage["status"], "incomplete")
        self.assertEqual(
            github_coverage["diagnostics"]["failure_class"], "malformed_response"
        )
        self.assertGreater(len(github_bundle["commits"]), 0)
        self.assertFalse(github_bundle["coverage"]["render_eligible"])

        gitlab = gitlab_transport()
        gitlab.responses["/projects/example%2Fproject/repository/commits"][
            0
        ].body.append(
            dict(
                gitlab.responses["/projects/example%2Fproject/repository/commits"][
                    0
                ].body[0]
            )
        )
        gitlab.responses["/projects/example%2Fproject/repository/commits"][0].body[0][
            "title"
        ] = ""
        gitlab.responses["/projects/example%2Fproject/repository/commits"][0].body[0][
            "message"
        ] = ""
        gitlab_bundle = GitLabProvider(gitlab).collect(
            request_for("gitlab", "gitlab.com")
        )
        gitlab_coverage = next(
            item
            for item in gitlab_bundle["coverage"]["observations"]
            if item["source"] == "commits"
        )
        self.assertEqual(gitlab_coverage["status"], "incomplete")
        self.assertEqual(
            gitlab_coverage["diagnostics"]["failure_class"], "malformed_response"
        )
        self.assertGreater(len(gitlab_bundle["commits"]), 0)

    def test_whitespace_padded_commit_id_isolated_at_provider_boundary(self) -> None:
        transport = github_transport()
        commits = transport.responses["/repos/example/project/commits"][0].body
        original_sha = commits[0]["sha"]
        commits[0]["sha"] = f" {original_sha} "
        bundle = GitHubProvider(transport).collect(request_for("github", "github.com"))
        observation = next(
            item
            for item in bundle["coverage"]["observations"]
            if item["source"] == "commits"
        )
        self.assertEqual(observation["status"], "incomplete")
        self.assertEqual(
            observation["diagnostics"]["failure_class"], "malformed_response"
        )
        self.assertTrue(bundle["commits"])
        self.assertNotIn(
            f" {original_sha} ", {item["sha"] for item in bundle["commits"]}
        )
        self.assertFalse(bundle["coverage"]["render_eligible"])

    def test_out_of_window_malformed_commits_do_not_block_the_source(self) -> None:
        github = github_transport()
        outside_github = deepcopy(
            github.responses["/repos/example/project/commits"][0].body[0]
        )
        outside_github["commit"]["message"] = ""
        outside_github["commit"]["committer"]["date"] = "2026-07-01T12:00:00Z"
        outside_github["commit"]["author"]["date"] = "2026-07-01T12:00:00Z"
        github.responses["/repos/example/project/commits"][0].body.append(
            outside_github
        )
        github_bundle = GitHubProvider(github).collect(
            request_for("github", "github.com")
        )
        github_coverage = next(
            item
            for item in github_bundle["coverage"]["observations"]
            if item["source"] == "commits"
        )
        self.assertEqual(github_coverage["status"], "supported")

        gitlab = gitlab_transport()
        outside_gitlab = deepcopy(
            gitlab.responses["/projects/example%2Fproject/repository/commits"][0].body[
                0
            ]
        )
        outside_gitlab["title"] = ""
        outside_gitlab["message"] = ""
        outside_gitlab["committed_date"] = "2026-07-01T12:00:00Z"
        gitlab.responses["/projects/example%2Fproject/repository/commits"][
            0
        ].body.append(outside_gitlab)
        gitlab_bundle = GitLabProvider(gitlab).collect(
            request_for("gitlab", "gitlab.com")
        )
        gitlab_coverage = next(
            item
            for item in gitlab_bundle["coverage"]["observations"]
            if item["source"] == "commits"
        )
        self.assertEqual(gitlab_coverage["status"], "supported")

    def test_custom_instance_urls_are_not_double_prefixed(self) -> None:
        cases = (
            ("github", "https://ghe.example", GitHubProvider, github_transport()),
            ("gitlab", "https://glt.example", GitLabProvider, gitlab_transport()),
            ("gitee", "https://gte.example", GiteeProvider, gitee_transport()),
        )
        roots = {
            "github": "/repos/example/project",
            "gitlab": "/projects/example%2Fproject",
            "gitee": "/repos/example/project",
        }
        for kind, instance, provider_type, transport in cases:
            with self.subTest(provider=kind):
                rewrite_transport_urls(transport, f"https://{kind}.com", instance)
                repository = transport.responses[roots[kind]][0].body
                repository["html_url" if kind != "gitlab" else "web_url"] = None
                provider = provider_type(transport, instance=instance)
                bundle = provider.collect(request_for(kind, instance))
                self.assertEqual(
                    bundle["repositories"][0]["web_url"],
                    f"{instance}/example/project",
                )
                self.assertNotIn(
                    "https://https://", bundle["repositories"][0]["web_url"]
                )

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
        merge_diagnostics(
            diagnostics, {"failure_class": "permission_denied", "status_code": 403}
        )
        self.assertEqual(diagnostics["failure_class"], "permission_denied")
        merge_diagnostics(
            diagnostics, {"failure_class": "rate_limited", "status_code": 429}
        )
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
            {
                "rate_limit": {
                    "x-ratelimit-remaining": "0",
                    "x-ratelimit-reset": "123",
                },
                "pagination": {
                    "complete": True,
                    "outcome": "documented_short_page",
                },
            },
        )

    def test_config_requires_explicit_allowlist_and_aware_window(self) -> None:
        config = load_collection_config(ROOT / "config.example.toml")
        self.assertEqual(config.repositories[0].target.provider_kind, "github")
        temporary = ROOT / "tests" / ".tmp-invalid-config.toml"
        try:
            temporary.write_text(
                "[window]\n"
                "start = 2026-07-27T00:00:00Z\n"
                "end = 2026-08-03T00:00:00Z\n"
                'timezone = "UTC"\n'
                "[scope]\n"
                "repositories = []\n"
                "[providers]\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_collection_config(temporary)
        finally:
            temporary.unlink(missing_ok=True)

    def test_config_rejects_unknown_provider(self) -> None:
        temporary = ROOT / "tests" / ".tmp-unknown-provider.toml"
        try:
            temporary.write_text(
                "[window]\n"
                "start = 2026-07-27T00:00:00Z\n"
                "end = 2026-08-03T00:00:00Z\n"
                'timezone = "UTC"\n'
                "[scope]\n"
                "[[scope.repositories]]\n"
                'provider_ref = "unknown"\n'
                'owner = "example"\n'
                'name = "project"\n'
                "[providers.unknown]\n"
                'kind = "unknown"\n'
                'instance = "example.invalid"\n',
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_collection_config(temporary)
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
