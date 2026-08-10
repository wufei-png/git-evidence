from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from git_evidence import __version__
from git_evidence.atomic_io import AtomicWriteError, atomic_write_text
from git_evidence.cli import main as cli_main
from git_evidence.model import load_bundle
from git_evidence.privacy import PrivacyError, sanitize_public_payload
from git_evidence.providers.base import (
    CollectionRequest,
    ProviderDescriptor,
    RepositoryTarget,
)
from git_evidence.providers.resource_base import BundleBuilder
from git_evidence.providers.transport import MappingTransport, UrllibTransport
from git_evidence.render import LABELS, render_bundle
from git_evidence.validation import (
    compute_render_eligibility,
    recompute_render_eligibility,
    validate_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "example_bundle.json"


class PrivacyBoundaryTests(unittest.TestCase):
    def test_high_confidence_secrets_and_malformed_urls_fail_closed(self) -> None:
        token = "configured/secret-value-123456"
        encoded = quote(token, safe="")
        for payload in (
            {"message": f"provider echoed {token}"},
            {"message": f"provider echoed {encoded}"},
            {"message": "Authorization: Bearer abcdefghijklmnop"},
            {"message": "-----BEGIN PRIVATE KEY-----"},
            {"web_url": "not an absolute URL"},
            {"web_url": "https://example.test/%FF"},
            {"web_url": "https://example.test/evidence#%FF"},
        ):
            with self.subTest(payload=payload), self.assertRaises(PrivacyError):
                sanitize_public_payload(payload, secret_values=(token,))

    def test_builder_scans_configured_secret_in_plain_text_fields(self) -> None:
        token = "configured-secret-value-123456"
        transport = MappingTransport({})
        transport.token = token
        target = RepositoryTarget("github", "github.com", "example", "project")
        request = CollectionRequest(
            provider_kind="github",
            instance="github.com",
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
        with self.assertRaises(PrivacyError):
            builder._add_entity(
                "work_items",
                {"id": "work_item:secret", "title": f"echo {quote(token, safe='')}"},
            )

        for url in (
            f"https://example.test/evidence/{token}",
            f"https://example.test/evidence?opaque={quote(token, safe='')}",
            f"https://example.test/evidence#opaque={quote(token, safe='')}",
        ):
            with self.subTest(url=url), self.assertRaises(PrivacyError):
                sanitize_public_payload(
                    {"web_url": url},
                    secret_values=(token,),
                )

    def test_bearer_security_prose_is_not_secret_material(self) -> None:
        payload = {"summary": "Fix bearer authentication and credential rotation docs"}
        self.assertEqual(sanitize_public_payload(payload), payload)

    def test_low_confidence_secret_text_warns_without_claiming_safety(self) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["change_requests"][0]["title"] = "rotation note token=possibly-redacted"
        recompute_render_eligibility(bundle)
        issues = validate_bundle(bundle)
        self.assertEqual({issue.severity for issue in issues}, {"warning"})
        self.assertTrue(compute_render_eligibility(bundle))
        report = render_bundle(bundle)
        self.assertIn("Validation warnings", report)
        self.assertIn("privacy\\.possible\\_secret\\_material", report)


class AtomicOutputTests(unittest.TestCase):
    def test_atomic_writer_uses_private_mode_and_preserves_previous_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "bundle.json"
            atomic_write_text(target, "first\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "first\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

            with (
                patch(
                    "git_evidence.atomic_io.os.replace",
                    side_effect=OSError("synthetic replace failure"),
                ),
                self.assertRaises(AtomicWriteError),
            ):
                atomic_write_text(target, "second\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "first\n")
            self.assertEqual(list(target.parent.glob(".bundle.json.*.tmp")), [])

    def test_cli_version_json_diagnostics_and_io_exit_are_stable(self) -> None:
        stdout = StringIO()
        with patch("sys.stdout", stdout), self.assertRaises(SystemExit) as version_exit:
            cli_main(["--version"])
        self.assertEqual(version_exit.exception.code, 0)
        self.assertIn(__version__, stdout.getvalue())

        with tempfile.TemporaryDirectory() as directory:
            bundle = load_bundle(FIXTURE)
            bundle["invocation"].pop("id")
            path = Path(directory) / "invalid.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                status = cli_main(
                    [
                        "validate",
                        str(path),
                        "--diagnostics-format",
                        "json",
                    ]
                )
            self.assertEqual(status, 1)
            diagnostics = json.loads(stdout.getvalue())
            self.assertEqual(diagnostics["status"], "invalid")
            self.assertTrue(diagnostics["issues"])
            self.assertEqual(
                set(diagnostics["issues"][0]),
                {"code", "severity", "path", "scope", "message", "remediation"},
            )

            valid = Path(directory) / "valid.json"
            valid.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                status = cli_main(
                    ["validate", str(valid), "--diagnostics-format", "json"]
                )
            self.assertEqual(status, 0)
            diagnostics = json.loads(stdout.getvalue())
            self.assertEqual(
                {key: diagnostics[key] for key in ("status", "issues")},
                {"status": "valid", "issues": []},
            )
            self.assertEqual(diagnostics["blocking_group_failure_count"], 0)

        stderr = StringIO()
        with (
            patch(
                "git_evidence.cli.atomic_write_text",
                side_effect=AtomicWriteError("synthetic output failure"),
            ),
            patch("sys.stderr", stderr),
        ):
            status = cli_main(
                [
                    "render",
                    str(FIXTURE),
                    "--output",
                    "/ignored/report.md",
                ]
            )
        self.assertEqual(status, 2)
        self.assertIn("synthetic output failure", stderr.getvalue())

    def test_cli_redacts_unknown_failures_behind_an_opaque_error_id(self) -> None:
        for diagnostics_format in ("text", "json"):
            with self.subTest(diagnostics_format=diagnostics_format):
                stderr = StringIO()
                argv = ["collect", "--config", "ignored.toml"]
                if diagnostics_format == "json":
                    argv.extend(
                        [
                            "--diagnostics-format",
                            "text",
                            "--diagnostics-format",
                            "json",
                        ]
                    )
                with (
                    patch(
                        "git_evidence.cli.load_collection_config",
                        side_effect=RuntimeError("synthetic internal secret"),
                    ),
                    patch(
                        "git_evidence.cli.secrets.token_hex",
                        return_value="0123456789abcdef",
                    ),
                    patch("sys.stderr", stderr),
                ):
                    status = cli_main(argv)
                self.assertEqual(status, 70)
                if diagnostics_format == "json":
                    self.assertEqual(
                        json.loads(stderr.getvalue()),
                        {
                            "status": "internal_failure",
                            "issues": [],
                            "error_id": "0123456789abcdef",
                        },
                    )
                else:
                    self.assertEqual(
                        stderr.getvalue(),
                        "ERROR: internal failure; error_id=0123456789abcdef\n",
                    )
                self.assertNotIn("synthetic internal secret", stderr.getvalue())

    def test_collect_json_diagnostics_are_single_documents_for_all_outcomes(
        self,
    ) -> None:
        render_eligible = load_bundle(FIXTURE)
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch("git_evidence.cli.load_collection_config", return_value={}),
            patch("git_evidence.cli.collect_config", return_value=render_eligible),
            patch("sys.stdout", stdout),
            patch("sys.stderr", stderr),
        ):
            status = cli_main(
                [
                    "collect",
                    "--config",
                    "ignored.toml",
                    "--diagnostics-format",
                    "json",
                ]
            )
        self.assertEqual(status, 0)
        diagnostics = json.loads(stderr.getvalue())
        self.assertEqual(diagnostics["status"], "render_eligible_with_warnings")
        self.assertEqual(diagnostics["issues"], [])
        self.assertEqual(
            json.loads(stdout.getvalue())["coverage"]["render_eligible"], True
        )

        failed = load_bundle(FIXTURE)
        failed["coverage"]["group_failures"] = [
            {
                "provider": "github",
                "instance": "github.com",
                "repository": failed["repositories"][0]["id"],
                "source": "commits",
                "failure_class": "service_error",
            }
        ]
        stderr = StringIO()
        with (
            patch("git_evidence.cli.load_collection_config", return_value={}),
            patch("git_evidence.cli.collect_config", return_value=failed),
            patch("sys.stdout", StringIO()),
            patch("sys.stderr", stderr),
        ):
            status = cli_main(
                [
                    "collect",
                    "--config",
                    "ignored.toml",
                    "--diagnostics-format",
                    "json",
                ]
            )
        self.assertEqual(status, 3)
        diagnostics = json.loads(stderr.getvalue())
        self.assertEqual(diagnostics["status"], "group_failure")
        self.assertEqual(diagnostics["group_failure_count"], 1)


class PaginationProofValidationTests(unittest.TestCase):
    def test_supported_paginated_sources_require_provider_specific_complete_proof(
        self,
    ) -> None:
        for mutation, expected_code in (
            (lambda item: item.pop("diagnostics"), "coverage.pagination_missing"),
            (
                lambda item: item.update(
                    diagnostics={
                        "pagination": {
                            "outcome": "max_pages_reached",
                            "complete": False,
                        }
                    }
                ),
                "coverage.pagination_supported_incomplete",
            ),
            (
                lambda item: item.update(
                    diagnostics={
                        "pagination": {
                            "outcome": "cursor_exhausted",
                            "complete": True,
                        }
                    }
                ),
                "coverage.pagination_provider_outcome",
            ),
        ):
            bundle = load_bundle(FIXTURE)
            work_items = next(
                item
                for item in bundle["coverage"]["observations"]
                if item["source"] == "work_items"
            )
            mutation(work_items)
            with self.subTest(expected_code=expected_code):
                self.assertIn(
                    expected_code,
                    {issue.code for issue in validate_bundle(bundle)},
                )


class CanaryLogBoundaryTests(unittest.TestCase):
    def test_failure_output_does_not_echo_repository_coordinates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin"
            binary.mkdir()
            stub = binary / "git-evidence"
            sensitive_repository = "repo:github:github.com:secret-owner/private-project"
            stub.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = collect ]; then\n'
                f"  echo 'required source failed for {sensitive_repository}' >&2\n"
                "  exit 3\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            stub.chmod(0o700)
            config = """\
[window]
start = 2026-08-01T00:00:00Z
end = 2026-08-02T00:00:00Z
timezone = "UTC"
[scope]
actors = []
[[scope.repositories]]
provider_ref = "live-github"
owner = "secret-owner"
name = "private-project"
[providers.live-github]
kind = "github"
instance = "github.com"
token_env = "LIVE_PROVIDER_TOKEN"
"""
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{binary}:{environment['PATH']}",
                    "PYTHONPATH": str(ROOT / "src"),
                    "RUNNER_TEMP": str(root),
                    "LIVE_CANARY_CONFIG_CONTENT": config,
                    "LIVE_EXPECTED_PROVIDER": "github",
                    "LIVE_ALLOWED_INSTANCES": "github.com",
                    "LIVE_PROVIDER_TOKEN": "fixture-token",
                }
            )
            result = subprocess.run(
                ["bash", str(ROOT / ".github/workflows/run-live-canary.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            combined = result.stdout + result.stderr
            self.assertEqual(result.returncode, 3)
            self.assertIn("CANARY_COLLECT: failed (exit 3)", combined)
            self.assertNotIn(sensitive_repository, combined)
            self.assertNotIn("secret-owner", combined)


class RenderingAndPackagingTests(unittest.TestCase):
    def test_visual_controls_are_rendered_visibly_and_actor_is_not_repeated(
        self,
    ) -> None:
        bundle = load_bundle(FIXTURE)
        bundle["change_requests"][0]["title"] = "safe\u202etxt\u200b"
        recompute_render_eligibility(bundle)
        report = render_bundle(
            bundle,
            profile="actor-summary",
            display_actor_names=True,
            actor_labels={bundle["actors"][0]["id"]: "Unique Actor Label"},
        )
        self.assertNotIn("\u202e", report)
        self.assertNotIn("\u200b", report)
        self.assertIn("U\\+202E", report)
        self.assertIn("U\\+200B", report)
        self.assertEqual(report.count("Unique Actor Label"), 1)

        # Localization strings are asserted directly because an intentionally
        # incomplete bundle must not be rendered.
        self.assertEqual(LABELS["zh-CN"]["no_coverage"], "没有覆盖观测。")
        self.assertEqual(LABELS["zh-CN"]["no_releases"], "没有已验证的版本或版本变更。")

    def test_user_agent_and_typing_marker_use_package_metadata(self) -> None:
        cursor = UrllibTransport("https://example.test").begin_get("/items")
        self.assertEqual(
            cursor.request.get_header("User-agent"),
            f"git-evidence/{__version__}",
        )
        self.assertTrue((ROOT / "src" / "git_evidence" / "py.typed").is_file())


if __name__ == "__main__":
    unittest.main()
