from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from git_evidence.atomic_io import AtomicWriteError
from git_evidence.cli import main as cli_main
from git_evidence.config import ConfigError
from git_evidence.model import load_bundle
from git_evidence.validation import recompute_render_eligibility

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "example_bundle.json"
SKILL = ROOT / "integrations" / "agent-skill" / "git-evidence"
RUNNER_PATH = SKILL / "scripts" / "run_git_evidence.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location(
        "git_evidence_agent_runner", RUNNER_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("could not load Agent Skill runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StructuredCliDiagnosticsTests(unittest.TestCase):
    def test_doctor_json_uses_stdout_for_success_and_config_failure(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch(
                "git_evidence.cli.load_collection_config",
                return_value=SimpleNamespace(repositories=(1, 2)),
            ),
            patch("sys.stdout", stdout),
            patch("sys.stderr", stderr),
        ):
            status = cli_main(
                [
                    "doctor",
                    "--config",
                    "ignored.toml",
                    "--diagnostics-format",
                    "json",
                ]
            )
        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {"status": "valid", "issues": [], "repository_count": 2},
        )
        self.assertEqual(stderr.getvalue(), "")

        stdout = StringIO()
        stderr = StringIO()
        with (
            patch(
                "git_evidence.cli.load_collection_config",
                side_effect=ConfigError("synthetic config failure"),
            ),
            patch("sys.stdout", stdout),
            patch("sys.stderr", stderr),
        ):
            status = cli_main(
                [
                    "doctor",
                    "--config",
                    "ignored.toml",
                    "--diagnostics-format",
                    "json",
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "config_error")
        self.assertEqual(stderr.getvalue(), "")

    def test_artifact_commands_keep_json_diagnostics_on_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.md"
            stdout = StringIO()
            stderr = StringIO()
            with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
                status = cli_main(
                    [
                        "render",
                        str(FIXTURE),
                        "--output",
                        str(report),
                        "--diagnostics-format",
                        "json",
                    ]
                )
            self.assertEqual(status, 0)
            self.assertTrue(report.exists())
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(json.loads(stderr.getvalue())["status"], "rendered")

        stderr = StringIO()
        with (
            patch(
                "git_evidence.cli.load_collection_config",
                side_effect=ConfigError("synthetic collection failure"),
            ),
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
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(stderr.getvalue())["status"], "collection_error")

    def test_render_json_reports_warnings_blockers_and_io_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            warning_bundle = load_bundle(FIXTURE)
            warning_bundle["change_requests"][0]["title"] = "token=possibly-redacted"
            recompute_render_eligibility(warning_bundle)
            warning_path = Path(directory) / "warning.json"
            warning_path.write_text(json.dumps(warning_bundle), encoding="utf-8")
            stderr = StringIO()
            with patch("sys.stderr", stderr):
                status = cli_main(
                    [
                        "render",
                        str(warning_path),
                        "--output",
                        str(Path(directory) / "warning.md"),
                        "--diagnostics-format",
                        "json",
                    ]
                )
            diagnostics = json.loads(stderr.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(diagnostics["status"], "rendered_with_warnings")
            self.assertTrue(diagnostics["issues"])

            invalid_bundle = load_bundle(FIXTURE)
            invalid_bundle["invocation"].pop("id")
            invalid_path = Path(directory) / "invalid.json"
            invalid_path.write_text(json.dumps(invalid_bundle), encoding="utf-8")
            output_path = Path(directory) / "blocked.md"
            stderr = StringIO()
            with patch("sys.stderr", stderr):
                status = cli_main(
                    [
                        "render",
                        str(invalid_path),
                        "--output",
                        str(output_path),
                        "--diagnostics-format",
                        "json",
                    ]
                )
            self.assertEqual(status, 1)
            self.assertEqual(json.loads(stderr.getvalue())["status"], "invalid")
            self.assertFalse(output_path.exists())

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
                    "--diagnostics-format",
                    "json",
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(stderr.getvalue())["status"], "io_error")

    def test_validate_input_error_is_json_on_stdout(self) -> None:
        stdout = StringIO()
        with patch("sys.stdout", stdout):
            status = cli_main(
                [
                    "validate",
                    "/missing/bundle.json",
                    "--diagnostics-format",
                    "json",
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "input_error")

    def test_collect_output_error_is_json_on_stderr(self) -> None:
        stderr = StringIO()
        with (
            patch("git_evidence.cli.load_collection_config", return_value={}),
            patch("git_evidence.cli.collect_config", return_value=load_bundle(FIXTURE)),
            patch(
                "git_evidence.cli.atomic_write_text",
                side_effect=AtomicWriteError("synthetic collect output failure"),
            ),
            patch("sys.stderr", stderr),
        ):
            status = cli_main(
                [
                    "collect",
                    "--config",
                    "ignored.toml",
                    "--output",
                    "/ignored/bundle.json",
                    "--diagnostics-format",
                    "json",
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(stderr.getvalue())["status"], "io_error")

    def test_internal_json_failures_follow_each_command_diagnostic_stream(self) -> None:
        cases = (
            (
                ["doctor", "--config", "ignored.toml", "--diagnostics-format", "json"],
                "git_evidence.cli.load_collection_config",
                "stdout",
            ),
            (
                ["validate", "ignored.json", "--diagnostics-format", "json"],
                "git_evidence.cli.load_bundle",
                "stdout",
            ),
            (
                ["collect", "--config", "ignored.toml", "--diagnostics-format", "json"],
                "git_evidence.cli.load_collection_config",
                "stderr",
            ),
            (
                ["render", "ignored.json", "--diagnostics-format", "json"],
                "git_evidence.cli.load_bundle",
                "stderr",
            ),
        )
        for argv, target, expected_stream in cases:
            with self.subTest(command=argv[0]):
                stdout = StringIO()
                stderr = StringIO()
                with (
                    patch(
                        target, side_effect=RuntimeError("synthetic internal secret")
                    ),
                    patch(
                        "git_evidence.cli.secrets.token_hex",
                        return_value="0123456789abcdef",
                    ),
                    patch("sys.stdout", stdout),
                    patch("sys.stderr", stderr),
                ):
                    status = cli_main(argv)
                self.assertEqual(status, 70)
                selected = stdout if expected_stream == "stdout" else stderr
                other = stderr if expected_stream == "stdout" else stdout
                diagnostics = json.loads(selected.getvalue())
                self.assertEqual(diagnostics["status"], "internal_failure")
                self.assertEqual(diagnostics["error_id"], "0123456789abcdef")
                self.assertEqual(other.getvalue(), "")


class AgentRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = _load_runner()

    def _success_process(
        self, command: list[str], **run_kwargs
    ) -> subprocess.CompletedProcess[bytes]:
        stage = command[1]
        stdout = ""
        stderr = ""
        if stage == "doctor":
            stdout = json.dumps(
                {"status": "valid", "issues": [], "repository_count": 1}
            )
        elif stage == "collect":
            output = Path(command[command.index("--output") + 1])
            output.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
            os.chmod(output, 0o600)
            warnings = load_bundle(FIXTURE)["coverage"]["warnings"]
            stderr = json.dumps(
                {
                    "status": "render_eligible_with_warnings",
                    "issues": [],
                    "group_failure_count": 0,
                    "blocking_group_failure_count": 0,
                    "coverage_warning_count": 2,
                    "group_failures": [],
                    "group_failures_truncated": 0,
                    "coverage_warnings": warnings,
                    "coverage_warnings_truncated": 0,
                }
            )
        elif stage == "validate":
            warnings = load_bundle(FIXTURE)["coverage"]["warnings"]
            stdout = json.dumps(
                {
                    "status": "valid",
                    "issues": [],
                    "group_failure_count": 0,
                    "blocking_group_failure_count": 0,
                    "coverage_warning_count": 2,
                    "group_failures": [],
                    "group_failures_truncated": 0,
                    "coverage_warnings": warnings,
                    "coverage_warnings_truncated": 0,
                }
            )
        elif stage == "render":
            output = Path(command[command.index("--output") + 1])
            output.write_text("# synthetic report\n", encoding="utf-8")
            os.chmod(output, 0o600)
            stderr = json.dumps(
                {
                    "status": "rendered",
                    "issues": [],
                    "profile": "project-first",
                    "language": "en",
                }
            )
        else:
            raise AssertionError(stage)
        run_kwargs["stdout"].write(stdout.encode("utf-8"))
        run_kwargs["stderr"].write(stderr.encode("utf-8"))
        return subprocess.CompletedProcess(command, 0)

    def test_collection_sequence_writes_private_bounded_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "run.toml"
            config.write_text("synthetic = true\n", encoding="utf-8")
            run_dir = root / "agent-run"
            stdout = StringIO()
            with (
                patch.object(
                    self.runner.subprocess,
                    "run",
                    side_effect=lambda command, **kwargs: self._success_process(
                        command, **kwargs
                    ),
                ) as mocked,
                patch("sys.stdout", stdout),
            ):
                status = self.runner.main(
                    [
                        "--collection-config",
                        str(config),
                        "--run-dir",
                        str(run_dir),
                        "--executable",
                        "synthetic-git-evidence",
                    ]
                )
            self.assertEqual(status, 0)
            self.assertEqual(mocked.call_count, 4)
            receipt = json.loads(stdout.getvalue())
            self.assertEqual(receipt["status"], "complete")
            self.assertEqual(
                [stage["name"] for stage in receipt["stages"]],
                ["doctor", "collect", "validate", "render"],
            )
            self.assertEqual(receipt["bundle"]["assertion_count"], 11)
            self.assertEqual(receipt["bundle"]["evidence_count"], 10)
            self.assertEqual(receipt["bundle"]["retrieval_modes"], ["recorded_replay"])
            self.assertEqual(len(receipt["bundle"]["coverage_warnings"]), 2)
            self.assertEqual(stat.S_IMODE(run_dir.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((run_dir / "receipt.json").stat().st_mode), 0o600
            )
            self.assertNotIn(
                "synthetic-git-evidence", (run_dir / "receipt.json").read_text()
            )

    def test_offline_mode_skips_collection_and_failure_stops_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "offline"
            calls: list[str] = []

            def offline_process(
                command: list[str], **kwargs
            ) -> subprocess.CompletedProcess[bytes]:
                calls.append(command[1])
                return self._success_process(command, **kwargs)

            with patch.object(
                self.runner.subprocess, "run", side_effect=offline_process
            ):
                status = self.runner.main(
                    [
                        "--bundle",
                        str(FIXTURE),
                        "--run-dir",
                        str(run_dir),
                        "--executable",
                        "synthetic-git-evidence",
                    ]
                )
            self.assertEqual(status, 0)
            self.assertEqual(calls, ["validate", "render"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "run.toml"
            config.write_text("synthetic = true\n", encoding="utf-8")
            run_dir = root / "failed"
            calls = []

            def failed_collect(
                command: list[str], **kwargs
            ) -> subprocess.CompletedProcess[bytes]:
                calls.append(command[1])
                if command[1] == "doctor":
                    return self._success_process(command, **kwargs)
                output = Path(command[command.index("--output") + 1])
                output.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
                kwargs["stderr"].write(
                    json.dumps(
                        {
                            "status": "group_failure",
                            "issues": [],
                            "group_failure_count": 1,
                            "blocking_group_failure_count": 1,
                            "group_failures": [
                                {
                                    "provider": "github",
                                    "instance": "github.com",
                                    "repository": "repo:github:github.com:example/project",
                                    "source": "commits",
                                    "failure_class": "service_error",
                                }
                            ],
                            "group_failures_truncated": 0,
                            "coverage_warning_count": 0,
                            "coverage_warnings": [],
                            "coverage_warnings_truncated": 0,
                        }
                    ).encode("utf-8")
                )
                return subprocess.CompletedProcess(command, 3)

            with patch.object(
                self.runner.subprocess, "run", side_effect=failed_collect
            ):
                status = self.runner.main(
                    [
                        "--collection-config",
                        str(config),
                        "--run-dir",
                        str(run_dir),
                        "--executable",
                        "synthetic-git-evidence",
                    ]
                )
            self.assertEqual(status, 3)
            self.assertEqual(calls, ["doctor", "collect"])
            receipt = json.loads((run_dir / "receipt.json").read_text())
            self.assertEqual(receipt["failed_stage"], "collect")
            self.assertNotIn("bundle", receipt)
            self.assertEqual(
                receipt["stages"][-1]["diagnostics"]["group_failures"][0][
                    "failure_class"
                ],
                "service_error",
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "run.toml"
            config.write_text("synthetic = true\n", encoding="utf-8")
            run_dir = root / "doctor-failed"
            calls = []

            def failed_doctor(command: list[str], **kwargs):
                calls.append(command[1])
                kwargs["stdout"].write(
                    json.dumps({"status": "config_error", "issues": []}).encode()
                )
                return subprocess.CompletedProcess(command, 2)

            with patch.object(self.runner.subprocess, "run", side_effect=failed_doctor):
                status = self.runner.main(
                    [
                        "--collection-config",
                        str(config),
                        "--run-dir",
                        str(run_dir),
                        "--executable",
                        "synthetic-git-evidence",
                    ]
                )
            self.assertEqual(status, 2)
            self.assertEqual(calls, ["doctor"])
            receipt = json.loads((run_dir / "receipt.json").read_text())
            self.assertEqual(receipt["failed_stage"], "doctor")

    def test_invalid_diagnostics_do_not_enter_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "run.toml"
            config.write_text("synthetic = true\n", encoding="utf-8")
            run_dir = root / "protocol-failure"
            secret = "synthetic-provider-secret"

            def invalid_process(command: list[str], **kwargs):
                kwargs["stdout"].write(f"not-json {secret}".encode())
                return subprocess.CompletedProcess(command, 2)

            stderr = StringIO()
            with (
                patch.object(
                    self.runner.subprocess, "run", side_effect=invalid_process
                ),
                patch("sys.stderr", stderr),
            ):
                status = self.runner.main(
                    [
                        "--collection-config",
                        str(config),
                        "--run-dir",
                        str(run_dir),
                        "--executable",
                        "synthetic-git-evidence",
                    ]
                )
            self.assertEqual(status, 70)
            receipt_text = (run_dir / "receipt.json").read_text(encoding="utf-8")
            self.assertNotIn(secret, receipt_text)
            self.assertNotIn(secret, stderr.getvalue())

    def test_oversized_diagnostics_fail_without_unbounded_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "run.toml"
            config.write_text("synthetic = true\n", encoding="utf-8")
            run_dir = root / "oversized"

            def oversized_process(command: list[str], **kwargs):
                kwargs["stdout"].write(b"x" * (self.runner.MAX_DIAGNOSTIC_BYTES + 1))
                return subprocess.CompletedProcess(command, 2)

            with patch.object(
                self.runner.subprocess, "run", side_effect=oversized_process
            ):
                status = self.runner.main(
                    [
                        "--collection-config",
                        str(config),
                        "--run-dir",
                        str(run_dir),
                        "--executable",
                        "synthetic-git-evidence",
                    ]
                )
            self.assertEqual(status, 70)
            receipt = json.loads((run_dir / "receipt.json").read_text())
            self.assertEqual(receipt["status"], "protocol_error")
            self.assertLess((run_dir / "receipt.json").stat().st_size, 4096)

    def test_invalid_issue_shape_is_rejected(self) -> None:
        with self.assertRaises(self.runner.RunnerError):
            self.runner._safe_diagnostics(
                {"status": "invalid", "issues": [{"code": "missing-fields"}]}
            )

    def test_malformed_coverage_projection_is_rejected(self) -> None:
        with self.assertRaises(self.runner.RunnerError):
            self.runner._safe_diagnostics(
                {
                    "status": "group_failure",
                    "issues": [],
                    "group_failure_count": 1,
                    "group_failures": [{}],
                    "group_failures_truncated": 0,
                }
            )

    def test_stage_status_must_match_command_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "run.toml"
            config.write_text("synthetic = true\n", encoding="utf-8")
            run_dir = root / "status-mismatch"

            def mismatched_status(command: list[str], **kwargs):
                kwargs["stdout"].write(
                    json.dumps({"status": "internal_failure", "issues": []}).encode()
                )
                return subprocess.CompletedProcess(command, 0)

            with patch.object(
                self.runner.subprocess, "run", side_effect=mismatched_status
            ):
                status = self.runner.main(
                    [
                        "--collection-config",
                        str(config),
                        "--run-dir",
                        str(run_dir),
                        "--executable",
                        "synthetic-git-evidence",
                    ]
                )
            self.assertEqual(status, 70)
            receipt = json.loads((run_dir / "receipt.json").read_text())
            self.assertEqual(receipt["status"], "protocol_error")

    def test_collect_summary_requires_consistent_blocking_counts(self) -> None:
        incomplete = {"status": "group_failure", "issues": []}
        contradictory = {
            "status": "group_failure",
            "issues": [],
            "group_failure_count": 0,
            "blocking_group_failure_count": 1,
            "coverage_warning_count": 0,
            "group_failures": [],
            "group_failures_truncated": 0,
            "coverage_warnings": [],
            "coverage_warnings_truncated": 0,
        }
        for diagnostics in (incomplete, contradictory):
            with (
                self.subTest(diagnostics=diagnostics),
                self.assertRaises(self.runner.RunnerError),
            ):
                safe = self.runner._safe_diagnostics(diagnostics)
                self.runner._validate_collect_summary(safe["status"], safe)

    def test_run_directory_io_failure_is_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            regular_file = Path(directory) / "not-a-directory"
            regular_file.write_text("occupied\n", encoding="utf-8")
            stderr = StringIO()
            with patch("sys.stderr", stderr):
                status = self.runner.main(
                    [
                        "--bundle",
                        str(FIXTURE),
                        "--run-dir",
                        str(regular_file / "child"),
                    ]
                )
            self.assertEqual(status, 2)
            self.assertIn("private run directory", stderr.getvalue())

    def test_collect_io_error_remains_a_stage_failure_not_protocol_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "run.toml"
            config.write_text("synthetic = true\n", encoding="utf-8")
            run_dir = root / "io-failure"

            def io_failure(command: list[str], **kwargs):
                if command[1] == "doctor":
                    return self._success_process(command, **kwargs)
                kwargs["stderr"].write(
                    json.dumps({"status": "io_error", "issues": []}).encode("utf-8")
                )
                return subprocess.CompletedProcess(command, 2)

            with patch.object(self.runner.subprocess, "run", side_effect=io_failure):
                status = self.runner.main(
                    [
                        "--collection-config",
                        str(config),
                        "--run-dir",
                        str(run_dir),
                        "--executable",
                        "synthetic-git-evidence",
                    ]
                )
            receipt = json.loads((run_dir / "receipt.json").read_text())
            self.assertEqual(status, 2)
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["failed_stage"], "collect")
            self.assertEqual(receipt["stages"][-1]["diagnostics"]["status"], "io_error")

    def test_real_cli_offline_replay_is_provider_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "git-evidence-test"
            executable.write_text(
                f"#!{sys.executable}\n"
                "from git_evidence.cli import main\n"
                "raise SystemExit(main())\n",
                encoding="utf-8",
            )
            os.chmod(executable, 0o700)
            run_dir = root / "offline-run"
            stdout = StringIO()
            with patch("sys.stdout", stdout):
                status = self.runner.main(
                    [
                        "--bundle",
                        str(FIXTURE),
                        "--run-dir",
                        str(run_dir),
                        "--executable",
                        str(executable),
                        "--profile",
                        "project-first",
                        "--language",
                        "zh-CN",
                    ]
                )
            receipt = json.loads(stdout.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(receipt["status"], "complete")
            self.assertEqual(
                [stage["name"] for stage in receipt["stages"]],
                ["validate", "render"],
            )
            self.assertEqual(receipt["bundle"]["retrieval_modes"], ["recorded_replay"])
            self.assertEqual(receipt["bundle"]["blocking_group_failure_count"], 0)
            self.assertTrue((run_dir / "report.md").is_file())

    def test_receipt_write_failure_is_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "receipt-failure"
            stderr = StringIO()
            with (
                patch.object(
                    self.runner,
                    "_write_private_json",
                    side_effect=OSError("synthetic disk failure"),
                ),
                patch.object(
                    self.runner.subprocess,
                    "run",
                    side_effect=lambda command, **kwargs: self._success_process(
                        command, **kwargs
                    ),
                ),
                patch("sys.stderr", stderr),
            ):
                status = self.runner.main(
                    [
                        "--bundle",
                        str(FIXTURE),
                        "--run-dir",
                        str(run_dir),
                        "--executable",
                        "synthetic-git-evidence",
                    ]
                )
            self.assertEqual(status, 2)
            self.assertIn("could not persist", stderr.getvalue())
            self.assertNotIn("synthetic disk failure", stderr.getvalue())


class AgentSkillEvalContractTests(unittest.TestCase):
    def test_eval_cases_define_tool_traces_and_forbidden_actions(
        self,
    ) -> None:
        cases = json.loads((SKILL / "evals" / "cases.json").read_text(encoding="utf-8"))
        self.assertEqual(len(cases), 8)
        by_id = {case["id"]: case for case in cases}
        self.assertEqual(
            by_id["offline-replay"]["expected_stages"], ["validate", "render"]
        )
        self.assertEqual(by_id["doctor-failure"]["expected_stages"], ["doctor"])
        self.assertEqual(by_id["clarify-live-scope"]["expected_stages"], [])
        for case in cases:
            self.assertTrue(case["evaluation"])
            self.assertIsInstance(case["expected_stages"], list)
            self.assertTrue(case["forbidden_actions"])
        expected = {expectation for case in cases for expectation in case["expect"]}
        self.assertTrue(
            {
                "ask_repository_allowlist",
                "stop_after_doctor",
                "keep_warning_visible",
                "credential_env_reference_only",
                "no_direct_provider_fetch",
                "report_receipt_retrieval_modes",
            }.issubset(expected)
        )


if __name__ == "__main__":
    unittest.main()
