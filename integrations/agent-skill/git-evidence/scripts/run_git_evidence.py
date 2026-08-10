#!/usr/bin/env python3
"""Deterministically orchestrate the Git Evidence CLI without provider logic."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

MAX_RECEIPT_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 1024 * 1024
MAX_DIAGNOSTIC_ISSUES = 128
MAX_COVERAGE_RECORDS = 128
MAX_DIAGNOSTIC_STRING_CHARS = 4096

ISSUE_FIELDS = ("code", "severity", "path", "scope", "message", "remediation")
COVERAGE_WARNING_FIELDS = (
    "code",
    "source",
    "provider_id",
    "repository_id",
    "status",
    "failure_class",
    "failure_classes",
)
GROUP_FAILURE_FIELDS = (
    "provider",
    "instance",
    "repository",
    "source",
    "failure_class",
)
EXPECTED_STAGE_STATUSES = {
    "doctor": {
        0: {"valid"},
        2: {"config_error"},
        70: {"internal_failure"},
    },
    "collect": {
        0: {"render_eligible", "render_eligible_with_warnings"},
        1: {"invalid"},
        2: {"collection_error", "io_error"},
        3: {"group_failure"},
        70: {"internal_failure"},
    },
    "validate": {
        0: {"valid", "valid_with_warnings"},
        1: {"invalid"},
        2: {"input_error"},
        70: {"internal_failure"},
    },
    "render": {
        0: {"rendered", "rendered_with_warnings"},
        1: {"invalid", "render_error"},
        2: {"input_error", "config_error", "io_error"},
        70: {"internal_failure"},
    },
}


class RunnerError(RuntimeError):
    """The local orchestration contract could not be completed safely."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument(
        "--collection-config",
        type=Path,
        help="TOML collection configuration for doctor and collect",
    )
    inputs.add_argument(
        "--bundle",
        type=Path,
        help="existing Schema 0.3 bundle for offline validate and render",
    )
    parser.add_argument(
        "--report-config",
        type=Path,
        help="optional TOML report configuration; collection config is the default",
    )
    parser.add_argument(
        "--profile",
        choices=("project-first", "timeline", "release-focused", "actor-summary"),
    )
    parser.add_argument("--language", choices=("en", "zh-CN"))
    parser.add_argument(
        "--run-dir",
        type=Path,
        help="new output directory; defaults to a private temporary directory",
    )
    parser.add_argument(
        "--executable",
        default="git-evidence",
        help="Git Evidence executable name or path (no shell evaluation)",
    )
    return parser


def _create_run_dir(requested: Path | None) -> Path:
    try:
        if requested is None:
            path = Path(tempfile.mkdtemp(prefix="git-evidence-agent-"))
        else:
            path = requested.expanduser().resolve()
            if path.exists():
                raise RunnerError(f"run directory already exists: {path}")
            path.mkdir(parents=True, mode=0o700)
        os.chmod(path, 0o700)
    except OSError as exc:
        raise RunnerError("could not create the private run directory") from exc
    return path


def _safe_diagnostics(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RunnerError("CLI diagnostics root is not an object")
    status = value.get("status")
    issues = value.get("issues")
    if not isinstance(status, str) or not isinstance(issues, list):
        raise RunnerError("CLI diagnostics are missing status or issues")
    safe: dict[str, Any] = {
        "status": _bounded_string(status),
        "issues": _project_issues(issues),
    }
    if len(issues) > MAX_DIAGNOSTIC_ISSUES:
        safe["issues_truncated"] = len(issues) - MAX_DIAGNOSTIC_ISSUES
    for key in (
        "repository_count",
        "group_failure_count",
        "coverage_warning_count",
        "blocking_group_failure_count",
        "group_failures_truncated",
        "coverage_warnings_truncated",
    ):
        if (
            key in value
            and isinstance(value[key], int)
            and not isinstance(value[key], bool)
        ):
            safe[key] = value[key]
    for key in ("profile", "language"):
        if isinstance(value.get(key), str):
            safe[key] = _bounded_string(value[key])
    for key, fields in (
        ("coverage_warnings", COVERAGE_WARNING_FIELDS),
        ("group_failures", GROUP_FAILURE_FIELDS),
    ):
        records = value.get(key)
        if isinstance(records, list):
            required_fields = (
                ("code", "source", "provider_id", "repository_id", "status")
                if key == "coverage_warnings"
                else GROUP_FAILURE_FIELDS
            )
            safe[key] = _project_coverage_records(
                records,
                fields=fields,
                required_fields=required_fields,
            )
    _validate_coverage_counts(value, safe)
    if isinstance(value.get("error_id"), str):
        safe["error_id"] = _bounded_string(value["error_id"])
    return safe


def _bounded_string(value: str) -> str:
    if len(value) <= MAX_DIAGNOSTIC_STRING_CHARS:
        return value
    return value[:MAX_DIAGNOSTIC_STRING_CHARS] + "…[truncated]"


def _project_issues(records: list[object]) -> list[dict[str, object]]:
    projected: list[dict[str, object]] = []
    for record in records[:MAX_DIAGNOSTIC_ISSUES]:
        if not isinstance(record, dict) or not all(
            isinstance(record.get(field), str) for field in ISSUE_FIELDS
        ):
            raise RunnerError("CLI diagnostics contain an invalid issue")
        projected.append(
            {field: _bounded_string(record[field]) for field in ISSUE_FIELDS}
        )
    return projected


def _project_records(
    records: list[object],
    *,
    fields: tuple[str, ...],
    limit: int,
) -> list[dict[str, object]]:
    projected: list[dict[str, object]] = []
    for record in records[:limit]:
        if not isinstance(record, dict):
            continue
        item: dict[str, object] = {}
        for field in fields:
            value = record.get(field)
            if isinstance(value, str):
                item[field] = _bounded_string(value)
            elif isinstance(value, list) and all(
                isinstance(child, str) for child in value
            ):
                item[field] = [
                    _bounded_string(child) for child in value[:MAX_COVERAGE_RECORDS]
                ]
        projected.append(item)
    return projected


def _project_coverage_records(
    records: list[object],
    *,
    fields: tuple[str, ...],
    required_fields: tuple[str, ...],
) -> list[dict[str, object]]:
    for record in records[:MAX_COVERAGE_RECORDS]:
        if not isinstance(record, dict) or not all(
            isinstance(record.get(field), str) for field in required_fields
        ):
            raise RunnerError("CLI diagnostics contain an invalid Coverage record")
        failure_classes = record.get("failure_classes")
        if failure_classes is not None and (
            not isinstance(failure_classes, list)
            or not all(isinstance(item, str) for item in failure_classes)
        ):
            raise RunnerError("CLI diagnostics contain invalid failure classes")
    return _project_records(
        records,
        fields=fields,
        limit=MAX_COVERAGE_RECORDS,
    )


def _validate_coverage_counts(
    original: dict[str, Any], projected: dict[str, Any]
) -> None:
    for count_key, records_key, truncated_key in (
        ("coverage_warning_count", "coverage_warnings", "coverage_warnings_truncated"),
        ("group_failure_count", "group_failures", "group_failures_truncated"),
    ):
        count = original.get(count_key)
        if count is None:
            continue
        records = original.get(records_key)
        truncated = original.get(truncated_key, 0)
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or not isinstance(records, list)
            or not isinstance(truncated, int)
            or isinstance(truncated, bool)
            or count != len(records) + truncated
        ):
            raise RunnerError("CLI Coverage counts do not match their projections")
        if len(projected.get(records_key, [])) != len(records):
            raise RunnerError("CLI Coverage projection could not be retained safely")


def _validate_collect_summary(status: str, diagnostics: dict[str, Any]) -> None:
    collection_statuses = {
        "render_eligible",
        "render_eligible_with_warnings",
        "invalid",
        "group_failure",
    }
    if status not in collection_statuses:
        return
    required = {
        "group_failure_count",
        "blocking_group_failure_count",
        "coverage_warning_count",
        "group_failures",
        "group_failures_truncated",
        "coverage_warnings",
        "coverage_warnings_truncated",
    }
    if not required <= diagnostics.keys():
        raise RunnerError("CLI collect diagnostics are missing Coverage summary fields")
    total = diagnostics["group_failure_count"]
    blocking = diagnostics["blocking_group_failure_count"]
    if (
        not isinstance(total, int)
        or not isinstance(blocking, int)
        or not 0 <= blocking <= total
    ):
        raise RunnerError(
            "CLI collect diagnostics contain contradictory failure counts"
        )
    if status == "group_failure" and blocking == 0:
        raise RunnerError("CLI group-failure diagnostics have no blocking failures")
    if status != "group_failure" and blocking != 0:
        raise RunnerError("CLI non-group-failure diagnostics claim blocking failures")


def _validate_stage_status(name: str, exit_code: int, status: object) -> None:
    expected = EXPECTED_STAGE_STATUSES.get(name, {}).get(exit_code)
    if not isinstance(status, str) or expected is None or status not in expected:
        raise RunnerError(
            f"Git Evidence returned an incompatible status for {name} exit {exit_code}"
        )


def _run_stage(
    name: str,
    command: list[str],
    *,
    diagnostics_stream: str,
) -> tuple[dict[str, Any], int]:
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(
                command,
                check=False,
                stdout=stdout,
                stderr=stderr,
            )
            diagnostics = stdout if diagnostics_stream == "stdout" else stderr
            diagnostics.seek(0)
            payload = diagnostics.read(MAX_DIAGNOSTIC_BYTES + 1)
    except OSError as exc:
        raise RunnerError(f"could not start Git Evidence for {name}") from exc
    if len(payload) > MAX_DIAGNOSTIC_BYTES:
        raise RunnerError(
            f"Git Evidence JSON diagnostics exceeded the bound for {name}"
        )
    try:
        safe_diagnostics = _safe_diagnostics(json.loads(payload.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, RunnerError) as exc:
        raise RunnerError(
            f"Git Evidence returned invalid JSON diagnostics for {name}"
        ) from exc
    _validate_stage_status(name, completed.returncode, safe_diagnostics["status"])
    if name == "collect":
        _validate_collect_summary(safe_diagnostics["status"], safe_diagnostics)
    return (
        {
            "name": name,
            "exit_code": completed.returncode,
            "diagnostics": safe_diagnostics,
        },
        completed.returncode,
    )


def _bundle_summary(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            payload = handle.read(MAX_RECEIPT_BUNDLE_BYTES + 1)
        if len(payload) > MAX_RECEIPT_BUNDLE_BYTES:
            raise RunnerError("validated Bundle exceeds the receipt reader bound")
        bundle = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError("could not read the bundle produced by Git Evidence") from exc
    if not isinstance(bundle, dict):
        raise RunnerError("Git Evidence bundle root is not an object")

    invocation = bundle.get("invocation")
    coverage = bundle.get("coverage")
    invocation_id = invocation.get("id") if isinstance(invocation, dict) else None
    warnings = coverage.get("warnings", []) if isinstance(coverage, dict) else []
    group_failures = (
        coverage.get("group_failures", []) if isinstance(coverage, dict) else []
    )
    retrieval_modes = sorted(
        {
            item["mode"]
            for item in bundle.get("retrievals", [])
            if isinstance(item, dict) and isinstance(item.get("mode"), str)
        }
    )
    return {
        "plan_id": bundle.get("plan_id"),
        "invocation_id": invocation_id,
        "bundle_digest": bundle.get("bundle_digest"),
        "assertion_count": len(bundle.get("assertions", []))
        if isinstance(bundle.get("assertions"), list)
        else 0,
        "evidence_count": len(bundle.get("evidence", []))
        if isinstance(bundle.get("evidence"), list)
        else 0,
        "render_eligible": coverage.get("render_eligible")
        if isinstance(coverage, dict)
        else None,
        "coverage_warning_count": len(warnings) if isinstance(warnings, list) else 0,
        "coverage_warnings": _project_coverage_records(
            warnings if isinstance(warnings, list) else [],
            fields=COVERAGE_WARNING_FIELDS,
            required_fields=(
                "code",
                "source",
                "provider_id",
                "repository_id",
                "status",
            ),
        ),
        "coverage_warnings_truncated": max(
            0,
            len(warnings) - MAX_COVERAGE_RECORDS if isinstance(warnings, list) else 0,
        ),
        "group_failure_count": len(group_failures)
        if isinstance(group_failures, list)
        else 0,
        "group_failures": _project_coverage_records(
            group_failures if isinstance(group_failures, list) else [],
            fields=GROUP_FAILURE_FIELDS,
            required_fields=GROUP_FAILURE_FIELDS,
        ),
        "group_failures_truncated": max(
            0,
            len(group_failures) - MAX_COVERAGE_RECORDS
            if isinstance(group_failures, list)
            else 0,
        ),
        "retrieval_modes": retrieval_modes,
    }


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    payload = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _finish(receipt_path: Path, receipt: dict[str, Any], exit_code: int) -> int:
    try:
        _write_private_json(receipt_path, receipt)
    except OSError:
        print(
            "ERROR: could not persist the private Git Evidence receipt", file=sys.stderr
        )
        return 2
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    return exit_code


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        run_dir = _create_run_dir(args.run_dir)
    except RunnerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    receipt_path = run_dir / "receipt.json"
    report_path = run_dir / "report.md"
    bundle_path = (
        args.bundle.expanduser().resolve() if args.bundle else run_dir / "bundle.json"
    )
    receipt: dict[str, Any] = {
        "receipt_version": "git-evidence-agent-receipt-1",
        "status": "running",
        "mode": "offline_bundle" if args.bundle else "collection",
        "artifacts": {
            "run_dir": str(run_dir),
            "bundle": str(bundle_path),
            "report": str(report_path),
            "receipt": str(receipt_path),
        },
        "stages": [],
    }

    def execute(name: str, command: list[str], stream: str) -> int:
        stage, exit_code = _run_stage(name, command, diagnostics_stream=stream)
        receipt["stages"].append(stage)
        return exit_code

    try:
        if args.collection_config:
            collection_config = args.collection_config.expanduser().resolve()
            exit_code = execute(
                "doctor",
                [
                    args.executable,
                    "doctor",
                    "--config",
                    str(collection_config),
                    "--diagnostics-format",
                    "json",
                ],
                "stdout",
            )
            if exit_code:
                receipt.update(status="failed", failed_stage="doctor")
                return _finish(receipt_path, receipt, exit_code)
            exit_code = execute(
                "collect",
                [
                    args.executable,
                    "collect",
                    "--config",
                    str(collection_config),
                    "--output",
                    str(bundle_path),
                    "--diagnostics-format",
                    "json",
                ],
                "stderr",
            )
            if exit_code:
                receipt.update(status="failed", failed_stage="collect")
                return _finish(receipt_path, receipt, exit_code)

        exit_code = execute(
            "validate",
            [
                args.executable,
                "validate",
                str(bundle_path),
                "--diagnostics-format",
                "json",
            ],
            "stdout",
        )
        if exit_code:
            receipt.update(status="failed", failed_stage="validate")
            return _finish(receipt_path, receipt, exit_code)
        receipt["bundle"] = _bundle_summary(bundle_path)
        validation_diagnostics = receipt["stages"][-1]["diagnostics"]
        blocking_count = validation_diagnostics.get("blocking_group_failure_count")
        if isinstance(blocking_count, int):
            receipt["bundle"]["blocking_group_failure_count"] = blocking_count

        render_command = [
            args.executable,
            "render",
            str(bundle_path),
            "--output",
            str(report_path),
            "--diagnostics-format",
            "json",
        ]
        report_config = args.report_config or args.collection_config
        if report_config:
            render_command.extend(
                ["--config", str(report_config.expanduser().resolve())]
            )
        if args.profile:
            render_command.extend(["--profile", args.profile])
        if args.language:
            render_command.extend(["--language", args.language])
        exit_code = execute("render", render_command, "stderr")
        if exit_code:
            receipt.update(status="failed", failed_stage="render")
            return _finish(receipt_path, receipt, exit_code)

        receipt["status"] = "complete"
        return _finish(receipt_path, receipt, 0)
    except RunnerError as exc:
        receipt.update(status="protocol_error", failed_stage="runner")
        persisted_status = _finish(receipt_path, receipt, 70)
        if persisted_status != 70:
            return persisted_status
        print(f"ERROR: {exc}", file=sys.stderr)
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
