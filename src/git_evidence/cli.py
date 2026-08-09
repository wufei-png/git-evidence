from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

from . import __version__
from .atomic_io import AtomicWriteError, atomic_write_text
from .collect import CollectionError, collect_config
from .config import (
    ConfigError,
    ReportConfig,
    load_collection_config,
    load_report_config,
)
from .model import BundleLoadError, load_bundle
from .providers import RESOURCE_SOURCES, provider_catalog
from .render import LANGUAGES, PROFILES, RenderError, render_bundle
from .validation import ValidationIssue, format_issues, validate_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="git-evidence", allow_abbrev=False)
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser(
        "validate", help="validate an evidence bundle", allow_abbrev=False
    )
    validate.add_argument("bundle", type=Path)
    validate.add_argument(
        "--diagnostics-format",
        choices=("text", "json"),
        default="text",
    )

    render = subparsers.add_parser(
        "render", help="render a validated evidence bundle", allow_abbrev=False
    )
    render.add_argument("bundle", type=Path)
    render.add_argument(
        "--config",
        type=Path,
        help="optional configuration for report and identity display",
    )
    render.add_argument("--profile", choices=PROFILES)
    render.add_argument("--language", choices=LANGUAGES)
    render.add_argument("--output", "-o", type=Path)

    subparsers.add_parser(
        "providers", help="list provider contracts", allow_abbrev=False
    )

    doctor = subparsers.add_parser(
        "doctor", help="validate a collection configuration", allow_abbrev=False
    )
    doctor.add_argument("--config", required=True, type=Path)

    collect = subparsers.add_parser(
        "collect",
        help="collect an evidence bundle from a configuration",
        allow_abbrev=False,
    )
    collect.add_argument("--config", required=True, type=Path)
    collect.add_argument("--output", "-o", type=Path)
    collect.add_argument(
        "--diagnostics-format",
        choices=("text", "json"),
        default="text",
    )
    return parser


def _diagnostics_text(issues: list[ValidationIssue]) -> str:
    return format_issues(issues)


def _diagnostics_json(
    status: str,
    issues: list[ValidationIssue],
    **summary: int,
) -> str:
    return json.dumps(
        {
            "status": status,
            "issues": [item.as_dict() for item in issues],
            **summary,
        },
        ensure_ascii=False,
        indent=2,
    )


def _emit_collect_diagnostics(
    *,
    status: str,
    issues: list[ValidationIssue],
    diagnostics_format: str,
    group_failure_count: int,
    coverage_warning_count: int,
) -> None:
    if diagnostics_format == "json":
        print(
            _diagnostics_json(
                status,
                issues,
                group_failure_count=group_failure_count,
                coverage_warning_count=coverage_warning_count,
            ),
            file=sys.stderr,
        )
        return
    if issues:
        print(_diagnostics_text(issues), file=sys.stderr)
    messages = {
        "group_failure": "COLLECTION: one or more provider groups failed",
        "invalid": "COLLECTION: validation failed",
        "render_eligible_with_warnings": "COLLECTION: render eligible with coverage warnings",
        "render_eligible": "COLLECTION: render eligible",
    }
    print(messages[status], file=sys.stderr)


def _write_output(path: Path, text: str) -> bool:
    try:
        atomic_write_text(path, text)
    except AtomicWriteError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return False
    return True


def _requested_diagnostics_format(argv: list[str] | None) -> str:
    values = list(sys.argv[1:] if argv is None else argv)
    requested = "text"
    for position, value in enumerate(values):
        if value == "--diagnostics-format" and position + 1 < len(values):
            requested = values[position + 1]
        if value.startswith("--diagnostics-format="):
            requested = value.partition("=")[2]
    return requested


def _main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "providers":
        print(
            json.dumps(
                [item.as_dict() for item in provider_catalog()],
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if args.command == "doctor":
        try:
            config = load_collection_config(args.config)
        except ConfigError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(
            f"CONFIGURATION: valid ({len(config.repositories)} allowlisted repositories)"
        )
        return 0
    if args.command == "collect":
        try:
            config = load_collection_config(args.config)
            bundle = collect_config(config)
        except (ConfigError, CollectionError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        serialized = json.dumps(bundle, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            if not _write_output(args.output, serialized):
                return 2
        else:
            print(serialized, end="")
        issues = validate_bundle(bundle, required_sources_contract=RESOURCE_SOURCES)
        group_failures = (bundle.get("coverage") or {}).get("group_failures") or []
        blocking_group_failures = [
            failure
            for failure in group_failures
            if isinstance(failure, dict) and failure.get("source") in RESOURCE_SOURCES
        ]
        warnings = (bundle.get("coverage") or {}).get("warnings") or []
        if blocking_group_failures:
            _emit_collect_diagnostics(
                status="group_failure",
                issues=issues,
                diagnostics_format=args.diagnostics_format,
                group_failure_count=len(blocking_group_failures),
                coverage_warning_count=len(warnings),
            )
            return 3
        blocking_issues = [issue for issue in issues if issue.severity == "error"]
        if blocking_issues:
            _emit_collect_diagnostics(
                status="invalid",
                issues=issues,
                diagnostics_format=args.diagnostics_format,
                group_failure_count=0,
                coverage_warning_count=len(warnings),
            )
            return 1
        _emit_collect_diagnostics(
            status="render_eligible_with_warnings"
            if warnings or issues
            else "render_eligible",
            issues=issues,
            diagnostics_format=args.diagnostics_format,
            group_failure_count=0,
            coverage_warning_count=len(warnings),
        )
        return 0
    try:
        bundle = load_bundle(args.bundle)
    except BundleLoadError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    issues = validate_bundle(bundle)
    if args.command == "validate":
        blocking_issues = [issue for issue in issues if issue.severity == "error"]
        if args.diagnostics_format == "json":
            print(
                _diagnostics_json(
                    "invalid"
                    if blocking_issues
                    else "valid_with_warnings"
                    if issues
                    else "valid",
                    issues,
                )
            )
        elif issues:
            print(_diagnostics_text(issues))
        if blocking_issues:
            return 1
        if not issues and args.diagnostics_format == "text":
            print("VALIDATION: none")
        return 0
    report_config = ReportConfig()
    if args.config:
        try:
            report_config = load_report_config(args.config)
        except ConfigError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
    profile = args.profile or report_config.profile
    language = args.language or report_config.language
    display_actor_names = report_config.display_actor_names
    actor_labels = report_config.actor_label_map()
    allow_source_urls = report_config.allow_source_urls
    try:
        rendered = render_bundle(
            bundle,
            profile=profile,
            language=language,
            display_actor_names=display_actor_names,
            actor_labels=actor_labels,
            allow_source_urls=allow_source_urls,
        )
    except RenderError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if args.output:
        if not _write_output(args.output, rendered):
            return 2
    else:
        print(rendered, end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI while keeping unknown failures out of user-visible output."""
    try:
        return _main(argv)
    except Exception:  # noqa: BLE001 - the process boundary must redact internals
        error_id = secrets.token_hex(8)
        if _requested_diagnostics_format(argv) == "json":
            print(
                json.dumps(
                    {
                        "status": "internal_failure",
                        "issues": [],
                        "error_id": error_id,
                    },
                    ensure_ascii=False,
                ),
                file=sys.stderr,
            )
        else:
            print(
                f"ERROR: internal failure; error_id={error_id}",
                file=sys.stderr,
            )
        return 70
