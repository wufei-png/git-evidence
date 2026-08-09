from __future__ import annotations

import argparse
import json
import sys
from io import StringIO
from pathlib import Path

from . import __version__
from .atomic_io import AtomicWriteError, atomic_write_text
from .bounds import InputLimitError, read_bounded_bytes
from .collect import CollectionError, collect_config
from .config import ConfigError, load_collection_config, load_report_config
from .identity import compute_artifact_bytes_digest
from .limits import MAX_BUNDLE_BYTES
from .migration import MigrationError, migrate_v01_to_v02
from .model import BundleLoadError, load_bundle
from .providers import RESOURCE_SOURCES, provider_catalog
from .render import LANGUAGES, PROFILES, RenderError, render_bundle
from .validation import ValidationIssue, format_issues, validate_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="git-evidence")
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate an evidence bundle")
    validate.add_argument("bundle", type=Path)
    validate.add_argument(
        "--diagnostics-format",
        choices=("text", "json"),
        default="text",
    )

    render = subparsers.add_parser("render", help="render a validated evidence bundle")
    render.add_argument("bundle", type=Path)
    render.add_argument(
        "--config",
        type=Path,
        help="optional configuration for report and identity display",
    )
    render.add_argument("--profile", choices=PROFILES)
    render.add_argument("--language", choices=LANGUAGES)
    render.add_argument("--output", "-o", type=Path)

    migrate = subparsers.add_parser(
        "migrate", help="explicitly migrate a schema 0.1 bundle to 0.2"
    )
    migrate.add_argument("bundle", type=Path)
    migrate.add_argument("--output", "-o", type=Path)

    subparsers.add_parser("providers", help="list provider contracts")

    doctor = subparsers.add_parser("doctor", help="validate a collection configuration")
    doctor.add_argument("--config", required=True, type=Path)

    collect = subparsers.add_parser(
        "collect", help="collect an evidence bundle from a configuration"
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
        "publishable_with_warnings": "COLLECTION: publishable with coverage warnings",
        "publishable": "COLLECTION: publishable",
    }
    print(messages[status], file=sys.stderr)


def _write_output(path: Path, text: str) -> bool:
    try:
        atomic_write_text(path, text)
    except AtomicWriteError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return False
    return True


def main(argv: list[str] | None = None) -> int:
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
        repositories = config["scope"]["repositories"]
        print(f"CONFIGURATION: valid ({len(repositories)} allowlisted repositories)")
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
            status="publishable_with_warnings" if warnings or issues else "publishable",
            issues=issues,
            diagnostics_format=args.diagnostics_format,
            group_failure_count=0,
            coverage_warning_count=len(warnings),
        )
        return 0
    if args.command == "migrate":
        try:
            raw = read_bounded_bytes(args.bundle, max_bytes=MAX_BUNDLE_BYTES)
            bundle = load_bundle(StringIO(raw.decode("utf-8")))
            migrated = migrate_v01_to_v02(
                bundle,
                source_artifact_digest=compute_artifact_bytes_digest(raw),
            )
        except (
            BundleLoadError,
            InputLimitError,
            MigrationError,
            OSError,
            UnicodeDecodeError,
        ) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        serialized = json.dumps(migrated, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            if not _write_output(args.output, serialized):
                return 2
        else:
            print(serialized, end="")
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
    report_config: dict[str, object] = {}
    if args.config:
        try:
            report_config = load_report_config(args.config)
        except ConfigError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
    profile = args.profile or str(report_config.get("profile", "project-first"))
    language = args.language or str(report_config.get("language", "en"))
    display_actor_names = bool(report_config.get("display_actor_names", False))
    actor_labels = report_config.get("actor_labels")
    privacy = report_config.get("privacy")
    allow_source_urls = True
    if isinstance(privacy, dict):
        allow_source_urls = bool(privacy.get("allow_source_urls", True))
    try:
        rendered = render_bundle(
            bundle,
            profile=profile,
            language=language,
            display_actor_names=display_actor_names,
            actor_labels=actor_labels if isinstance(actor_labels, dict) else None,
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
