from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .collect import CollectionError, collect_config
from .config import ConfigError, load_collection_config, load_report_config
from .model import BundleLoadError, load_bundle
from .providers import RESOURCE_SOURCES, provider_catalog
from .render import LANGUAGES, PROFILES, RenderError, render_bundle
from .validation import format_issues, validate_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="git-evidence")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate an evidence bundle")
    validate.add_argument("bundle", type=Path)

    render = subparsers.add_parser("render", help="render a validated evidence bundle")
    render.add_argument("bundle", type=Path)
    render.add_argument("--config", type=Path, help="optional configuration for report and identity display")
    render.add_argument("--profile", choices=PROFILES)
    render.add_argument("--language", choices=LANGUAGES)
    render.add_argument("--output", "-o", type=Path)

    subparsers.add_parser("providers", help="list provider contracts")

    doctor = subparsers.add_parser("doctor", help="validate a collection configuration")
    doctor.add_argument("--config", required=True, type=Path)

    collect = subparsers.add_parser("collect", help="collect an evidence bundle from a configuration")
    collect.add_argument("--config", required=True, type=Path)
    collect.add_argument("--output", "-o", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "providers":
        print(json.dumps([item.as_dict() for item in provider_catalog()], ensure_ascii=False, indent=2))
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
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(serialized, encoding="utf-8")
        else:
            print(serialized, end="")
        issues = validate_bundle(bundle, required_sources_contract=RESOURCE_SOURCES)
        group_failures = (bundle.get("coverage") or {}).get("group_failures") or []
        blocking_group_failures = [
            failure
            for failure in group_failures
            if isinstance(failure, dict) and failure.get("source") in RESOURCE_SOURCES
        ]
        if blocking_group_failures:
            if issues:
                print(format_issues(issues), file=sys.stderr)
            print("COLLECTION: one or more provider groups failed", file=sys.stderr)
            return 3
        if issues:
            print(format_issues(issues), file=sys.stderr)
            return 1
        warnings = (bundle.get("coverage") or {}).get("warnings") or []
        if warnings:
            print("COLLECTION: publishable with coverage warnings", file=sys.stderr)
        else:
            print("COLLECTION: publishable", file=sys.stderr)
        return 0
    try:
        bundle = load_bundle(args.bundle)
    except BundleLoadError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    issues = validate_bundle(bundle)
    if args.command == "validate":
        if issues:
            print(format_issues(issues))
            return 1
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
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0
