from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime
from hashlib import sha256
from html import escape as html_escape
from typing import Any
from urllib.parse import quote

from .model import collection
from .privacy import sanitize_public_url
from .time import local_date, parse_instant
from .validation import format_issues, validate_bundle

PROFILES = ("project-first", "timeline", "release-focused", "actor-summary")
LANGUAGES = ("en", "zh-CN")
RENDER_POLICY_VERSION = "render-policy-v1"

LABELS = {
    "en": {
        "title": "Git Evidence Engineering Activity Report",
        "window": "Window",
        "projects": "Projects and topics",
        "project_activity": "Project activity",
        "releases": "Releases and changes",
        "timeline": "Timeline",
        "actors": "Actor summary",
        "other": "Other verified activity",
        "coverage": "Data coverage",
        "coverage_warnings": "Coverage warnings",
        "validation_warnings": "Validation warnings",
        "evidence": "evidence",
        "evidence_index": "Evidence index",
        "report_metadata": "Report metadata",
        "anonymous": "anonymous actor",
        "actor_warning": "Actor view is informational only; it is not a productivity or performance score.",
        "no_coverage": "No coverage observations.",
        "no_releases": "No verified releases or release changes.",
    },
    "zh-CN": {
        "title": "Git 平台工程活动报告",
        "window": "时间窗口",
        "projects": "项目与专题",
        "project_activity": "项目活动",
        "releases": "版本与变更",
        "timeline": "时间线",
        "actors": "人员视图",
        "other": "其他已验证活动",
        "coverage": "数据覆盖",
        "coverage_warnings": "覆盖警告",
        "validation_warnings": "校验警告",
        "evidence": "证据",
        "evidence_index": "证据索引",
        "report_metadata": "报告元数据",
        "anonymous": "匿名成员",
        "actor_warning": "人员视图仅用于信息回顾，不代表生产力或绩效评分。",
        "no_coverage": "没有覆盖观测。",
        "no_releases": "没有已验证的版本或版本变更。",
    },
}


class RenderError(ValueError):
    """The bundle cannot be safely rendered."""


def _escape_text(value: Any) -> str:
    text = str(value or "").replace("\n", " ").strip()
    visual_controls = {
        *range(0x200B, 0x2010),
        *range(0x202A, 0x202F),
        *range(0x2060, 0x2070),
        0xFEFF,
    }
    text = "".join(
        f"U+{ord(character):04X}" if ord(character) in visual_controls else character
        for character in text
    )
    text = html_escape(text, quote=False)
    markdown_punctuation = r"\\`*_[\]{}()#+\-.!|>"
    return "".join(
        f"\\{character}" if character in markdown_punctuation else character
        for character in text
    )


def _link(label: str, url: str) -> str:
    safe_url = quote(str(sanitize_public_url(url)), safe=":/?#[]@!$&'()*+,;=%-._~")
    return f"[{_escape_text(label)}](<{safe_url}>)"


def _actor_labels(
    bundle: dict[str, Any],
    language: str,
    *,
    display_actor_names: bool = False,
    actor_labels: Mapping[str, str] | None = None,
) -> dict[str, str]:
    labels = LABELS[language]
    actors = sorted(
        collection(bundle, "actors"), key=lambda item: str(item.get("id", ""))
    )
    result: dict[str, str] = {}
    anonymous_number = 0
    for actor in actors:
        actor_id = actor.get("id")
        if not actor_id:
            continue
        display = (
            actor_labels.get(actor_id) if display_actor_names and actor_labels else None
        )
        if isinstance(display, str) and display.strip():
            result[actor_id] = _escape_text(display)
            continue
        anonymous_number += 1
        digest = sha256(str(actor_id).encode("utf-8")).hexdigest()[:6]
        result[actor_id] = f"{labels['anonymous']} {anonymous_number} ({digest})"
    return result


def _indexes(
    bundle: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    repositories = {
        item["id"]: item
        for item in collection(bundle, "repositories")
        if item.get("id")
    }
    evidence = {
        item["id"]: item for item in collection(bundle, "evidence") if item.get("id")
    }
    return repositories, evidence


def _claim_sort_key(claim: dict[str, Any]) -> tuple[datetime, str]:
    return (
        parse_instant(str(claim.get("occurred_at") or "")),
        str(claim.get("id") or ""),
    )


def _claim_repository_id(claim: dict[str, Any]) -> str | None:
    repository_id = claim.get("repository_id")
    if isinstance(repository_id, str):
        return repository_id
    return None


_ASSERTION_SECTIONS = {
    "work_item.observed.v1": "project",
    "change_request.observed.v1": "change",
    "change_request.merged.v1": "release",
    "interaction.observed.v1": "project",
    "commit.observed.v1": "change",
    "ref_change.observed.v1": "change",
    "release.observed.v1": "release",
    "release.published.v1": "release",
}


def _renderable_claims(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    subjects: dict[str, dict[str, Any]] = {}
    for key in (
        "repositories",
        "work_items",
        "change_requests",
        "interactions",
        "commits",
        "ref_changes",
        "releases",
    ):
        for item in collection(bundle, key):
            subject_id = item.get("id")
            if isinstance(subject_id, str) and subject_id:
                subjects[subject_id] = item
    claims: list[dict[str, Any]] = []
    for assertion in collection(bundle, "assertions"):
        predicate = str(assertion.get("predicate") or "verified activity")
        subject = subjects.get(assertion.get("subject_id"), {})
        summary = (
            subject.get("title")
            or subject.get("name")
            or subject.get("tag")
            or subject.get("ref")
            or subject.get("sha")
            or predicate
        )
        claims.append(
            {
                **assertion,
                "kind": predicate,
                "section": _ASSERTION_SECTIONS.get(predicate, "project"),
                "summary": summary,
            }
        )
    return claims


def _claim_line(
    claim: dict[str, Any],
    evidence: dict[str, dict[str, Any]],
    actor_labels: dict[str, str],
    language: str,
    *,
    evidence_numbers: Mapping[str, str],
    allow_source_urls: bool = True,
    include_actor: bool = True,
) -> str:
    summary = _escape_text(
        claim.get("summary")
        or claim.get("title")
        or claim.get("kind")
        or "verified activity"
    )
    actor_id = claim.get("actor_id")
    actor = actor_labels.get(actor_id) if actor_id else None
    if actor and include_actor:
        summary = f"{summary} — {actor}"
    links = []
    for evidence_id in claim.get("evidence_ids") or []:
        item = evidence.get(evidence_id)
        if not item:
            continue
        url = item.get("url")
        number = evidence_numbers.get(str(evidence_id))
        if number is None:
            continue
        if allow_source_urls and url:
            links.append(_link(number, str(url)))
        else:
            links.append(f"[{number}]")
    suffix = f" ({', '.join(links)})" if links else ""
    return f"- {summary}{suffix}"


def _render_coverage(bundle: dict[str, Any], language: str) -> list[str]:
    labels = LABELS[language]
    coverage = bundle.get("coverage") or {}
    lines = [f"## {labels['coverage']}", ""]
    for observation in coverage.get("observations") or []:
        if not isinstance(observation, dict):
            continue
        source = _escape_text(observation.get("source") or "unknown")
        status = _escape_text(observation.get("status") or "unknown")
        note = _escape_text(observation.get("note") or "")
        provider_id = _escape_text(observation.get("provider_id") or "unknown-provider")
        repository_id = _escape_text(
            observation.get("repository_id") or "unknown-repository"
        )
        lines.append(
            f"- {source}: **{status}** — provider={provider_id}; repository={repository_id}"
            + (f" — {note}" if note else "")
        )
    if not (coverage.get("observations") or []):
        lines.append(f"- {labels['no_coverage']}")
    warnings = coverage.get("warnings") or []
    if warnings:
        lines.extend(["", f"### {labels['coverage_warnings']}", ""])
        for warning in warnings:
            if not isinstance(warning, dict):
                continue
            source = _escape_text(warning.get("source") or "unknown")
            status = _escape_text(warning.get("status") or "unknown")
            provider_id = _escape_text(warning.get("provider_id") or "unknown-provider")
            repository_id = _escape_text(
                warning.get("repository_id") or "unknown-repository"
            )
            code = _escape_text(warning.get("code") or "coverage_warning")
            message = _escape_text(
                warning.get("message") or "optional source is not complete"
            )
            failure_class = warning.get("failure_class")
            if not failure_class and isinstance(warning.get("failure_classes"), list):
                failure_class = ", ".join(
                    str(value)
                    for value in warning["failure_classes"]
                    if isinstance(value, str)
                )
            failure = (
                f"; failure={_escape_text(failure_class)}" if failure_class else ""
            )
            lines.append(
                f"- **{code}** — {source}: **{status}** — "
                f"provider={provider_id}; repository={repository_id} — {message}{failure}"
            )
    return lines


def _render_metadata(bundle: dict[str, Any], profile: str, language: str) -> list[str]:
    invocation = (
        bundle.get("invocation") if isinstance(bundle.get("invocation"), dict) else {}
    )
    generator = (
        invocation.get("generator")
        if isinstance(invocation.get("generator"), dict)
        else {}
    )
    generator_text = (
        f"{generator.get('name', 'unknown')}/{generator.get('version', 'unknown')}"
    )
    if generator.get("commit"):
        generator_text += f"@{generator['commit']}"
    return [
        f"## {LABELS[language]['report_metadata']}",
        "",
        f"- plan_id: `{_escape_text(bundle.get('plan_id'))}`",
        f"- invocation_id: `{_escape_text(invocation.get('id'))}`",
        f"- bundle_digest: `{_escape_text(bundle.get('bundle_digest'))}`",
        f"- generator: `{_escape_text(generator_text)}`",
        f"- profile: `{_escape_text(profile)}`",
        f"- language: `{_escape_text(language)}`",
        f"- policy: `{RENDER_POLICY_VERSION}`",
        "",
    ]


def _render_evidence_index(
    bundle: dict[str, Any],
    evidence_numbers: Mapping[str, str],
    language: str,
    *,
    allow_source_urls: bool,
) -> list[str]:
    items = sorted(
        collection(bundle, "evidence"), key=lambda item: str(item.get("id", ""))
    )
    if not items:
        return []
    retrievals = {
        item.get("id"): item
        for item in collection(bundle, "retrievals")
        if isinstance(item.get("id"), str)
    }
    lines = ["", f"## {LABELS[language]['evidence_index']}", ""]
    for item in items:
        evidence_id = str(item.get("id") or "")
        number = evidence_numbers[evidence_id]
        retrieval = retrievals.get(item.get("retrieval_id"), {})
        native = (
            item.get("native_identity")
            if isinstance(item.get("native_identity"), dict)
            else {}
        )
        native_text = (
            native.get("value")
            if native.get("state") == "known"
            else native.get("reason", "unavailable")
        )
        source_ref = (
            item.get("source_ref") or retrieval.get("target_ref") or "unavailable"
        )
        if not allow_source_urls and "://" in str(source_ref):
            source_ref = "[hidden]"
        retrieval_detail = "; ".join(
            f"{name}={_escape_text(value)}"
            for name, value in (
                ("mode", retrieval.get("mode")),
                ("endpoint", retrieval.get("endpoint_kind")),
                ("page", retrieval.get("page")),
                ("pagination", retrieval.get("pagination_outcome")),
                ("fetched_at", retrieval.get("fetched_at")),
                ("stored_at", retrieval.get("stored_at")),
                ("replayed_at", retrieval.get("replayed_at")),
            )
            if value is not None
        )
        description = (
            f"provider={_escape_text(item.get('provider_id'))}; "
            f"subject={_escape_text(item.get('subject_type'))}:{_escape_text(item.get('subject_id'))}; "
            f"source={_escape_text(item.get('source'))}; native={_escape_text(native_text)}; "
            f"retrieval={_escape_text(item.get('retrieval_id'))}; {retrieval_detail}; "
            f"source_ref={_escape_text(source_ref)}"
        )
        url = item.get("url")
        label = _link(number, str(url)) if allow_source_urls and url else f"[{number}]"
        lines.append(f"- {label} — {description}")
    return lines


def render_bundle(
    bundle: dict[str, Any],
    profile: str = "project-first",
    language: str = "en",
    *,
    display_actor_names: bool = False,
    actor_labels: Mapping[str, str] | None = None,
    allow_source_urls: bool = True,
) -> str:
    """Render a validated bundle using a deterministic built-in profile."""
    if profile not in PROFILES:
        raise RenderError(
            f"unknown profile: {profile}; choose from {', '.join(PROFILES)}"
        )
    if language not in LANGUAGES:
        raise RenderError(
            f"unknown language: {language}; choose from {', '.join(LANGUAGES)}"
        )
    issues = validate_bundle(bundle)
    blocking_issues = [issue for issue in issues if issue.severity == "error"]
    if blocking_issues:
        raise RenderError(
            "bundle is not render eligible:\n" + format_issues(blocking_issues)
        )

    labels = LABELS[language]
    repositories, evidence = _indexes(bundle)
    evidence_numbers = {
        evidence_id: f"E{position}"
        for position, evidence_id in enumerate(sorted(evidence), start=1)
    }
    rendered_actor_labels = _actor_labels(
        bundle,
        language,
        display_actor_names=display_actor_names,
        actor_labels=actor_labels,
    )
    claims = sorted(_renderable_claims(bundle), key=_claim_sort_key)
    window = bundle["plan"]["window"]
    lines = [
        f"# {labels['title']}",
        "",
        f"{labels['window']}: `{window['start']}` → `{window['end']}` ({window['timezone']})",
        "",
    ]
    lines.extend(_render_metadata(bundle, profile, language))

    if profile == "timeline":
        lines.extend([f"## {labels['timeline']}", ""])
        current_date = None
        for claim in claims:
            date = local_date(
                str(claim.get("occurred_at")), window["timezone"]
            ).isoformat()
            if date != current_date:
                if current_date is not None:
                    lines.append("")
                lines.append(f"### {date}")
                lines.append("")
                current_date = date
            lines.append(
                _claim_line(
                    claim,
                    evidence,
                    rendered_actor_labels,
                    language,
                    evidence_numbers=evidence_numbers,
                    allow_source_urls=allow_source_urls,
                )
            )
    elif profile == "actor-summary":
        lines.extend([f"## {labels['actors']}", "", f"> {labels['actor_warning']}", ""])
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for claim in claims:
            grouped[str(claim.get("actor_id") or "anonymous")].append(claim)
        for actor_id in sorted(grouped):
            lines.append(
                f"### {rendered_actor_labels.get(actor_id, labels['anonymous'])}"
            )
            lines.append("")
            for claim in grouped[actor_id]:
                lines.append(
                    _claim_line(
                        claim,
                        evidence,
                        rendered_actor_labels,
                        language,
                        evidence_numbers=evidence_numbers,
                        allow_source_urls=allow_source_urls,
                        include_actor=False,
                    )
                )
            lines.append("")
    else:
        project_claims: dict[str, list[dict[str, Any]]] = defaultdict(list)
        other_claims: list[dict[str, Any]] = []
        for claim in claims:
            repository_id = _claim_repository_id(claim)
            if repository_id and repository_id in repositories:
                project_claims[repository_id].append(claim)
            else:
                other_claims.append(claim)

        if profile == "release-focused":
            release_claims = [
                claim for claim in claims if str(claim.get("section")) == "release"
            ]
            lines.extend([f"## {labels['releases']}", ""])
            for claim in release_claims:
                lines.append(
                    _claim_line(
                        claim,
                        evidence,
                        rendered_actor_labels,
                        language,
                        evidence_numbers=evidence_numbers,
                        allow_source_urls=allow_source_urls,
                    )
                )
            if not release_claims:
                lines.append(f"- {labels['no_releases']}")
            lines.append("")

        heading = (
            labels["projects"]
            if profile == "project-first"
            else labels["project_activity"]
        )
        lines.extend([f"## {heading}", ""])
        for repository_id in sorted(project_claims):
            repository = repositories[repository_id]
            name = _escape_text(
                repository.get("full_name") or repository.get("name") or repository_id
            )
            lines.extend([f"### {name}", ""])
            for claim in project_claims[repository_id]:
                if (
                    profile == "release-focused"
                    and str(claim.get("section")) == "release"
                ):
                    continue
                lines.append(
                    _claim_line(
                        claim,
                        evidence,
                        rendered_actor_labels,
                        language,
                        evidence_numbers=evidence_numbers,
                        allow_source_urls=allow_source_urls,
                    )
                )
            lines.append("")
        if other_claims:
            lines.extend([f"## {labels['other']}", ""])
            for claim in other_claims:
                lines.append(
                    _claim_line(
                        claim,
                        evidence,
                        rendered_actor_labels,
                        language,
                        evidence_numbers=evidence_numbers,
                        allow_source_urls=allow_source_urls,
                    )
                )
            lines.append("")

    lines.extend(_render_coverage(bundle, language))
    lines.extend(
        _render_evidence_index(
            bundle,
            evidence_numbers,
            language,
            allow_source_urls=allow_source_urls,
        )
    )
    warning_issues = [issue for issue in issues if issue.severity == "warning"]
    if warning_issues:
        lines.extend(["", f"### {labels['validation_warnings']}", ""])
        for issue in warning_issues:
            lines.append(
                f"- **{_escape_text(issue.code)}** — {_escape_text(issue.path)}"
            )
    return "\n".join(lines).rstrip() + "\n"
