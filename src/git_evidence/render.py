from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from html import escape as html_escape
from typing import Any, Mapping
from urllib.parse import quote

from .model import collection
from .privacy import sanitize_public_url
from .validation import format_issues, validate_bundle

PROFILES = ("project-first", "timeline", "release-focused", "actor-summary")
LANGUAGES = ("en", "zh-CN")

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
        f"U+{ord(character):04X}"
        if ord(character) in visual_controls
        else character
        for character in text
    )
    text = html_escape(text, quote=False)
    markdown_punctuation = r"\\`*_[\]{}()#+\-.!|>"
    return "".join(f"\\{character}" if character in markdown_punctuation else character for character in text)


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
    actors = sorted(collection(bundle, "actors"), key=lambda item: str(item.get("id", "")))
    result: dict[str, str] = {}
    anonymous_number = 0
    for actor in actors:
        actor_id = actor.get("id")
        if not actor_id:
            continue
        display = actor_labels.get(actor_id) if display_actor_names and actor_labels else None
        if isinstance(display, str) and display.strip():
            result[actor_id] = _escape_text(display)
            continue
        anonymous_number += 1
        digest = sha256(str(actor_id).encode("utf-8")).hexdigest()[:6]
        result[actor_id] = f"{labels['anonymous']} {anonymous_number} ({digest})"
    return result


def _indexes(bundle: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    repositories = {item["id"]: item for item in collection(bundle, "repositories") if item.get("id")}
    evidence = {item["id"]: item for item in collection(bundle, "evidence") if item.get("id")}
    return repositories, evidence


def _fact_sort_key(fact: dict[str, Any]) -> tuple[str, str]:
    return (str(fact.get("occurred_at") or ""), str(fact.get("id") or ""))


def _fact_repository_id(fact: dict[str, Any]) -> str | None:
    repository_id = fact.get("repository_id")
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
    if bundle.get("schema_version") != "0.2":
        return collection(bundle, "facts")
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


def _fact_line(
    fact: dict[str, Any],
    evidence: dict[str, dict[str, Any]],
    actor_labels: dict[str, str],
    language: str,
    *,
    allow_source_urls: bool = True,
    include_actor: bool = True,
) -> str:
    labels = LABELS[language]
    summary = _escape_text(fact.get("summary") or fact.get("title") or fact.get("kind") or "verified activity")
    actor_id = fact.get("actor_id")
    actor = actor_labels.get(actor_id) if actor_id else None
    if actor and include_actor:
        summary = f"{summary} — {actor}"
    links = []
    for evidence_id in fact.get("evidence_ids") or []:
        item = evidence.get(evidence_id)
        if not item:
            continue
        url = item.get("url")
        if allow_source_urls and url:
            links.append(_link(labels["evidence"], str(url)))
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
        lines.append(f"- {source}: **{status}**" + (f" — {note}" if note else ""))
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
            repository_id = _escape_text(warning.get("repository_id") or "unknown-repository")
            code = _escape_text(warning.get("code") or "coverage_warning")
            message = _escape_text(warning.get("message") or "optional source is not complete")
            failure_class = warning.get("failure_class")
            if not failure_class and isinstance(warning.get("failure_classes"), list):
                failure_class = ", ".join(
                    str(value) for value in warning["failure_classes"] if isinstance(value, str)
                )
            failure = f"; failure={_escape_text(failure_class)}" if failure_class else ""
            lines.append(
                f"- **{code}** — {source}: **{status}** — "
                f"provider={provider_id}; repository={repository_id} — {message}{failure}"
            )
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
        raise RenderError(f"unknown profile: {profile}; choose from {', '.join(PROFILES)}")
    if language not in LANGUAGES:
        raise RenderError(f"unknown language: {language}; choose from {', '.join(LANGUAGES)}")
    issues = validate_bundle(bundle)
    blocking_issues = [issue for issue in issues if issue.severity == "error"]
    if blocking_issues:
        raise RenderError(
            "bundle is not publishable:\n" + format_issues(blocking_issues)
        )

    labels = LABELS[language]
    repositories, evidence = _indexes(bundle)
    rendered_actor_labels = _actor_labels(
        bundle,
        language,
        display_actor_names=display_actor_names,
        actor_labels=actor_labels,
    )
    facts = sorted(_renderable_claims(bundle), key=_fact_sort_key)
    run_or_plan = bundle["plan"] if bundle.get("schema_version") == "0.2" else bundle["run"]
    window = run_or_plan["window"]
    lines = [
        f"# {labels['title']}",
        "",
        f"{labels['window']}: `{window['start']}` → `{window['end']}` ({window['timezone']})",
        "",
    ]

    if profile == "timeline":
        lines.extend([f"## {labels['timeline']}", ""])
        current_date = None
        for fact in facts:
            date = str(fact.get("occurred_at") or "unknown")[:10]
            if date != current_date:
                if current_date is not None:
                    lines.append("")
                lines.append(f"### {date}")
                lines.append("")
                current_date = date
            lines.append(
                _fact_line(
                    fact,
                    evidence,
                    rendered_actor_labels,
                    language,
                    allow_source_urls=allow_source_urls,
                )
            )
    elif profile == "actor-summary":
        lines.extend([f"## {labels['actors']}", "", f"> {labels['actor_warning']}", ""])
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for fact in facts:
            grouped[str(fact.get("actor_id") or "anonymous")].append(fact)
        for actor_id in sorted(grouped):
            lines.append(f"### {rendered_actor_labels.get(actor_id, labels['anonymous'])}")
            lines.append("")
            for fact in grouped[actor_id]:
                lines.append(
                    _fact_line(
                        fact,
                        evidence,
                        rendered_actor_labels,
                        language,
                        allow_source_urls=allow_source_urls,
                        include_actor=False,
                    )
                )
            lines.append("")
    else:
        project_facts: dict[str, list[dict[str, Any]]] = defaultdict(list)
        other_facts: list[dict[str, Any]] = []
        for fact in facts:
            repository_id = _fact_repository_id(fact)
            if repository_id and repository_id in repositories:
                project_facts[repository_id].append(fact)
            else:
                other_facts.append(fact)

        if profile == "release-focused":
            release_facts = [fact for fact in facts if str(fact.get("section")) == "release"]
            lines.extend([f"## {labels['releases']}", ""])
            for fact in release_facts:
                lines.append(
                    _fact_line(
                        fact,
                        evidence,
                        rendered_actor_labels,
                        language,
                        allow_source_urls=allow_source_urls,
                    )
                )
            if not release_facts:
                lines.append(f"- {labels['no_releases']}")
            lines.append("")

        heading = labels["projects"] if profile == "project-first" else labels["project_activity"]
        lines.extend([f"## {heading}", ""])
        for repository_id in sorted(project_facts):
            repository = repositories[repository_id]
            name = _escape_text(repository.get("full_name") or repository.get("name") or repository_id)
            lines.extend([f"### {name}", ""])
            for fact in project_facts[repository_id]:
                if profile == "release-focused" and str(fact.get("section")) == "release":
                    continue
                lines.append(
                    _fact_line(
                        fact,
                        evidence,
                        rendered_actor_labels,
                        language,
                        allow_source_urls=allow_source_urls,
                    )
                )
            lines.append("")
        if other_facts:
            lines.extend([f"## {labels['other']}", ""])
            for fact in other_facts:
                lines.append(
                    _fact_line(
                        fact,
                        evidence,
                        rendered_actor_labels,
                        language,
                        allow_source_urls=allow_source_urls,
                    )
                )
            lines.append("")

    lines.extend(_render_coverage(bundle, language))
    warning_issues = [issue for issue in issues if issue.severity == "warning"]
    if warning_issues:
        lines.extend(["", f"### {labels['validation_warnings']}", ""])
        for issue in warning_issues:
            lines.append(
                f"- **{_escape_text(issue.code)}** — {_escape_text(issue.path)}"
            )
    return "\n".join(lines).rstrip() + "\n"
