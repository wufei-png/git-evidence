from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from typing import Any

from .model import collection
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
        "evidence": "evidence",
        "anonymous": "anonymous actor",
        "actor_warning": "Actor view is informational only; it is not a productivity or performance score.",
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
        "evidence": "证据",
        "anonymous": "匿名成员",
        "actor_warning": "人员视图仅用于信息回顾，不代表生产力或绩效评分。",
    },
}


class RenderError(ValueError):
    """The bundle cannot be safely rendered."""


def _escape_text(value: Any) -> str:
    text = str(value or "").replace("\n", " ").strip()
    return text.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def _link(label: str, url: str) -> str:
    return f"[{_escape_text(label)}](<{url}>)"


def _actor_labels(bundle: dict[str, Any], language: str) -> dict[str, str]:
    labels = LABELS[language]
    actors = sorted(collection(bundle, "actors"), key=lambda item: str(item.get("id", "")))
    result: dict[str, str] = {}
    anonymous_number = 0
    for actor in actors:
        actor_id = actor.get("id")
        if not actor_id:
            continue
        display = actor.get("display_name") or actor.get("public_label")
        if display:
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


def _fact_line(
    fact: dict[str, Any],
    evidence: dict[str, dict[str, Any]],
    actor_labels: dict[str, str],
    language: str,
) -> str:
    labels = LABELS[language]
    summary = _escape_text(fact.get("summary") or fact.get("title") or fact.get("kind") or "verified activity")
    actor_id = fact.get("actor_id")
    actor = actor_labels.get(actor_id) if actor_id else None
    if actor:
        summary = f"{summary} — {actor}"
    links = []
    for evidence_id in fact.get("evidence_ids") or []:
        item = evidence.get(evidence_id)
        if not item:
            continue
        url = item.get("url")
        if url:
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
        lines.append(f"- `{source}`: **{status}**" + (f" — {note}" if note else ""))
    if not (coverage.get("observations") or []):
        lines.append("- No coverage observations.")
    return lines


def render_bundle(
    bundle: dict[str, Any], profile: str = "project-first", language: str = "en"
) -> str:
    """Render a validated bundle using a deterministic built-in profile."""
    if profile not in PROFILES:
        raise RenderError(f"unknown profile: {profile}; choose from {', '.join(PROFILES)}")
    if language not in LANGUAGES:
        raise RenderError(f"unknown language: {language}; choose from {', '.join(LANGUAGES)}")
    issues = validate_bundle(bundle)
    if issues:
        raise RenderError("bundle is not publishable:\n" + format_issues(issues))

    labels = LABELS[language]
    repositories, evidence = _indexes(bundle)
    actor_labels = _actor_labels(bundle, language)
    facts = sorted(collection(bundle, "facts"), key=_fact_sort_key)
    window = bundle["run"]["window"]
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
            lines.append(_fact_line(fact, evidence, actor_labels, language))
    elif profile == "actor-summary":
        lines.extend([f"## {labels['actors']}", "", f"> {labels['actor_warning']}", ""])
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for fact in facts:
            grouped[str(fact.get("actor_id") or "anonymous")].append(fact)
        for actor_id in sorted(grouped):
            lines.append(f"### {actor_labels.get(actor_id, labels['anonymous'])}")
            lines.append("")
            for fact in grouped[actor_id]:
                lines.append(_fact_line(fact, evidence, actor_labels, language))
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
                lines.append(_fact_line(fact, evidence, actor_labels, language))
            if not release_facts:
                lines.append("- No verified releases or release changes.")
            lines.append("")

        heading = labels["projects"] if profile == "project-first" else labels["project_activity"]
        lines.extend([f"## {heading}", ""])
        for repository_id in sorted(project_facts):
            repository = repositories[repository_id]
            name = _escape_text(repository.get("full_name") or repository.get("name") or repository_id)
            lines.extend([f"### `{name}`", ""])
            for fact in project_facts[repository_id]:
                if profile == "release-focused" and str(fact.get("section")) == "release":
                    continue
                lines.append(_fact_line(fact, evidence, actor_labels, language))
            lines.append("")
        if other_facts:
            lines.extend([f"## {labels['other']}", ""])
            for fact in other_facts:
                lines.append(_fact_line(fact, evidence, actor_labels, language))
            lines.append("")

    lines.extend(_render_coverage(bundle, language))
    return "\n".join(lines).rstrip() + "\n"
