from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_COLLECTION_SUBJECT = {
    "work_items": ("work_item", "work_item.observed.v1"),
    "change_requests": ("change_request", "change_request.observed.v1"),
    "interactions": ("interaction", "interaction.observed.v1"),
    "commits": ("commit", "commit.observed.v1"),
    "ref_changes": ("ref_change", "ref_change.observed.v1"),
    "releases": ("release", "release.observed.v1"),
}


def build_assertions(bundle: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Derive typed claims from normalized entities and their recorded evidence."""
    evidence_by_subject: dict[tuple[str, str], list[str]] = {}
    for evidence in bundle.get("evidence", []):
        if not isinstance(evidence, dict):
            continue
        subject_type = evidence.get("subject_type")
        subject_id = evidence.get("subject_id")
        evidence_id = evidence.get("id")
        if all(
            isinstance(value, str) and value
            for value in (subject_type, subject_id, evidence_id)
        ):
            evidence_by_subject.setdefault((subject_type, subject_id), []).append(
                evidence_id
            )

    assertions: list[dict[str, Any]] = []
    for collection_name, (
        subject_type,
        default_predicate,
    ) in _COLLECTION_SUBJECT.items():
        for entity in bundle.get(collection_name, []):
            if not isinstance(entity, dict):
                continue
            subject_id = entity.get("id")
            occurred_at = entity.get("occurred_at")
            repository_id = entity.get("repository_id")
            evidence_ids = sorted(
                evidence_by_subject.get((subject_type, subject_id), [])
            )
            if not all(
                (
                    isinstance(subject_id, str) and subject_id,
                    isinstance(occurred_at, str) and occurred_at,
                    isinstance(repository_id, str) and repository_id,
                    bool(evidence_ids),
                )
            ):
                continue
            predicate = default_predicate
            if collection_name == "change_requests" and (
                entity.get("merged_at") is not None or entity.get("state") == "merged"
            ):
                predicate = "change_request.merged.v1"
            assertion: dict[str, Any] = {
                "id": f"assertion:{predicate}:{subject_id}",
                "subject_type": subject_type,
                "subject_id": subject_id,
                "predicate": predicate,
                "occurred_at": occurred_at,
                "repository_id": repository_id,
                "evidence_ids": evidence_ids,
            }
            actor_id = entity.get("actor_id")
            if isinstance(actor_id, str) and actor_id:
                assertion["actor_id"] = actor_id
            assertions.append(assertion)
    return sorted(assertions, key=lambda item: item["id"])
