from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping

from .identity import (
    CANONICALIZATION,
    compute_bundle_digest,
    compute_plan_id,
    invocation_record,
    normalize_plan,
    utc_now,
)


class MigrationError(ValueError):
    """A legacy artifact cannot be explicitly migrated to the latest schema."""


PREDICATE_BY_FACT_KIND = {
    "work_item_observed": "work_item.observed.v1",
    "change_request_observed": "change_request.observed.v1",
    "change_request_merged": "change_request.merged.v1",
    "interaction_observed": "interaction.observed.v1",
    "commit_observed": "commit.observed.v1",
    "ref_change_observed": "ref_change.observed.v1",
    "release_observed": "release.observed.v1",
    "release_published": "release.published.v1",
}

_ENTITY_FIELDS = {
    "providers": {"id", "kind", "instance", "capabilities", "extensions"},
    "repositories": {"id", "provider_id", "full_name", "name", "web_url", "extensions"},
    "actors": {"id", "provider_id", "source_id", "handle", "extensions"},
    "work_items": {
        "id", "repository_id", "actor_id", "occurred_at", "kind", "number",
        "title", "state", "web_url", "extensions",
    },
    "change_requests": {
        "id", "repository_id", "actor_id", "occurred_at", "kind", "number",
        "title", "state", "merged_at", "web_url", "extensions",
    },
    "interactions": {
        "id", "repository_id", "actor_id", "occurred_at", "kind", "subject_type",
        "subject_id", "subject_number", "body_collected", "web_url", "extensions",
    },
    "commits": {
        "id", "repository_id", "actor_id", "occurred_at", "title", "sha",
        "hash_algorithm", "web_url", "extensions",
    },
    "ref_changes": {
        "id", "repository_id", "actor_id", "occurred_at", "kind", "ref",
        "change_association", "commit_ids", "commit_shas", "change_request_ids",
        "evidence_ids", "web_url", "extensions",
    },
    "releases": {
        "id", "repository_id", "actor_id", "occurred_at", "name", "tag",
        "web_url", "extensions",
    },
    "evidence": {
        "id", "provider_id", "subject_type", "subject_id", "source", "url",
        "source_ref", "extensions",
    },
}


def _utc_timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise MigrationError("legacy timestamps must be timezone-aware")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _normalize_timestamps(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                _utc_timestamp(child)
                if isinstance(child, str)
                and (key in {"start", "end"} or key.endswith("_at"))
                else _normalize_timestamps(child)
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_normalize_timestamps(item) for item in value]
    return value


def _legacy_plan(bundle: Mapping[str, Any]) -> dict[str, Any]:
    run = bundle.get("run") if isinstance(bundle.get("run"), dict) else {}
    coverage = (
        bundle.get("coverage") if isinstance(bundle.get("coverage"), dict) else {}
    )
    observations = coverage.get("observations")
    sources_by_provider: dict[str, set[str]] = {}
    if isinstance(observations, list):
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            provider_id = observation.get("provider_id")
            source = observation.get("source")
            if isinstance(provider_id, str) and isinstance(source, str):
                sources_by_provider.setdefault(provider_id, set()).add(source)
    providers: list[dict[str, Any]] = []
    for provider in bundle.get("providers", []):
        if not isinstance(provider, dict):
            continue
        provider_id = provider.get("id")
        kind = provider.get("kind")
        instance = provider.get("instance")
        if not all(isinstance(value, str) and value for value in (provider_id, kind, instance)):
            continue
        providers.append(
            {
                "kind": kind,
                "instance": instance,
                "selected_sources": sorted(sources_by_provider.get(provider_id, set())),
            }
        )
    providers.sort(key=lambda item: (item["kind"], item["instance"]))
    return normalize_plan({
        "origin": "legacy_migration",
        "window": deepcopy(run.get("window")),
        "scope": deepcopy(run.get("scope")),
        "providers": providers,
    })


def _provider_kind_indexes(
    bundle: Mapping[str, Any],
) -> tuple[dict[str, str], dict[str, str]]:
    provider_kinds = {
        item.get("id"): item.get("kind")
        for item in bundle.get("providers", [])
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and isinstance(item.get("kind"), str)
    }
    repository_kinds: dict[str, str] = {}
    for item in bundle.get("repositories", []):
        if not isinstance(item, dict):
            continue
        repository_id = item.get("id")
        provider_id = item.get("provider_id")
        kind = provider_kinds.get(provider_id)
        if isinstance(repository_id, str) and isinstance(kind, str):
            repository_kinds[repository_id] = kind
    return provider_kinds, repository_kinds


def _record_provider_kind(
    key: str,
    item: Mapping[str, Any],
    provider_kinds: Mapping[str, str],
    repository_kinds: Mapping[str, str],
) -> str:
    if key == "providers" and isinstance(item.get("kind"), str):
        return str(item["kind"])
    provider_kind = provider_kinds.get(item.get("provider_id"))
    if isinstance(provider_kind, str):
        return provider_kind
    repository_kind = repository_kinds.get(item.get("repository_id"))
    return repository_kind if isinstance(repository_kind, str) else "legacy"


def _strict_record(
    key: str,
    item: Mapping[str, Any],
    *,
    provider_kind: str,
) -> dict[str, Any]:
    allowed = _ENTITY_FIELDS[key]
    record = {name: deepcopy(value) for name, value in item.items() if name in allowed}
    unknown = {
        name: deepcopy(value)
        for name, value in item.items()
        if name not in allowed
    }
    if unknown:
        extensions = record.get("extensions")
        if not isinstance(extensions, dict):
            extensions = {}
        namespace = extensions.get(provider_kind)
        if not isinstance(namespace, dict):
            namespace = {}
        legacy_fields = namespace.get("legacy_fields")
        if not isinstance(legacy_fields, dict):
            legacy_fields = {}
        legacy_fields.update(unknown)
        namespace["legacy_fields"] = legacy_fields
        extensions[provider_kind] = namespace
        record["extensions"] = extensions
    return record


def _migrate_entities(bundle: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    provider_kinds, repository_kinds = _provider_kind_indexes(bundle)
    result: dict[str, list[dict[str, Any]]] = {}
    for key in (
        "providers", "repositories", "actors", "work_items", "change_requests",
        "interactions", "commits", "ref_changes", "releases",
    ):
        records: list[dict[str, Any]] = []
        for item in bundle.get(key, []):
            if not isinstance(item, dict):
                continue
            records.append(
                _strict_record(
                    key,
                    item,
                    provider_kind=_record_provider_kind(
                        key, item, provider_kinds, repository_kinds
                    ),
                )
            )
        result[key] = records
    return result


def _legacy_retrievals(
    bundle: Mapping[str, Any], source_artifact_digest: str
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    retrievals: list[dict[str, Any]] = []
    by_provider: dict[str, str] = {}
    digest_suffix = source_artifact_digest.rsplit(":", 1)[-1][:16]
    for provider in bundle.get("providers", []):
        if not isinstance(provider, dict):
            continue
        provider_id = provider.get("id")
        if not isinstance(provider_id, str) or not provider_id:
            continue
        retrieval_id = f"retrieval:legacy:{digest_suffix}:{len(retrievals) + 1}"
        by_provider[provider_id] = retrieval_id
        retrievals.append(
            {
                "id": retrieval_id,
                "provider_id": provider_id,
                "mode": "legacy_import",
                "endpoint_kind": "legacy_bundle",
                "target_ref": "schema:0.1",
                "source_artifact_digest": source_artifact_digest,
            }
        )
    return retrievals, by_provider


def _migrate_evidence(
    bundle: Mapping[str, Any], retrieval_by_provider: Mapping[str, str]
) -> list[dict[str, Any]]:
    provider_kinds, repository_kinds = _provider_kind_indexes(bundle)
    result: list[dict[str, Any]] = []
    for legacy in bundle.get("evidence", []):
        if not isinstance(legacy, dict):
            continue
        evidence = _strict_record(
            "evidence",
            legacy,
            provider_kind=_record_provider_kind(
                "evidence", legacy, provider_kinds, repository_kinds
            ),
        )
        provider_id = evidence.get("provider_id")
        retrieval_id = retrieval_by_provider.get(provider_id)
        if retrieval_id:
            evidence["retrieval_id"] = retrieval_id
        evidence["native_identity"] = {
            "state": "unavailable",
            "reason": "not_recorded_in_schema_0.1",
        }
        result.append(evidence)
    return result


def _migrate_assertions(bundle: Mapping[str, Any]) -> list[dict[str, Any]]:
    evidence_index = {
        item.get("id"): item
        for item in bundle.get("evidence", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    assertions: list[dict[str, Any]] = []
    for legacy in bundle.get("facts", []):
        if not isinstance(legacy, dict):
            continue
        kind = legacy.get("kind")
        predicate = PREDICATE_BY_FACT_KIND.get(kind)
        evidence_ids = legacy.get("evidence_ids")
        first_evidence = (
            evidence_index.get(evidence_ids[0])
            if isinstance(evidence_ids, list) and evidence_ids
            else None
        )
        subject_type = legacy.get("subject_type")
        subject_id = legacy.get("subject_id")
        if isinstance(first_evidence, dict):
            subject_type = subject_type or first_evidence.get("subject_type")
            subject_id = subject_id or first_evidence.get("subject_id")
        legacy_id = legacy.get("id")
        if not all(
            (
                isinstance(legacy_id, str) and legacy_id,
                isinstance(predicate, str) and predicate,
                isinstance(subject_type, str) and subject_type,
                isinstance(subject_id, str) and subject_id,
                isinstance(evidence_ids, list) and bool(evidence_ids),
            )
        ):
            raise MigrationError(f"legacy fact {legacy_id!r} cannot become a typed assertion")
        assertion: dict[str, Any] = {
            "id": legacy_id.replace("fact:", "assertion:", 1),
            "subject_type": subject_type,
            "subject_id": subject_id,
            "predicate": predicate,
            "occurred_at": legacy.get("occurred_at"),
            "repository_id": legacy.get("repository_id"),
            "evidence_ids": list(evidence_ids),
        }
        actor_id = legacy.get("actor_id")
        if isinstance(actor_id, str) and actor_id:
            assertion["actor_id"] = actor_id
        assertions.append(assertion)
    return assertions


def migrate_v01_to_v02(
    bundle: Mapping[str, Any],
    *,
    source_artifact_digest: str,
    migrated_at: str | None = None,
) -> dict[str, Any]:
    """Explicitly migrate a validated v0.1 artifact without mutating it."""
    if bundle.get("schema_version") != "0.1":
        raise MigrationError("only schema_version 0.1 can be migrated to 0.2")
    from .validation import validate_bundle

    blockers = [issue for issue in validate_bundle(dict(bundle)) if issue.severity == "error"]
    if blockers:
        raise MigrationError("legacy bundle must validate before migration")
    artifact_digest = source_artifact_digest
    timestamp = migrated_at or utc_now()
    plan = _legacy_plan(bundle)
    entities = _migrate_entities(bundle)
    retrievals, retrieval_by_provider = _legacy_retrievals(bundle, artifact_digest)
    coverage = deepcopy(bundle.get("coverage"))
    if not isinstance(coverage, dict):
        raise MigrationError("legacy bundle has no coverage object")
    render_eligible = coverage.pop("allow_publish", None)
    coverage.setdefault("group_failures", [])
    coverage["render_eligible"] = render_eligible
    privacy = deepcopy(bundle.get("privacy"))
    if not isinstance(privacy, dict):
        privacy = {
            "actor_display": "anonymous",
            "source_urls": "sanitized",
            "auth_redaction": True,
        }
    result: dict[str, Any] = {
        "schema_version": "0.2",
        "canonicalization": deepcopy(CANONICALIZATION),
        "plan_id": compute_plan_id(plan),
        "plan": plan,
        "invocation": invocation_record(started_at=timestamp, finished_at=timestamp),
        **entities,
        "retrievals": retrievals,
        "evidence": _migrate_evidence(bundle, retrieval_by_provider),
        "assertions": _migrate_assertions(bundle),
        "collection": deepcopy(bundle.get("collection", {})),
        "privacy": privacy,
        "coverage": coverage,
        "migration": {
            "source_schema_version": "0.1",
            "source_artifact_digest": artifact_digest,
            "migrated_at": timestamp,
        },
    }
    result = _normalize_timestamps(result)
    result["plan"] = normalize_plan(result["plan"])
    result["plan_id"] = compute_plan_id(result["plan"])
    result["bundle_digest"] = compute_bundle_digest(result)
    target_blockers = [
        issue
        for issue in validate_bundle(result)
        if issue.severity == "error"
    ]
    if target_blockers:
        codes = ", ".join(sorted({issue.code for issue in target_blockers}))
        raise MigrationError(f"migrated 0.2 bundle is invalid: {codes}")
    return result
