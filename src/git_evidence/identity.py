from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import math
import os
from typing import Any, Mapping
import unicodedata
from uuid import uuid4

import rfc8785

from . import __version__


CANONICALIZATION = {
    "algorithm": "RFC8785",
    "version": "v1",
    "unicode_normalization": "NFC",
}
PLAN_DOMAIN = b"git-evidence:plan:v1\n"
BUNDLE_DOMAIN = b"git-evidence:bundle:v1\n"
CANONICAL_COLLECTIONS = (
    "providers",
    "repositories",
    "actors",
    "work_items",
    "change_requests",
    "interactions",
    "commits",
    "ref_changes",
    "releases",
    "retrievals",
    "evidence",
    "assertions",
)


class IdentityError(ValueError):
    """Canonical identity input cannot be represented without ambiguity."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _normalize_nfc(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise IdentityError("canonical identity input contains a non-finite number")
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize_nfc(item) for item in value]
    if isinstance(value, tuple):
        return [_normalize_nfc(item) for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise IdentityError("canonical identity objects require string keys")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise IdentityError(
                    "canonical identity object keys collide after NFC normalization"
                )
            normalized[normalized_key] = _normalize_nfc(child)
        return normalized
    raise IdentityError(
        f"canonical identity input contains unsupported {type(value).__name__}"
    )


def canonical_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(_normalize_nfc(value))
    except (rfc8785.CanonicalizationError, UnicodeError, ValueError) as exc:
        raise IdentityError(str(exc)) from exc


def _digest(prefix: bytes, value: Any, namespace: str) -> str:
    digest = sha256(prefix + canonical_bytes(value)).hexdigest()
    return f"{namespace}:sha256:{digest}"


def normalize_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    value = _normalize_nfc(deepcopy(dict(plan)))
    scope = value.get("scope")
    if isinstance(scope, dict):
        for key in ("repositories", "actors"):
            items = scope.get(key)
            if isinstance(items, list):
                items.sort(key=canonical_bytes)
    providers = value.get("providers")
    if isinstance(providers, list):
        for provider in providers:
            if not isinstance(provider, dict):
                continue
            selected_sources = provider.get("selected_sources")
            if isinstance(selected_sources, list):
                selected_sources.sort(key=canonical_bytes)
        providers.sort(
            key=lambda item: (
                str(item.get("kind", "")) if isinstance(item, dict) else "",
                str(item.get("instance", "")) if isinstance(item, dict) else "",
                canonical_bytes(item),
            )
        )
    return value


def compute_plan_id(plan: Mapping[str, Any]) -> str:
    return _digest(PLAN_DOMAIN, normalize_plan(plan), "plan")


def compute_artifact_bytes_digest(value: bytes) -> str:
    return f"artifact:sha256:{sha256(value).hexdigest()}"


def bundle_digest_input(bundle: Mapping[str, Any]) -> dict[str, Any]:
    value = _normalize_nfc(deepcopy(dict(bundle)))
    value.pop("bundle_digest", None)
    for key in CANONICAL_COLLECTIONS:
        collection = value.get(key)
        if isinstance(collection, list):
            collection.sort(
                key=lambda item: (
                    str(item.get("id", "")) if isinstance(item, dict) else "",
                    canonical_bytes(item),
                )
            )
    return value


def compute_bundle_digest(bundle: Mapping[str, Any]) -> str:
    return _digest(BUNDLE_DOMAIN, bundle_digest_input(bundle), "bundle")


def invocation_record(
    *,
    started_at: str | None = None,
    finished_at: str | None = None,
) -> dict[str, Any]:
    generator: dict[str, str] = {
        "name": "git-evidence",
        "version": __version__,
    }
    commit = os.environ.get("GIT_EVIDENCE_BUILD_COMMIT")
    if isinstance(commit, str) and commit:
        generator["commit"] = commit
    return {
        "id": f"invocation:{uuid4()}",
        "started_at": started_at or utc_now(),
        "finished_at": finished_at or utc_now(),
        "generator": generator,
    }
