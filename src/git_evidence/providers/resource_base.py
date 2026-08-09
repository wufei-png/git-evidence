from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from typing import Any
from urllib.parse import unquote, urlsplit

from ..bounds import (
    InputLimitError,
    indented_json_growth_upper_bound,
    json_size_with_limit,
)
from ..limits import MAX_BUNDLE_BYTES, MAX_NORMALIZED_ENTITIES, MAX_PAGES
from ..privacy import PrivacyError, sanitize_public_payload
from ..time import TimeValueError, normalize_utc, parse_instant
from .base import (
    ACTIVITY_SOURCES,
    CAPABILITY_STATES,
    CHANGE_REQUEST_COVERAGE_SOURCES,
    CORE_RESOURCE_SOURCES,
    OPERATIONAL_FAILURE_CLASSES,
    RESOURCE_SOURCES,
    CollectionRequest,
    ProviderDescriptor,
    ProviderNotReady,
    RepositoryTarget,
    append_optional_coverage_warning,
    coverage_blocker,
    git_object_id_algorithm,
    instance_web_base,
    is_verifiable_sha,
    merge_capability_status,
    validate_instance,
)
from .transport import (
    DOCUMENTED_SHORT_PAGE_PAGINATION,
    ApiError,
    JsonTransport,
    PageResult,
    PaginationCursor,
    PaginationStrategy,
    ResponseShapeError,
    failure_class_for_status,
    is_success_status,
    new_response_correlation_key,
    response_retrieval_provenance,
    response_status_error,
    transport_metrics,
    validate_json_value_limits,
)


@dataclass
class SourceResult:
    items: list[dict[str, Any]] = dataclass_field(default_factory=list)
    status: str = "supported"
    note: str = ""
    diagnostics: dict[str, Any] = dataclass_field(default_factory=dict)
    retrievals: list[dict[str, Any]] = dataclass_field(default_factory=list)
    item_retrieval_keys: list[str] = dataclass_field(default_factory=list)


@dataclass
class RepositorySnapshot:
    repository: dict[str, Any] | None = None
    sources: dict[str, SourceResult] = dataclass_field(default_factory=dict)
    retrievals: list[dict[str, Any]] = dataclass_field(default_factory=list)


@dataclass
class PageSourceRequest:
    """Provider-owned description of one independently schedulable page source."""

    target: RepositoryTarget
    source: str
    path: str
    params: dict[str, Any]
    normalizer: Callable[[dict[str, Any]], dict[str, Any]]
    filter_item: Callable[[Any], bool] | None = None
    subject_type: str = ""
    subject_id: str = ""
    endpoint_kind: str = ""
    cursor: PaginationCursor | None = None
    result: SourceResult | None = None


@dataclass
class _RootRequest:
    target: RepositoryTarget
    path: str
    request_cursor: Any | None = None
    snapshot: RepositorySnapshot | None = None
    done: bool = False


class StrictNormalizationError(ResponseShapeError):
    """A native item cannot be represented without inventing identity or time."""


EXPECTED_PROVIDER_FAILURES = (ApiError, ProviderNotReady, PrivacyError)
MALFORMED_NORMALIZATION_ERRORS = (ResponseShapeError,)


def is_valid_native_id(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return False
    text = str(value).strip()
    return bool(text) and text.lower() not in {"none", "null"}


def validate_repository_identity(
    raw: Any,
    target: RepositoryTarget,
    *,
    identity_field: str,
) -> None:
    """Reject a repository root response that is not the requested target."""
    if not isinstance(raw, dict):
        raise ResponseShapeError("repository response must be an object")
    expected_full_name = f"{target.owner}/{target.name}"
    if raw.get(identity_field) != expected_full_name or raw.get("name") != target.name:
        raise ResponseShapeError(
            "repository response identity does not match the requested target"
        )
    for value in _direct_identity_url_values(raw):
        if not isinstance(value, str) or not repository_url_matches_target(
            value, target
        ):
            raise ResponseShapeError(
                "repository response URL does not match the requested target"
            )


def native_id(item: dict[str, Any], *fields: str) -> Any:
    for field in fields:
        value = item.get(field)
        if is_valid_native_id(value):
            return value
    raise StrictNormalizationError(
        "provider response omitted a stable native identifier: " + ", ".join(fields)
    )


def in_window_or_malformed(item: Any, request: CollectionRequest, *fields: str) -> bool:
    """Use the same first-occurrence selector as the normalizer."""
    if not isinstance(item, dict):
        return True
    value = occurrence_timestamp(item, *fields)
    if value is None:
        return True
    if parse_timestamp(value) is None:
        return True
    return in_window(value, request)


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return parse_instant(value)
    except TimeValueError:
        return None


def in_window(value: Any, request: CollectionRequest) -> bool:
    timestamp = parse_timestamp(value)
    start = parse_timestamp(request.window_start)
    end = parse_timestamp(request.window_end)
    if timestamp is None or start is None or end is None:
        return False
    return start <= timestamp.astimezone(start.tzinfo) < end.astimezone(start.tzinfo)


def occurrence_timestamp(item: dict[str, Any], *fields: str) -> str | None:
    for field in fields:
        value = item.get(field)
        if isinstance(value, str) and value:
            try:
                return normalize_utc(value)
            except TimeValueError:
                return value
    return None


def first_timestamp(item: dict[str, Any], *fields: str) -> str | None:
    """Select and UTC-normalize the first declared occurrence timestamp."""
    return occurrence_timestamp(item, *fields)


def actor_from(item: dict[str, Any], *fields: str) -> dict[str, Any] | None:
    for field in fields:
        value = item.get(field)
        if isinstance(value, dict):
            source_id = (
                value.get("id")
                or value.get("node_id")
                or value.get("login")
                or value.get("username")
            )
            if source_id is not None:
                return {
                    "source_id": str(source_id),
                    "handle": value.get("login")
                    or value.get("username")
                    or value.get("name"),
                }
    return None


def page_result_to_source(result: PageResult, source: str) -> SourceResult:
    if result.complete:
        return SourceResult(
            result.items,
            "supported",
            f"{result.pages} page(s)",
            result.diagnostics or {},
            result.retrievals,
            result.item_retrieval_keys,
        )
    return SourceResult(
        result.items,
        "incomplete",
        f"{source} pagination reached the configured page limit",
        result.diagnostics or {},
        result.retrievals,
        result.item_retrieval_keys,
    )


def api_error_diagnostics(error: ApiError) -> dict[str, Any]:
    diagnostics: dict[str, Any] = {
        "attempts": error.attempts,
        "retryable": error.retryable,
    }
    failure_class = error.failure_class
    if failure_class is None:
        if isinstance(error, ResponseShapeError):
            failure_class = "malformed_response"
        elif error.status_code is not None:
            failure_class = failure_class_for_status(error.status_code)
        else:
            failure_class = "transport_error"
    diagnostics["failure_class"] = failure_class
    if len(error.failure_classes) > 1:
        diagnostics["failure_classes"] = list(error.failure_classes)
    if error.status_code is not None:
        diagnostics["status_code"] = error.status_code
    if error.retry_after is not None:
        diagnostics["retry_after_seconds"] = error.retry_after
    if error.rate_limit:
        diagnostics["rate_limit"] = dict(error.rate_limit)
    if error.pagination_outcome:
        diagnostics["pagination"] = {
            "outcome": error.pagination_outcome,
            "complete": False,
        }
    return diagnostics


def exception_diagnostics(error: Exception) -> dict[str, Any]:
    """Map typed provider failures to the public failure-class contract."""
    if isinstance(error, ApiError):
        return api_error_diagnostics(error)
    if isinstance(error, ProviderNotReady):
        return {"failure_class": "provider_not_ready"}
    if isinstance(error, PrivacyError):
        return {"failure_class": "privacy_violation"}
    raise error


def optional_activity_failure_sources(error: Exception) -> dict[str, SourceResult]:
    """Convert an optional activity exception without discarding core resources."""
    diagnostics = exception_diagnostics(error)
    return {
        source: SourceResult(
            [],
            "incomplete",
            "optional activity/ref collection failed; coverage warning emitted",
            dict(diagnostics),
        )
        for source in ACTIVITY_SOURCES
    }


def _identity_containers(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    containers: list[dict[str, Any]] = []
    pending = [value]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        containers.append(current)
        for field in (
            "repository",
            "project",
            "repo",
            "source_project",
            "target_project",
            "base",
            "head",
            "_links",
            "references",
        ):
            nested = current.get(field)
            if isinstance(nested, dict):
                pending.append(nested)
    return containers


def _url_segments(path: str) -> list[str]:
    return [unquote(segment) for segment in path.split("/") if segment]


def _path_has_prefix(path_segments: list[str], prefix: list[str]) -> bool:
    if not prefix or len(path_segments) < len(prefix):
        return False
    if path_segments[: len(prefix) - 1] != prefix[:-1]:
        return False
    repository_segment = prefix[-1]
    accepted_repository_segments = {repository_segment}
    if not repository_segment.endswith(".git"):
        accepted_repository_segments.add(f"{repository_segment}.git")
    return path_segments[len(prefix) - 1] in accepted_repository_segments


def _effective_port(scheme: str, port: int | None) -> int | None:
    if port is not None:
        return port
    return {"http": 80, "https": 443}.get(scheme)


def _authority_matches(
    parsed: Any, *, scheme: str, hostname: str, port: int | None
) -> bool:
    return (
        parsed.scheme == scheme
        and isinstance(parsed.hostname, str)
        and parsed.hostname.lower() == hostname.lower()
        and _effective_port(parsed.scheme, parsed.port) == _effective_port(scheme, port)
    )


def repository_url_matches_target(value: str, target: RepositoryTarget) -> bool:
    """Check a provider web/API URL against the exact repository target."""
    try:
        parsed = urlsplit(value)
        base = urlsplit(instance_web_base(target.instance))
    except (TypeError, ValueError):
        return False
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    if not base.hostname:
        return False
    path_segments = _url_segments(parsed.path)
    repository_segments = [
        segment for segment in f"{target.owner}/{target.name}".split("/") if segment
    ]
    if not repository_segments:
        return False
    base_segments = _url_segments(base.path)
    web_prefix = [*base_segments, *repository_segments]
    authorities = [(base.scheme, base.hostname, base.port, web_prefix)]

    api_base_segments = [*base_segments, "api"]
    if target.provider_kind == "github":
        api_base_segments.append("v3")
        api_prefix = [*api_base_segments, "repos", *repository_segments]
        if target.instance == "github.com":
            authorities.append(
                ("https", "api.github.com", None, ["repos", *repository_segments])
            )
    elif target.provider_kind == "gitlab":
        api_base_segments.append("v4")
        encoded_repository = "/".join(repository_segments)
        api_prefixes = [
            [*api_base_segments, "projects", encoded_repository],
            [*api_base_segments, "projects", *repository_segments],
        ]
        authorities.extend(
            (base.scheme, base.hostname, base.port, prefix) for prefix in api_prefixes
        )
        api_prefix = None
    elif target.provider_kind == "gitee":
        api_base_segments.append("v5")
        api_prefix = [*api_base_segments, "repos", *repository_segments]
    else:
        api_prefix = None

    if api_prefix is not None:
        authorities.append((base.scheme, base.hostname, base.port, api_prefix))
    try:
        return any(
            _authority_matches(parsed, scheme=scheme, hostname=hostname, port=port)
            and _path_has_prefix(path_segments, prefix)
            for scheme, hostname, port, prefix in authorities
        )
    except (TypeError, ValueError):
        return False


# Keep the old private name available to callers that used the previous helper.
_repository_url_matches_target = repository_url_matches_target


_IDENTITY_URL_FIELDS = (
    "html_url",
    "web_url",
    "repository_url",
    "repo_url",
    "project_url",
    "api_url",
    "url",
    "noteable_url",
    "self",
)


def _identity_url_values(value: Any) -> list[Any]:
    values: list[Any] = []
    for container in _identity_containers(value):
        for field in _IDENTITY_URL_FIELDS:
            if field in container and container[field] is not None:
                values.extend(_url_candidate_values(container[field]))
    return values


def _direct_identity_url_values(value: Any) -> list[Any]:
    """Collect root URL fields without treating nested provider self links as repository URLs."""
    if not isinstance(value, dict):
        return []
    return [
        candidate
        for field in _IDENTITY_URL_FIELDS
        if field != "self" and value.get(field) is not None
        for candidate in _url_candidate_values(value[field])
    ]


def _url_candidate_values(candidate: Any) -> list[Any]:
    if not isinstance(candidate, dict):
        return [candidate]
    extracted = [
        candidate[key] for key in ("href", "url") if isinstance(candidate.get(key), str)
    ]
    return extracted or [candidate]


def validate_native_item_repository_identity(
    raw: Any,
    normalized: Any,
    target: RepositoryTarget,
    *,
    provider_kind: str,
) -> None:
    """Reject native records whose embedded repository points elsewhere."""
    expected_full_name = f"{target.owner}/{target.name}"
    identity_field = "path_with_namespace" if provider_kind == "gitlab" else "full_name"
    containers = _identity_containers(raw)
    for container in containers:
        for field in (identity_field, "full_name", "path_with_namespace"):
            if field not in container or container[field] is None:
                continue
            identity = container[field]
            if not isinstance(identity, str) or identity.strip() != expected_full_name:
                raise StrictNormalizationError(
                    "native item repository identity does not match the requested target"
                )

        if provider_kind == "gitlab" and container is not raw:
            path = container.get("path")
            if (
                path is not None
                and (
                    "path_with_namespace" in container
                    or "project_id" in container
                    or "namespace" in container
                )
                and (not isinstance(path, str) or path.strip() != target.name)
            ):
                raise StrictNormalizationError(
                    "native item project path does not match the requested target"
                )

    for container in containers:
        for relation in (
            "repository",
            "project",
            "repo",
            "source_project",
            "target_project",
        ):
            nested = container.get(relation)
            if (
                not isinstance(nested, dict)
                or "name" not in nested
                or nested["name"] is None
            ):
                continue
            nested_name = nested["name"]
            if not isinstance(nested_name, str) or nested_name.strip() not in {
                expected_full_name,
                target.name,
            }:
                raise StrictNormalizationError(
                    "native item repository name does not match the requested target"
                )

    for container in containers:
        owner = container.get("owner")
        owner_name = (
            next(
                (
                    owner.get(field)
                    for field in ("login", "name", "username")
                    if isinstance(owner.get(field), str) and owner.get(field)
                ),
                None,
            )
            if isinstance(owner, dict)
            else owner
        )
        name = container.get("name")
        if owner_name is None or name is None:
            continue
        if owner_name != target.owner or name != target.name:
            raise StrictNormalizationError(
                "native item owner/name does not match the requested target"
            )

    urls = _identity_url_values(raw)
    if isinstance(normalized, dict) and "web_url" in normalized:
        urls.append(normalized.get("web_url"))
    for value in urls:
        if value is None:
            continue
        if not isinstance(value, str) or not repository_url_matches_target(
            value, target
        ):
            raise StrictNormalizationError(
                "native item URL does not match the requested target"
            )


def merge_diagnostics(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Merge child-request diagnostics without losing distinct failure causes."""
    if not incoming:
        return

    protected = {
        "status_code",
        "attempts",
        "retryable",
        "retry_after_seconds",
        "rate_limit",
        "child_diagnostics",
    }

    def snapshot(value: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value[key]
            for key in (
                "failure_class",
                "failure_classes",
                "status_code",
                "attempts",
                "retryable",
                "retry_after_seconds",
                "rate_limit",
            )
            if key in value
        }

    collisions = {
        key
        for key in protected
        if key != "child_diagnostics"
        and key in target
        and key in incoming
        and target[key] != incoming[key]
    }
    if collisions:
        children = target.get("child_diagnostics")
        if not isinstance(children, list):
            children = []
            previous = snapshot(target)
            if previous:
                children.append(previous)
            target["child_diagnostics"] = children
        child = snapshot(incoming)
        if child:
            children.append(child)

    def classes(value: Any) -> set[str]:
        if isinstance(value, str) and value:
            return {value}
        if isinstance(value, (list, tuple, set)):
            return {item for item in value if isinstance(item, str) and item}
        return set()

    failure_classes = (
        classes(target.get("failure_class"))
        | classes(target.get("failure_classes"))
        | classes(incoming.get("failure_class"))
        | classes(incoming.get("failure_classes"))
    )
    for key, value in incoming.items():
        if key not in protected or key not in target:
            target[key] = value
    if len(failure_classes) == 1:
        target["failure_class"] = next(iter(failure_classes))
        target.pop("failure_classes", None)
    elif failure_classes:
        target.pop("failure_class", None)
        target["failure_classes"] = sorted(failure_classes)


def _append_normalization_diagnostics(
    result: SourceResult,
    source: str,
    dropped: int,
    failure_classes: set[str],
) -> None:
    if not dropped:
        return
    result.status = "incomplete"
    note = f"{source} response dropped {dropped} malformed item(s)"
    result.note = f"{result.note}; {note}" if result.note else note
    diagnostics = {
        "failure_class": next(iter(failure_classes))
        if len(failure_classes) == 1
        else None,
        "failure_classes": sorted(failure_classes)
        if len(failure_classes) > 1
        else None,
        "dropped_count": dropped,
        "malformed_items": dropped,
    }
    diagnostics = {
        key: value for key, value in diagnostics.items() if value is not None
    }
    merge_diagnostics(result.diagnostics, diagnostics)


def coerce_optional_source_result(source: str, value: Any) -> SourceResult:
    """Keep malformed optional provider return values inside the warning boundary."""
    if not isinstance(value, SourceResult):
        return SourceResult(
            [],
            "incomplete",
            f"{source} optional source returned an invalid SourceResult",
            {
                "failure_class": "malformed_response",
                "returned_type": type(value).__name__,
            },
        )
    if value.status not in CAPABILITY_STATES:
        return SourceResult(
            [],
            "incomplete",
            f"{source} optional source returned an invalid capability status",
            {"failure_class": "malformed_response", "returned_status": value.status},
        )
    if not isinstance(value.diagnostics, dict):
        return SourceResult(
            [],
            "incomplete",
            f"{source} optional source returned invalid diagnostics",
            {
                "failure_class": "malformed_response",
                "diagnostics_type": type(value.diagnostics).__name__,
            },
        )
    if not isinstance(value.note, str):
        return SourceResult(
            [],
            "incomplete",
            f"{source} optional source returned an invalid note",
            {
                "failure_class": "malformed_response",
                "note_type": type(value.note).__name__,
            },
        )
    return value


class BundleBuilder:
    def __init__(
        self,
        request: CollectionRequest,
        descriptor: ProviderDescriptor,
        transport: JsonTransport,
    ) -> None:
        self.request = request
        self.descriptor = descriptor
        self.transport = transport
        self.provider_id = f"provider:{descriptor.kind}:{request.instance}"
        transport_token = getattr(transport, "token", None)
        self._secret_values = (
            (transport_token,)
            if isinstance(transport_token, str) and transport_token
            else ()
        )
        self.bundle: dict[str, Any] = {
            "fragment_version": "0.3",
            "window": {
                "start": request.window_start,
                "end": request.window_end,
                "timezone": request.timezone,
            },
            "scope": {
                "repositories": list(request.repository_ids),
                "actors": list(request.actor_ids),
            },
            "providers": [
                {
                    "id": self.provider_id,
                    "kind": descriptor.kind,
                    "instance": request.instance,
                    "capabilities": {},
                }
            ],
            "repositories": [],
            "actors": [],
            "work_items": [],
            "change_requests": [],
            "interactions": [],
            "commits": [],
            "ref_changes": [],
            "releases": [],
            "evidence": [],
            "assertions": [],
            "retrievals": [],
            "collection": {
                "provider": descriptor.kind,
                "instance": request.instance,
                "group_status": "completed",
                "limits": {
                    "timeout_seconds": request.timeout_seconds,
                    "max_retries": request.max_retries,
                    "max_pages": request.max_pages,
                    "max_requests": request.max_requests,
                    "retry_jitter_seconds": request.retry_jitter_seconds,
                    "retry_after_max_seconds": request.retry_after_max_seconds,
                },
                "metrics": transport_metrics(transport),
            },
            "coverage": {
                "required_sources": list(RESOURCE_SOURCES),
                "observations": [],
                "fatal": [],
                "group_failures": [],
                "warnings": [],
            },
        }
        self._seen: dict[str, set[str]] = {
            key: set() for key in self.bundle if isinstance(self.bundle[key], list)
        }
        self._actor_ids: dict[str, str] = {}
        self._commit_ids_by_sha: dict[tuple[str, str], set[str]] = {}
        self._change_request_ids_by_sha: dict[tuple[str, str], set[str]] = {}
        self._duplicate_counts: dict[tuple[str, str], int] = {}
        self._filtered_subjects: dict[str, dict[str, Any]] = {}
        self._retrieval_ids: dict[str, str] = {}
        self._retrieval_provenance: dict[str, dict[str, Any]] = {}
        self._transaction_token = 0
        self._active_transaction: int | None = None
        self._index_undo: list[tuple[str, str, Any, Any]] = []
        self._entity_count = 1
        self._bundle_size_estimate = (
            json_size_with_limit(
                self.bundle,
                max_bytes=MAX_BUNDLE_BYTES - 1,
            )
            + 1
        )

    def checkpoint(self) -> dict[str, Any]:
        """Start a source transaction without copying historical indexes."""
        if self._active_transaction is not None:
            raise RuntimeError("nested BundleBuilder transactions are not supported")
        self._transaction_token += 1
        self._active_transaction = self._transaction_token
        self._index_undo.clear()
        coverage = self.bundle["coverage"]
        capabilities = self.bundle["providers"][0]["capabilities"]
        return {
            "transaction_token": self._transaction_token,
            "collection_lengths": {
                key: len(value)
                for key, value in self.bundle.items()
                if isinstance(value, list)
            },
            "coverage_lengths": {
                key: len(coverage[key])
                for key in ("observations", "fatal", "group_failures", "warnings")
            },
            "capabilities": dict(capabilities),
            "entity_count": self._entity_count,
            "bundle_size_estimate": self._bundle_size_estimate,
        }

    def commit(self, checkpoint: dict[str, Any]) -> None:
        """Accept the current source transaction and discard its undo journal."""
        self._require_active_transaction(checkpoint)
        self._active_transaction = None
        self._index_undo.clear()

    def restore(self, checkpoint: dict[str, Any]) -> None:
        """Truncate source deltas and restore indexes after failed emission."""
        self._require_active_transaction(checkpoint)
        for key, length in checkpoint["collection_lengths"].items():
            del self.bundle[key][length:]
        coverage = self.bundle["coverage"]
        for key, length in checkpoint["coverage_lengths"].items():
            del coverage[key][length:]
        capabilities = self.bundle["providers"][0]["capabilities"]
        capabilities.clear()
        capabilities.update(checkpoint["capabilities"])
        for operation, mapping_name, key, value in reversed(self._index_undo):
            mapping = getattr(self, mapping_name)
            if operation == "discard":
                mapping[key].discard(value)
            elif operation == "delete":
                mapping.pop(key, None)
            elif operation == "restore":
                existed, previous = value
                if existed:
                    mapping[key] = previous
                else:
                    mapping.pop(key, None)
        self._entity_count = checkpoint["entity_count"]
        self._bundle_size_estimate = checkpoint["bundle_size_estimate"]
        self._active_transaction = None
        self._index_undo.clear()

    def _require_active_transaction(self, checkpoint: dict[str, Any]) -> None:
        if checkpoint.get("transaction_token") != self._active_transaction:
            raise RuntimeError("BundleBuilder transaction checkpoint is not active")

    def _set_index_value(self, mapping_name: str, key: Any, value: Any) -> None:
        mapping = getattr(self, mapping_name)
        if self._active_transaction is not None:
            self._index_undo.append(
                ("restore", mapping_name, key, (key in mapping, mapping.get(key)))
            )
        mapping[key] = value

    def _pop_index_value(self, mapping_name: str, key: Any) -> Any:
        mapping = getattr(self, mapping_name)
        if key not in mapping:
            return None
        if self._active_transaction is not None:
            self._index_undo.append(
                ("restore", mapping_name, key, (True, mapping[key]))
            )
        return mapping.pop(key)

    def _add_index_member(self, mapping_name: str, key: Any, value: str) -> None:
        mapping = getattr(self, mapping_name)
        if key not in mapping:
            mapping[key] = set()
            if self._active_transaction is not None:
                self._index_undo.append(("delete", mapping_name, key, None))
        if value in mapping[key]:
            return
        mapping[key].add(value)
        if self._active_transaction is not None:
            self._index_undo.append(("discard", mapping_name, key, value))

    def _account_bundle_growth(self, value: Any, *, base_indent: int) -> None:
        self._bundle_size_estimate += indented_json_growth_upper_bound(
            value,
            base_indent=base_indent,
        )
        if self._bundle_size_estimate <= MAX_BUNDLE_BYTES:
            return
        try:
            self._bundle_size_estimate = (
                json_size_with_limit(
                    self.bundle,
                    max_bytes=MAX_BUNDLE_BYTES - 1,
                )
                + 1
            )
        except (InputLimitError, TypeError, ValueError) as exc:
            raise ResponseShapeError(
                f"evidence bundle exceeds {MAX_BUNDLE_BYTES} bytes",
                failure_class="limit_exceeded",
            ) from exc

    @staticmethod
    def _failure_classes(diagnostics: dict[str, Any]) -> set[str]:
        values: set[str] = set()

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                failure_class = value.get("failure_class")
                if isinstance(failure_class, str) and failure_class:
                    values.add(failure_class)
                failure_classes = value.get("failure_classes")
                if isinstance(failure_classes, list):
                    values.update(
                        item
                        for item in failure_classes
                        if isinstance(item, str) and item
                    )
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(diagnostics)
        return values

    def add_coverage(
        self, source: str, target: RepositoryTarget, result: SourceResult
    ) -> None:
        self._add_retrievals(source, target, result.retrievals)
        ledgers = self.bundle["coverage"]
        starting_lengths = {
            key: len(ledgers[key])
            for key in ("observations", "fatal", "group_failures", "warnings")
        }
        diagnostics = dict(result.diagnostics)
        metrics = transport_metrics(self.transport)
        if (
            metrics["retry_count"]
            or metrics["budget_exhausted"]
            or metrics["cache_hits"]
            or metrics["cache_misses"]
        ):
            diagnostics.setdefault("metrics", metrics)
        failure_classes = self._failure_classes(diagnostics)
        group_failure_classes = failure_classes & OPERATIONAL_FAILURE_CLASSES
        if (
            source in RESOURCE_SOURCES
            and result.status == "supported"
            and group_failure_classes
        ):
            result.status = "incomplete"
            classes = ", ".join(sorted(group_failure_classes))
            result.note = (
                f"{result.note}; " if result.note else ""
            ) + f"core source reported operational failure: {classes}"
        observation = {
            "source": source,
            "provider_id": self.provider_id,
            "repository_id": target.canonical_id,
            "status": result.status,
        }
        if result.note:
            observation["note"] = result.note
        if diagnostics:
            observation["diagnostics"] = diagnostics
        observation = sanitize_public_payload(
            observation,
            secret_values=self._secret_values,
        )
        self.bundle["coverage"]["observations"].append(observation)
        append_optional_coverage_warning(self.bundle["coverage"], observation)
        capabilities = self.bundle["providers"][0]["capabilities"]
        capabilities[source] = merge_capability_status(
            capabilities.get(source), result.status
        )
        if result.status != "supported" and group_failure_classes:
            observation.setdefault("diagnostics", {})["group_failure"] = True
            for failure_class in sorted(group_failure_classes):
                failure = {
                    "provider": self.descriptor.kind,
                    "instance": self.request.instance,
                    "repository": target.canonical_id,
                    "source": source,
                    "failure_class": failure_class,
                }
                self.bundle["coverage"]["group_failures"].append(failure)
                if source in RESOURCE_SOURCES:
                    self.bundle["coverage"]["fatal"].append(
                        coverage_blocker(
                            code="required_source_failure",
                            status=result.status,
                            **failure,
                        )
                    )
        elif source in RESOURCE_SOURCES and result.status != "supported":
            self.bundle["coverage"]["fatal"].append(
                coverage_blocker(
                    code="required_source_incomplete",
                    provider=self.descriptor.kind,
                    instance=self.request.instance,
                    repository=target.canonical_id,
                    source=source,
                    status=result.status,
                )
            )
        self._apply_duplicate_coverage(source, target.canonical_id)
        growth = {
            key: ledgers[key][starting_lengths[key] :]
            for key in starting_lengths
            if len(ledgers[key]) > starting_lengths[key]
        }
        self._account_bundle_growth(growth, base_indent=6)

    def _add_retrievals(
        self,
        source: str,
        target: RepositoryTarget,
        retrievals: list[dict[str, Any]],
    ) -> None:
        for raw in retrievals:
            if not isinstance(raw, dict):
                continue
            key = raw.get("_key")
            if not isinstance(key, str) or not key:
                continue
            if key in self._retrieval_ids:
                if self._retrieval_provenance.get(key) != raw:
                    raise ResponseShapeError(
                        "conflicting response Retrieval correlation key",
                        failure_class="malformed_response",
                    )
                continue
            retrieval_id = (
                f"retrieval:{self.provider_id}:{len(self.bundle['retrievals']) + 1}"
            )
            record = {
                field: value
                for field, value in raw.items()
                if field
                in {
                    "mode",
                    "target_ref",
                    "fetched_at",
                    "replayed_at",
                    "stored_at",
                    "cache_age_seconds",
                    "cache_ttl_seconds",
                    "page",
                    "pagination_outcome",
                    "etag",
                    "last_modified",
                    "api_version",
                }
            }
            record.update(
                {
                    "id": retrieval_id,
                    "provider_id": self.provider_id,
                    "endpoint_kind": (
                        raw.get("endpoint_kind")
                        if isinstance(raw.get("endpoint_kind"), str)
                        and raw["endpoint_kind"]
                        else source
                    ),
                    "repository_id": target.canonical_id,
                }
            )
            if (
                not isinstance(record.get("target_ref"), str)
                or not record["target_ref"]
            ):
                record["target_ref"] = source
            self._add_entity("retrievals", sanitize_public_payload(record))
            self._set_index_value("_retrieval_ids", key, retrieval_id)
            self._set_index_value("_retrieval_provenance", key, deepcopy(raw))

    def record_optional_failure(
        self,
        source: str,
        target: RepositoryTarget,
        error: Exception,
        *,
        fail_closed: bool = False,
    ) -> None:
        """Enrich an optional observation after a boundary failure."""
        diagnostics = exception_diagnostics(error)
        diagnostics["group_failure"] = True
        matches = [
            observation
            for observation in self.bundle["coverage"]["observations"]
            if observation.get("source") == source
            and observation.get("provider_id") == self.provider_id
            and observation.get("repository_id") == target.canonical_id
        ]
        if not matches:
            self.add_coverage(
                source,
                target,
                SourceResult(
                    [],
                    "incomplete",
                    f"{source} optional collection failed; coverage warning emitted",
                    dict(diagnostics),
                ),
            )
            matches = [
                observation
                for observation in self.bundle["coverage"]["observations"]
                if observation.get("source") == source
                and observation.get("provider_id") == self.provider_id
                and observation.get("repository_id") == target.canonical_id
            ]
        for observation in matches:
            observation["status"] = "incomplete"
            observation["note"] = (
                f"{observation.get('note')}; " if observation.get("note") else ""
            ) + "optional source boundary failure"
            observation_diagnostics = observation.setdefault("diagnostics", {})
            if isinstance(observation_diagnostics, dict):
                merge_diagnostics(observation_diagnostics, diagnostics)
            capabilities = self.bundle["providers"][0]["capabilities"]
            capabilities[source] = merge_capability_status(
                capabilities.get(source), "incomplete"
            )
            append_optional_coverage_warning(self.bundle["coverage"], observation)
        failure = {
            "provider": self.descriptor.kind,
            "instance": self.request.instance,
            "repository": target.canonical_id,
            "source": source,
            "failure_class": diagnostics["failure_class"],
        }
        if not any(
            isinstance(existing, dict)
            and all(existing.get(field) == failure[field] for field in failure)
            for existing in self.bundle["coverage"]["group_failures"]
        ):
            self.bundle["coverage"]["group_failures"].append(failure)
        if fail_closed:
            blocker = coverage_blocker(
                code="privacy_violation",
                status="incomplete",
                **failure,
            )
            if blocker not in self.bundle["coverage"]["fatal"]:
                self.bundle["coverage"]["fatal"].append(blocker)

    def add_repository(
        self,
        record: dict[str, Any],
        *,
        target: RepositoryTarget | None = None,
    ) -> None:
        record = dict(record)
        record.pop("_retrieval_key", None)
        repository = target.canonical_id if target is not None else record.get("id")
        self._add_entity(
            "repositories",
            record,
            source="repositories",
            repository_id=repository if isinstance(repository, str) else None,
        )

    def add_records(
        self,
        category: str,
        records: list[dict[str, Any]],
        *,
        target: RepositoryTarget,
        evidence_source: str = "resource_api",
    ) -> None:
        for raw in records:
            record = dict(raw)
            actor = record.pop("_actor", None)
            association_shas = self._unique_strings(record.pop("_association_shas", []))
            commit_shas = self._unique_strings(record.pop("_commit_shas", []))
            explicit_change_request_ids = self._unique_strings(
                record.pop("_change_request_ids", [])
            )
            association_attempted = bool(record.pop("_association_attempted", False))
            association_complete = bool(record.pop("_association_complete", False))
            native_identity = record.pop("_native_id", None)
            retrieval_key = record.pop("_retrieval_key", None)
            entity_id = record.get("id")
            if not isinstance(entity_id, str) or not entity_id:
                continue
            if entity_id in self._seen[category]:
                for source in self._coverage_sources_for_category(category):
                    self._record_duplicate(source, target.canonical_id)
                continue
            actor_id = self._actor_id(actor)
            if (
                self.request.actor_ids
                and actor is not None
                and actor_id not in self.request.actor_ids
            ):
                if category in {"work_items", "change_requests"}:
                    self._set_index_value(
                        "_filtered_subjects",
                        entity_id,
                        {
                            key: record[key]
                            for key in ("id", "kind", "repository_id", "number")
                            if key in record
                        },
                    )
                continue
            if category == "interactions":
                subject_type = record.get("subject_type")
                subject_id = record.get("subject_id")
                subject_collection = {
                    "work_item": "work_items",
                    "change_request": "change_requests",
                }.get(subject_type)
                if not isinstance(subject_id, str) or subject_collection is None:
                    raise ResponseShapeError(
                        "interaction has no canonical subject",
                        failure_class="malformed_response",
                    )
                if subject_id not in self._seen[subject_collection]:
                    structural_subject = self._pop_index_value(
                        "_filtered_subjects", subject_id
                    )
                    if structural_subject is None or not self._add_entity(
                        subject_collection,
                        structural_subject,
                        repository_id=target.canonical_id,
                    ):
                        raise ResponseShapeError(
                            "interaction subject is unavailable after actor filtering",
                            failure_class="malformed_response",
                        )
            if category == "change_requests":
                for sha in association_shas:
                    self._add_index_member(
                        "_change_request_ids_by_sha",
                        (target.canonical_id, sha),
                        entity_id,
                    )
            elif category == "commits":
                sha = record.get("sha")
                if isinstance(sha, str) and sha:
                    self._add_index_member(
                        "_commit_ids_by_sha",
                        (target.canonical_id, sha),
                        entity_id,
                    )
                    algorithm = git_object_id_algorithm(sha)
                    if algorithm is not None:
                        record["hash_algorithm"] = algorithm
            elif category == "ref_changes":
                known_change_request_ids = [
                    change_request_id
                    for change_request_id in explicit_change_request_ids
                    if change_request_id in self._seen.get("change_requests", set())
                ]
                if association_attempted and len(known_change_request_ids) != len(
                    explicit_change_request_ids
                ):
                    association_complete = False
                if known_change_request_ids:
                    record["change_request_ids"] = known_change_request_ids
                if commit_shas:
                    record["commit_shas"] = commit_shas
                    commit_ids = sorted(
                        {
                            commit_id
                            for sha in commit_shas
                            for commit_id in self._commit_ids_by_sha.get(
                                (target.canonical_id, sha), set()
                            )
                        }
                    )
                    if commit_ids:
                        record["commit_ids"] = commit_ids
                record["change_association"] = self._associate_ref_change(
                    target,
                    commit_shas,
                    known_change_request_ids,
                    association_attempted=association_attempted,
                    association_complete=association_complete,
                )
            if actor_id:
                self._add_actor(actor)
            if actor_id:
                record["actor_id"] = actor_id
            record = sanitize_public_payload(
                record,
                secret_values=self._secret_values,
            )
            if not self._add_entity(
                category,
                record,
                source=self._coverage_sources_for_category(category)[0],
                repository_id=target.canonical_id,
            ):
                continue
            evidence_id = f"evidence:{category}:{entity_id}"
            evidence = {
                "id": evidence_id,
                "provider_id": self.provider_id,
                "subject_type": category.removesuffix("s"),
                "subject_id": entity_id,
                "source": evidence_source,
                "retrieval_id": self._retrieval_ids.get(str(retrieval_key), ""),
                "native_identity": {"state": "known", "value": str(native_identity)},
            }
            if not evidence["retrieval_id"] or not is_valid_native_id(native_identity):
                raise ResponseShapeError(
                    "record has no response Retrieval or native identity",
                    failure_class="malformed_response",
                )
            if record.get("web_url"):
                evidence["url"] = record["web_url"]
            else:
                evidence["source_ref"] = f"{self.provider_id}:{category}:{entity_id}"
            self._add_entity("evidence", evidence)

    @staticmethod
    def _coverage_sources_for_category(category: str) -> tuple[str, ...]:
        if category == "change_requests":
            return CHANGE_REQUEST_COVERAGE_SOURCES
        return (category,)

    @staticmethod
    def _unique_strings(values: Any) -> list[str]:
        if not isinstance(values, (list, tuple, set)):
            return []
        return list(
            dict.fromkeys(value for value in values if isinstance(value, str) and value)
        )

    def _associate_ref_change(
        self,
        target: RepositoryTarget,
        commit_shas: list[str],
        explicit_change_request_ids: list[str],
        *,
        association_attempted: bool = False,
        association_complete: bool = False,
    ) -> str:
        if association_attempted:
            if not commit_shas or not association_complete:
                return "unknown"
            if explicit_change_request_ids:
                return (
                    "linked" if len(explicit_change_request_ids) == 1 else "ambiguous"
                )
            return "unlinked"
        if explicit_change_request_ids:
            return "linked" if len(explicit_change_request_ids) == 1 else "ambiguous"
        if not commit_shas:
            return "unknown"
        candidates: set[str] = set()
        unresolved = False
        for sha in commit_shas:
            matches = self._change_request_ids_by_sha.get(
                (target.canonical_id, sha), set()
            )
            if len(matches) > 1:
                return "ambiguous"
            if not matches:
                unresolved = True
            candidates.update(matches)
        if len(candidates) > 1:
            return "ambiguous"
        if unresolved or not candidates:
            return "unknown"
        return "linked"

    def _actor_id(self, actor: dict[str, Any] | None) -> str | None:
        if not isinstance(actor, dict) or actor.get("source_id") is None:
            return None
        source_id = str(actor["source_id"])
        return f"actor:{self.descriptor.kind}:{self.request.instance}:{source_id}"

    def _add_actor(self, actor: dict[str, Any] | None) -> str | None:
        actor_id = self._actor_id(actor)
        if actor_id is None:
            return None
        source_id = str(actor["source_id"])
        if source_id not in self._actor_ids:
            self._set_index_value(
                "_actor_ids",
                source_id,
                f"actor:{self.descriptor.kind}:{self.request.instance}:{source_id}",
            )
        if actor_id not in self._seen["actors"]:
            self._add_entity(
                "actors",
                {
                    "id": actor_id,
                    "provider_id": self.provider_id,
                    "source_id": source_id,
                    "handle": actor.get("handle"),
                },
            )
        return actor_id

    def _record_duplicate(self, source: str, repository_id: str | None) -> None:
        if not isinstance(repository_id, str) or not repository_id:
            return
        key = (source, repository_id)
        self._set_index_value(
            "_duplicate_counts", key, self._duplicate_counts.get(key, 0) + 1
        )
        self._apply_duplicate_coverage(source, repository_id)
        self._account_bundle_growth(
            {"source": source, "repository_id": repository_id, "duplicate_count": 1},
            base_indent=6,
        )

    def _apply_duplicate_coverage(self, source: str, repository_id: str) -> None:
        duplicate_count = self._duplicate_counts.get((source, repository_id), 0)
        if not duplicate_count:
            return
        diagnostic = {
            "failure_class": "malformed_response",
            "duplicate_count": duplicate_count,
            "dropped_count": duplicate_count,
            "malformed_items": duplicate_count,
        }
        for observation in self.bundle["coverage"]["observations"]:
            if (
                observation.get("source") != source
                or observation.get("provider_id") != self.provider_id
                or observation.get("repository_id") != repository_id
            ):
                continue
            observation["status"] = "incomplete"
            observation["note"] = (
                f"{observation.get('note')}; " if observation.get("note") else ""
            ) + f"{source} response contained {duplicate_count} duplicate record(s)"
            observation_diagnostics = observation.setdefault("diagnostics", {})
            if isinstance(observation_diagnostics, dict):
                merge_diagnostics(observation_diagnostics, diagnostic)
            capabilities = self.bundle["providers"][0]["capabilities"]
            capabilities[source] = merge_capability_status(
                capabilities.get(source), "incomplete"
            )
            append_optional_coverage_warning(self.bundle["coverage"], observation)
        if source in RESOURCE_SOURCES:
            fatal = coverage_blocker(
                code="duplicate_records",
                provider=self.descriptor.kind,
                instance=self.request.instance,
                repository=repository_id,
                source=source,
                status="incomplete",
                failure_class="malformed_response",
            )
            if fatal not in self.bundle["coverage"]["fatal"]:
                self.bundle["coverage"]["fatal"].append(fatal)

    def _add_entity(
        self,
        category: str,
        record: dict[str, Any],
        *,
        source: str | None = None,
        repository_id: str | None = None,
    ) -> bool:
        record = sanitize_public_payload(
            record,
            secret_values=self._secret_values,
        )
        validate_json_value_limits(record)
        entity_id = record.get("id")
        if not isinstance(entity_id, str) or not entity_id:
            return False
        if entity_id in self._seen[category]:
            duplicate_source = source or (
                CHANGE_REQUEST_COVERAGE_SOURCES[0]
                if category == "change_requests"
                else category
                if category in RESOURCE_SOURCES
                else None
            )
            duplicate_repository = repository_id or record.get("repository_id")
            if duplicate_repository is None and category == "repositories":
                duplicate_repository = entity_id
            if duplicate_source is not None:
                self._record_duplicate(duplicate_source, duplicate_repository)
            return False
        if self._entity_count >= MAX_NORMALIZED_ENTITIES:
            raise ResponseShapeError(
                f"normalized entity count exceeds {MAX_NORMALIZED_ENTITIES}",
                failure_class="limit_exceeded",
            )
        self._add_index_member("_seen", category, entity_id)
        self.bundle[category].append(record)
        self._entity_count += 1
        self._account_bundle_growth(record, base_indent=4)
        return True

    def finish(self) -> dict[str, Any]:
        metrics = transport_metrics(self.transport)
        self.bundle["collection"]["metrics"] = metrics
        if metrics["insecure_transport"]:
            self.bundle["collection"]["group_status"] = "diagnostic_insecure_transport"
            seen_failures: set[tuple[str, str]] = set()
            for observation in self.bundle["coverage"]["observations"]:
                if not isinstance(observation, dict):
                    continue
                source = observation.get("source")
                repository_id = observation.get("repository_id")
                if not isinstance(source, str) or not isinstance(repository_id, str):
                    continue
                observation["status"] = "incomplete"
                diagnostics = observation.setdefault("diagnostics", {})
                if isinstance(diagnostics, dict):
                    diagnostics["failure_class"] = "insecure_transport"
                    diagnostics["group_failure"] = True
                capabilities = self.bundle["providers"][0]["capabilities"]
                capabilities[source] = merge_capability_status(
                    capabilities.get(source), "incomplete"
                )
                key = (repository_id, source)
                if key in seen_failures:
                    continue
                seen_failures.add(key)
                failure = {
                    "provider": self.descriptor.kind,
                    "instance": self.request.instance,
                    "repository": repository_id,
                    "source": source,
                    "failure_class": "insecure_transport",
                }
                self.bundle["coverage"]["group_failures"].append(failure)
                if source in RESOURCE_SOURCES:
                    self.bundle["coverage"]["fatal"].append(
                        coverage_blocker(
                            code="required_source_failure",
                            status="incomplete",
                            **failure,
                        )
                    )
                else:
                    append_optional_coverage_warning(
                        self.bundle["coverage"], observation
                    )
        for observation in self.bundle["coverage"]["observations"]:
            if isinstance(observation, dict):
                append_optional_coverage_warning(self.bundle["coverage"], observation)
        from ..assertions import build_assertions
        from ..validation import has_blocking_core_coverage

        self.bundle["assertions"] = build_assertions(self.bundle)
        self.bundle["coverage"]["render_eligible"] = not has_blocking_core_coverage(
            self.bundle["coverage"],
            repository_ids=self.request.repository_ids,
            provider_ids_by_repository={
                repository_id: self.provider_id
                for repository_id in self.request.repository_ids
            },
        )
        try:
            json_size_with_limit(
                self.bundle,
                max_bytes=MAX_BUNDLE_BYTES - 1,
            )
        except (InputLimitError, TypeError, ValueError) as exc:
            raise ResponseShapeError(
                f"evidence bundle exceeds {MAX_BUNDLE_BYTES} bytes",
                failure_class="limit_exceeded",
            ) from exc
        return self.bundle


class ResourceProvider:
    descriptor: ProviderDescriptor
    pagination_strategy: PaginationStrategy = DOCUMENTED_SHORT_PAGE_PAGINATION

    def __init__(
        self, transport: JsonTransport, instance: str, *, max_pages: int = 100
    ) -> None:
        if isinstance(max_pages, bool) or not isinstance(max_pages, int):
            raise TypeError("max_pages must be an integer")
        if max_pages < 1 or max_pages > MAX_PAGES:
            raise ValueError(f"max_pages must be in [1, {MAX_PAGES}]")
        self.transport = transport
        self.instance = validate_instance(instance)
        self.max_pages = max_pages

    def probe(self) -> dict[str, Any]:
        """Describe the adapter without turning implementation status into coverage."""
        return {
            **self.descriptor.as_dict(),
            "instance": self.instance,
        }

    def collect(self, request: CollectionRequest) -> dict[str, Any]:
        if request.provider_kind != self.descriptor.kind:
            raise ValueError(
                f"request provider {request.provider_kind!r} does not match {self.descriptor.kind!r}"
            )
        if self.instance != request.instance:
            raise ValueError(
                f"provider instance {self.instance!r} does not match request instance {request.instance!r}"
            )
        for target in request.repositories:
            if (
                not isinstance(target, RepositoryTarget)
                or target.provider_kind != request.provider_kind
                or target.instance != request.instance
            ):
                raise ValueError(
                    "repository target provider and instance must match the collection request"
                )
        if isinstance(request.max_pages, bool) or not isinstance(
            request.max_pages, int
        ):
            raise TypeError("request.max_pages must be an integer")
        if request.max_pages < 1 or request.max_pages > MAX_PAGES:
            raise ValueError(f"request.max_pages must be in [1, {MAX_PAGES}]")
        self.max_pages = request.max_pages
        builder = BundleBuilder(request, self.descriptor, self.transport)
        snapshots = self._collect_core_fair(request)
        for target in request.repositories:
            snapshot = snapshots[target.canonical_id]
            for source in CORE_RESOURCE_SOURCES:
                if source == "repositories" and source not in snapshot.sources:
                    result = SourceResult(
                        [snapshot.repository] if snapshot.repository else [],
                        "supported" if snapshot.repository else "unavailable",
                        "repository resource observed"
                        if snapshot.repository
                        else "repository resource unavailable",
                        retrievals=snapshot.retrievals,
                    )
                else:
                    result = snapshot.sources.get(
                        source,
                        SourceResult(
                            [],
                            "unavailable",
                            "provider did not return this resource source",
                        ),
                    )
                if source == "change_requests":
                    self._emit_change_requests(builder, target, result, request)
                else:
                    self._emit_core_source(builder, target, source, result, request)
        # Optional activity/ref work starts only after every repository's core queue.
        for target in request.repositories:
            if request.include_activity_api:
                activity_boundary_error: Exception | None = None
                try:
                    activity_sources = self._collect_activity(target, request)
                    if not isinstance(activity_sources, dict):
                        raise ResponseShapeError(
                            "provider returned invalid optional activity sources"
                        )
                except EXPECTED_PROVIDER_FAILURES as exc:
                    activity_boundary_error = exc
                    activity_sources = optional_activity_failure_sources(exc)
            else:
                activity_boundary_error = None
                activity_sources = {
                    source: SourceResult(
                        [],
                        "unavailable",
                        "activity API disabled; push/ref completeness is not claimed",
                    )
                    for source in ACTIVITY_SOURCES
                }
            for source in ACTIVITY_SOURCES:
                checkpoint = builder.checkpoint()
                try:
                    result = coerce_optional_source_result(
                        source,
                        activity_sources.get(
                            source,
                            SourceResult(
                                [],
                                "unsupported",
                                "provider did not return this activity source",
                            ),
                        ),
                    )
                    result = self._strict_source_result(result, source, target, request)
                    builder.add_coverage(source, target, result)
                    if source == "ref_changes":
                        builder.add_records(
                            "ref_changes",
                            result.items,
                            target=target,
                            evidence_source="activity_api",
                        )
                    if "privacy_violation" in builder._failure_classes(
                        result.diagnostics
                    ) and not isinstance(activity_boundary_error, PrivacyError):
                        builder.record_optional_failure(
                            source,
                            target,
                            PrivacyError(
                                "optional source reported a privacy violation"
                            ),
                            fail_closed=True,
                        )
                except EXPECTED_PROVIDER_FAILURES as exc:
                    builder.restore(checkpoint)
                    builder.record_optional_failure(
                        source,
                        target,
                        exc,
                        fail_closed=isinstance(exc, PrivacyError),
                    )
                else:
                    builder.commit(checkpoint)
                if isinstance(activity_boundary_error, PrivacyError):
                    builder.record_optional_failure(
                        source,
                        target,
                        activity_boundary_error,
                        fail_closed=True,
                    )
        return builder.finish()

    def _emit_core_source(
        self,
        builder: BundleBuilder,
        target: RepositoryTarget,
        source: str,
        result: SourceResult,
        request: CollectionRequest,
    ) -> None:
        checkpoint = builder.checkpoint()
        try:
            result = self._strict_source_result(result, source, target, request)
            builder.add_coverage(source, target, result)
            if source == "repositories":
                for item in result.items:
                    builder.add_repository(item, target=target)
                builder.commit(checkpoint)
                return
            builder.add_records(
                source,
                result.items,
                target=target,
            )
            builder.commit(checkpoint)
        except EXPECTED_PROVIDER_FAILURES as exc:
            builder.restore(checkpoint)
            builder.add_coverage(
                source,
                target,
                SourceResult(
                    [],
                    "incomplete",
                    "source emission failed",
                    exception_diagnostics(exc),
                ),
            )

    def _emit_change_requests(
        self,
        builder: BundleBuilder,
        target: RepositoryTarget,
        result: SourceResult,
        request: CollectionRequest,
    ) -> None:
        checkpoint = builder.checkpoint()
        try:
            result = self._strict_source_result(
                result, "change_requests", target, request
            )
            for position, source in enumerate(CHANGE_REQUEST_COVERAGE_SOURCES):
                coverage_result = result
                if position:
                    coverage_result = SourceResult(
                        status=result.status,
                        note=result.note,
                        diagnostics=deepcopy(result.diagnostics),
                    )
                builder.add_coverage(source, target, coverage_result)
            builder.add_records("change_requests", result.items, target=target)
            builder.commit(checkpoint)
        except EXPECTED_PROVIDER_FAILURES as exc:
            builder.restore(checkpoint)
            for source in CHANGE_REQUEST_COVERAGE_SOURCES:
                builder.add_coverage(
                    source,
                    target,
                    SourceResult(
                        [],
                        "incomplete",
                        "source emission failed",
                        exception_diagnostics(exc),
                    ),
                )

    def _collect_core_fair(
        self,
        request: CollectionRequest,
    ) -> dict[str, RepositorySnapshot]:
        """Collect roots, top-level pages, then interactions in deterministic rounds."""
        targets = sorted(request.repositories, key=lambda target: target.canonical_id)
        snapshots: dict[str, RepositorySnapshot] = {}
        roots: list[_RootRequest] = []
        for target in targets:
            try:
                path = self._scheduled_root_path(target)
                if not isinstance(path, str) or not path:
                    raise ResponseShapeError(
                        "provider returned an invalid repository root path"
                    )
                roots.append(_RootRequest(target, path))
            except EXPECTED_PROVIDER_FAILURES as exc:
                snapshots[target.canonical_id] = self._failed_repository_snapshot(exc)
        while any(not task.done for task in roots):
            for task in roots:
                if task.done:
                    continue
                self._step_root_request(task)
                if task.done and task.snapshot is not None:
                    snapshots[task.target.canonical_id] = task.snapshot

        top_level: list[PageSourceRequest] = []
        for target in targets:
            snapshot = snapshots[target.canonical_id]
            if snapshot.repository is not None:
                try:
                    planned = self._scheduled_top_level_requests(target, request)
                    self._validate_scheduled_tasks(
                        planned, target, interaction_tasks=False
                    )
                    top_level.extend(planned)
                except EXPECTED_PROVIDER_FAILURES as exc:
                    failure = self._failed_source_result(
                        exc, "top-level source planning failed"
                    )
                    for source in (
                        "work_items",
                        "change_requests",
                        "commits",
                        "releases",
                        "interactions",
                    ):
                        snapshot.sources[source] = SourceResult(
                            [],
                            failure.status,
                            failure.note,
                            dict(failure.diagnostics),
                        )
        self._run_page_rounds(top_level, interaction_rounds=False)
        for task in top_level:
            snapshots[task.target.canonical_id].sources[task.source] = (
                task.result
                or SourceResult(
                    [], "incomplete", "scheduled source did not produce a result"
                )
            )

        interactions: list[PageSourceRequest] = []
        for target in targets:
            snapshot = snapshots[target.canonical_id]
            if (
                snapshot.repository is not None
                and "interactions" not in snapshot.sources
            ):
                try:
                    planned = self._scheduled_interaction_requests(
                        target, snapshot, request
                    )
                    self._validate_scheduled_tasks(
                        planned, target, interaction_tasks=True
                    )
                    interactions.extend(planned)
                except EXPECTED_PROVIDER_FAILURES as exc:
                    snapshot.sources["interactions"] = self._failed_source_result(
                        exc, "interaction planning failed"
                    )
        self._run_page_rounds(interactions, interaction_rounds=True)
        by_repository: dict[str, list[SourceResult]] = {
            target.canonical_id: [] for target in targets
        }
        for target in targets:
            snapshot = snapshots[target.canonical_id]
            if snapshot.repository is None or "interactions" in snapshot.sources:
                continue
            for parent_source in ("work_items", "change_requests"):
                parent = snapshot.sources[parent_source]
                if parent.status != "supported":
                    by_repository[target.canonical_id].append(
                        SourceResult(
                            [],
                            "incomplete",
                            (
                                "interaction discovery is incomplete because "
                                f"{parent_source} coverage is {parent.status}"
                            ),
                            {
                                "dependency_source": parent_source,
                                "dependency": dict(parent.diagnostics),
                            },
                        )
                    )
        for task in interactions:
            if task.result is not None:
                by_repository[task.target.canonical_id].append(task.result)
        for target in targets:
            snapshot = snapshots[target.canonical_id]
            if snapshot.repository is None:
                continue
            snapshot.sources["interactions"] = self._merge_scheduled_sources(
                by_repository[target.canonical_id]
            )
        return snapshots

    @staticmethod
    def _validate_scheduled_tasks(
        planned: Any,
        target: RepositoryTarget,
        *,
        interaction_tasks: bool,
    ) -> None:
        if not isinstance(planned, list):
            raise ResponseShapeError("provider returned a non-list scheduled task set")
        required = ("work_items", "change_requests", "commits", "releases")
        if not interaction_tasks and sorted(task.source for task in planned) != sorted(
            required
        ):
            raise ResponseShapeError(
                "provider must return exactly one task per top-level source"
            )
        for task in planned:
            if (
                not isinstance(task, PageSourceRequest)
                or task.target.canonical_id != target.canonical_id
                or not isinstance(task.path, str)
                or not task.path
                or not isinstance(task.params, dict)
                or not callable(task.normalizer)
                or (task.filter_item is not None and not callable(task.filter_item))
                or (interaction_tasks and task.source != "interactions")
                or (not interaction_tasks and task.source not in required)
            ):
                raise ResponseShapeError("provider returned an invalid scheduled task")
            if interaction_tasks and not all(
                isinstance(value, str)
                for value in (task.subject_type, task.subject_id, task.endpoint_kind)
            ):
                raise ResponseShapeError(
                    "provider returned invalid interaction ordering fields"
                )

    def _step_root_request(self, task: _RootRequest) -> None:
        try:
            if task.request_cursor is None:
                begin_get = getattr(self.transport, "begin_get", None)
                if callable(begin_get):
                    task.request_cursor = begin_get(task.path, None)
            if task.request_cursor is not None:
                task.request_cursor.step()
                if not task.request_cursor.done:
                    return
                response = task.request_cursor.result()
            else:
                response = self.transport.get(task.path)
            if not is_success_status(response.status_code):
                raise response_status_error(
                    response,
                    redact_url=getattr(self.transport, "_redact_url", None),
                )
            if not isinstance(response.body, dict):
                raise ResponseShapeError(
                    f"expected repository object from {response.url}"
                )
            repository = self._scheduled_repository(task.target, response.body)
            if not isinstance(repository, dict):
                raise ResponseShapeError(
                    "provider returned an invalid normalized repository"
                )
            retrieval_key = new_response_correlation_key()
            repository["_retrieval_key"] = retrieval_key
            task.snapshot = RepositorySnapshot(
                repository,
                retrievals=[
                    response_retrieval_provenance(
                        response,
                        key=retrieval_key,
                        target_ref=task.path,
                        endpoint_kind="repositories",
                    )
                ],
            )
        except EXPECTED_PROVIDER_FAILURES as exc:
            task.snapshot = self._failed_repository_snapshot(exc)
        task.done = True

    @staticmethod
    def _failed_source_result(error: Exception, note: str) -> SourceResult:
        return SourceResult([], "incomplete", note, exception_diagnostics(error))

    @classmethod
    def _failed_repository_snapshot(cls, error: Exception) -> RepositorySnapshot:
        diagnostics = exception_diagnostics(error)
        note = (
            "provider request failed"
            if isinstance(error, ApiError)
            else "provider collection failed"
        )
        return RepositorySnapshot(
            None,
            {
                source: SourceResult([], "incomplete", note, dict(diagnostics))
                for source in CORE_RESOURCE_SOURCES
            },
        )

    def _run_page_rounds(
        self,
        tasks: list[PageSourceRequest],
        *,
        interaction_rounds: bool,
    ) -> None:
        source_order = {
            source: index
            for index, source in enumerate(
                ("work_items", "change_requests", "commits", "releases")
            )
        }
        for task in tasks:
            try:
                if (
                    interaction_rounds
                    and task.source != "interactions"
                    or (not interaction_rounds and task.source not in source_order)
                ):
                    raise ResponseShapeError(
                        "provider returned an invalid scheduled source"
                    )
                task.cursor = PaginationCursor(
                    self.transport,
                    task.path,
                    task.params,
                    per_page=100,
                    max_pages=self.max_pages,
                    strategy=self.pagination_strategy,
                )
            except EXPECTED_PROVIDER_FAILURES as exc:
                task.result = self._failed_source_result(
                    exc, "scheduled source initialization failed"
                )
        interaction_subject_offsets: dict[str, int] = {}
        interaction_endpoint_offsets: dict[tuple[str, str, str], int] = {}
        while any(task.result is None for task in tasks):
            active = [task for task in tasks if task.result is None]
            if interaction_rounds:
                active.sort(
                    key=lambda task: (
                        task.target.canonical_id,
                        task.subject_type,
                        task.subject_id,
                        task.endpoint_kind,
                    )
                )
                selected = []
                by_repository: dict[str, list[PageSourceRequest]] = {}
                for task in active:
                    by_repository.setdefault(task.target.canonical_id, []).append(task)
                for repository_id, candidates in by_repository.items():
                    by_subject: dict[tuple[str, str], list[PageSourceRequest]] = {}
                    for task in candidates:
                        subject = (task.subject_type, task.subject_id)
                        by_subject.setdefault(subject, []).append(task)
                    subjects = list(by_subject)
                    subject_offset = interaction_subject_offsets.get(repository_id, 0)
                    subject = subjects[subject_offset % len(subjects)]
                    interaction_subject_offsets[repository_id] = subject_offset + 1
                    endpoints = by_subject[subject]
                    endpoint_key = (repository_id, *subject)
                    endpoint_offset = interaction_endpoint_offsets.get(endpoint_key, 0)
                    selected.append(endpoints[endpoint_offset % len(endpoints)])
                    interaction_endpoint_offsets[endpoint_key] = endpoint_offset + 1
            else:
                selected = sorted(
                    active,
                    key=lambda task: (
                        (task.cursor.pages if task.cursor is not None else 0) + 1,
                        task.target.canonical_id,
                        source_order[task.source],
                    ),
                )
            for task in selected:
                try:
                    if task.cursor is None:
                        raise ResponseShapeError(
                            "scheduled source cursor is unavailable"
                        )
                    task.cursor.step()
                    if not task.cursor.done:
                        continue
                    normalized = self._normalize_scheduled_page(
                        task, task.cursor.result()
                    )
                    if not isinstance(normalized, SourceResult):
                        raise ResponseShapeError(
                            "provider returned an invalid normalized source"
                        )
                    task.result = normalized
                except EXPECTED_PROVIDER_FAILURES as exc:
                    diagnostics = exception_diagnostics(exc)
                    diagnostics["metrics"] = transport_metrics(self.transport)
                    if isinstance(exc, ApiError) and task.cursor is not None:
                        try:
                            task.result = self._normalize_scheduled_page(
                                task,
                                PageResult(
                                    list(task.cursor.items),
                                    task.cursor.pages,
                                    False,
                                    diagnostics,
                                    list(task.cursor.retrievals),
                                    list(task.cursor.item_retrieval_keys),
                                ),
                            )
                            if not isinstance(task.result, SourceResult):
                                raise ResponseShapeError(
                                    "provider returned an invalid normalized source"
                                )
                            task.result.note = (
                                "provider request failed after "
                                f"{task.cursor.pages} accepted page(s)"
                            )
                        except EXPECTED_PROVIDER_FAILURES as normalization_error:
                            task.result = self._failed_source_result(
                                normalization_error,
                                "scheduled source normalization failed",
                            )
                    else:
                        task.result = SourceResult(
                            [],
                            "incomplete",
                            "scheduled source failed unexpectedly",
                            diagnostics,
                        )

    def _normalize_scheduled_page(
        self,
        task: PageSourceRequest,
        page: PageResult,
    ) -> SourceResult:
        diagnostics = dict(page.diagnostics or {})
        metrics = transport_metrics(self.transport)
        if (
            metrics["retry_count"]
            or metrics["budget_exhausted"]
            or metrics["cache_hits"]
            or metrics["cache_misses"]
        ):
            diagnostics.setdefault("metrics", metrics)
        result = SourceResult(
            page.items,
            "supported" if page.complete else "incomplete",
            (
                f"{page.pages} page(s)"
                if page.complete
                else f"{task.source} pagination reached the configured page limit"
            ),
            diagnostics,
            page.retrievals,
            page.item_retrieval_keys,
        )
        for retrieval in result.retrievals:
            retrieval.setdefault("endpoint_kind", task.endpoint_kind or task.source)
        return self._normalize_items(
            result,
            task.source,
            task.normalizer,
            target=task.target,
            filter_item=task.filter_item,
        )

    @staticmethod
    def _merge_scheduled_sources(results: list[SourceResult]) -> SourceResult:
        records: list[dict[str, Any]] = []
        notes: list[str] = []
        diagnostics: dict[str, Any] = {}
        retrievals: list[dict[str, Any]] = []
        item_retrieval_keys: list[str] = []
        complete = True
        for result in results:
            records.extend(result.items)
            retrievals.extend(result.retrievals)
            item_retrieval_keys.extend(result.item_retrieval_keys)
            merge_diagnostics(diagnostics, result.diagnostics)
            if result.status != "supported":
                complete = False
                if result.note:
                    notes.append(result.note)
        return SourceResult(
            records,
            "supported" if complete else "incomplete",
            "; ".join(notes),
            diagnostics,
            retrievals,
            item_retrieval_keys,
        )

    def _strict_source_result(
        self,
        result: SourceResult,
        source: str,
        target: RepositoryTarget,
        request: CollectionRequest,
    ) -> SourceResult:
        """Reject identity/repository/time gaps while retaining valid siblings."""
        if not isinstance(result.items, list):
            result.items = []
            _append_normalization_diagnostics(result, source, 1, {"malformed_response"})
            return result
        valid: list[dict[str, Any]] = []
        dropped = 0
        failure_classes: set[str] = set()
        valid_retrieval_keys: list[str] = []
        for position, item in enumerate(result.items):
            try:
                if source == "activities":
                    self._validate_activity_item(item, request)
                else:
                    self._validate_canonical_item(item, source, target, request)
                valid.append(item)
                if position < len(result.item_retrieval_keys):
                    valid_retrieval_keys.append(result.item_retrieval_keys[position])
            except PrivacyError:
                raise
            except MALFORMED_NORMALIZATION_ERRORS:
                dropped += 1
                failure_classes.add("malformed_response")
        result.items = valid
        result.item_retrieval_keys = valid_retrieval_keys
        _append_normalization_diagnostics(result, source, dropped, failure_classes)
        return result

    @staticmethod
    def _validate_activity_item(item: Any, request: CollectionRequest) -> None:
        if not isinstance(item, dict):
            raise StrictNormalizationError("activity item must be an object")
        event_id = native_id(item, "id", "event_id", "push_id")
        del event_id
        occurred_at = first_timestamp(item, "created_at", "occurred_at", "updated_at")
        if parse_timestamp(occurred_at) is None or not in_window(occurred_at, request):
            raise StrictNormalizationError(
                "activity item has an invalid or out-of-window timestamp"
            )

    @staticmethod
    def _validate_canonical_item(
        item: Any,
        source: str,
        target: RepositoryTarget,
        request: CollectionRequest,
    ) -> None:
        if not isinstance(item, dict):
            raise StrictNormalizationError(f"{source} item must be an object")
        entity_id = item.get("id")
        if not isinstance(entity_id, str) or not entity_id.strip():
            raise StrictNormalizationError(f"{source} item has no stable canonical id")
        if source == "repositories":
            if entity_id != target.canonical_id:
                raise StrictNormalizationError(
                    "repository identity does not match the allowlist"
                )
            if not isinstance(item.get("provider_id"), str) or not item["provider_id"]:
                raise StrictNormalizationError(
                    "repository item has no provider identity"
                )
            for field in ("full_name", "name"):
                if not isinstance(item.get(field), str) or not item[field].strip():
                    raise StrictNormalizationError(f"repository item has no {field}")
            return
        if item.get("repository_id") != target.canonical_id:
            raise StrictNormalizationError(
                f"{source} item has the wrong repository identity"
            )
        if not is_valid_native_id(item.get("_native_id")):
            raise StrictNormalizationError(f"{source} item has no stable native id")
        if source == "commits":
            sha = item.get("sha")
            native_sha = item.get("_native_id")
            if (
                not is_verifiable_sha(sha)
                or native_sha != sha
                or not entity_id.endswith(f":{sha}")
            ):
                raise StrictNormalizationError(
                    "commit SHA does not match its canonical/native identity"
                )
        occurred_at = item.get("occurred_at")
        if parse_timestamp(occurred_at) is None or not in_window(occurred_at, request):
            raise StrictNormalizationError(
                f"{source} item has an invalid or out-of-window occurred_at"
            )
        if source in {
            "work_items",
            "change_requests",
            "interactions",
        } and not is_valid_native_id(
            item.get("number")
            if source != "interactions"
            else item.get("subject_number")
        ):
            raise StrictNormalizationError(
                f"{source} item has no stable subject number"
            )
        if source == "interactions":
            subject_type = item.get("subject_type")
            subject_id = item.get("subject_id")
            if subject_type not in {"work_item", "change_request"}:
                raise StrictNormalizationError("interaction has no valid subject type")
            expected_subject_id = (
                target.canonical_id.replace("repo:", f"{subject_type}:", 1)
                + f":{item.get('subject_number')}"
            )
            if not isinstance(subject_id, str) or subject_id != expected_subject_id:
                raise StrictNormalizationError(
                    "interaction has no canonical subject identity"
                )

    def _normalize_items(
        self,
        result: SourceResult,
        source: str,
        normalizer: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        target: RepositoryTarget | None = None,
        filter_item: Callable[[Any], bool] | None = None,
    ) -> SourceResult:
        """Normalize valid records while turning malformed items into diagnostics."""
        normalized: list[dict[str, Any]] = []
        dropped = 0
        failure_classes: set[str] = set()
        normalized_retrieval_keys: list[str] = []
        for position, item in enumerate(result.items):
            try:
                if filter_item is not None and not filter_item(item):
                    continue
                normalized_item = normalizer(item)
                retrieval_key = (
                    result.item_retrieval_keys[position]
                    if position < len(result.item_retrieval_keys)
                    else item.get("_retrieval_key")
                )
                if isinstance(normalized_item, dict) and isinstance(retrieval_key, str):
                    normalized_item["_retrieval_key"] = retrieval_key
                    normalized_retrieval_keys.append(retrieval_key)
                if target is not None:
                    validate_native_item_repository_identity(
                        item,
                        normalized_item,
                        target,
                        provider_kind=self.descriptor.kind,
                    )
                normalized.append(normalized_item)
            except PrivacyError:
                raise
            except MALFORMED_NORMALIZATION_ERRORS:
                dropped += 1
                failure_classes.add("malformed_response")
        result.items = normalized
        result.item_retrieval_keys = normalized_retrieval_keys
        _append_normalization_diagnostics(result, source, dropped, failure_classes)
        return result

    def _safe_page(
        self,
        source: str,
        fetch: Callable[[], PageResult],
    ) -> SourceResult:
        try:
            result = fetch()
        except ApiError as exc:
            diagnostics = api_error_diagnostics(exc)
            diagnostics["metrics"] = transport_metrics(self.transport)
            return SourceResult(
                [], "incomplete", "provider request failed", diagnostics
            )
        for retrieval in result.retrievals:
            retrieval.setdefault("endpoint_kind", source)
        diagnostics = dict(result.diagnostics or {})
        metrics = transport_metrics(self.transport)
        if (
            metrics["retry_count"]
            or metrics["budget_exhausted"]
            or metrics["cache_hits"]
            or metrics["cache_misses"]
        ):
            diagnostics.setdefault("metrics", metrics)
        return SourceResult(
            result.items,
            "supported" if result.complete else "incomplete",
            f"{result.pages} page(s)"
            if result.complete
            else f"{source} pagination reached the configured page limit",
            diagnostics,
            result.retrievals,
            result.item_retrieval_keys,
        )

    def _scheduled_root_path(self, target: RepositoryTarget) -> str:
        raise ProviderNotReady(
            f"{self.descriptor.kind} root scheduling is not implemented"
        )

    def _scheduled_repository(
        self,
        target: RepositoryTarget,
        raw: dict[str, Any],
    ) -> dict[str, Any]:
        raise ProviderNotReady(
            f"{self.descriptor.kind} root normalization is not implemented"
        )

    def _scheduled_top_level_requests(
        self,
        target: RepositoryTarget,
        request: CollectionRequest,
    ) -> list[PageSourceRequest]:
        raise ProviderNotReady(
            f"{self.descriptor.kind} source scheduling is not implemented"
        )

    def _scheduled_interaction_requests(
        self,
        target: RepositoryTarget,
        snapshot: RepositorySnapshot,
        request: CollectionRequest,
    ) -> list[PageSourceRequest]:
        raise ProviderNotReady(
            f"{self.descriptor.kind} interaction scheduling is not implemented"
        )

    def _collect_activity(
        self, target: RepositoryTarget, request: CollectionRequest
    ) -> dict[str, SourceResult]:
        return {
            source: SourceResult(
                [],
                "unsupported",
                "activity/ref collection is not implemented for this provider",
            )
            for source in ACTIVITY_SOURCES
        }
