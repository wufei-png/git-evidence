from __future__ import annotations

import ipaddress
import math
import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote, unquote, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import idna

from ..limits import (
    MAX_PAGES,
    MAX_REQUESTS,
    MAX_RETRIES,
    MAX_RETRY_AFTER_SECONDS,
    MAX_RETRY_JITTER_SECONDS,
    MAX_TIMEOUT_SECONDS,
    MIN_CORE_REQUESTS_PER_REPOSITORY,
    MIN_RETRY_AFTER_SECONDS,
    MIN_TIMEOUT_SECONDS,
)

CAPABILITY_STATES = ("supported", "unsupported", "unavailable", "incomplete")
CAPABILITY_STATUS_PRIORITY = {
    "supported": 0,
    "unsupported": 1,
    "unavailable": 2,
    "incomplete": 3,
}
RESOURCE_SOURCES = (
    "repositories",
    "work_items",
    "change_requests",
    "interactions",
    "commits",
    "releases",
)
ACTIVITY_SOURCES = ("activities", "ref_changes")
OPTIONAL_COVERAGE_WARNING_CODE = "optional_coverage_warning"
# Optional warning status is an evidence-quality severity, not a success flag.
# Keep the most conservative state when observations are combined in either
# order so warning output cannot depend on provider/group iteration order.
OPTIONAL_STATUS_PRIORITY = {
    "unsupported": 1,
    "unavailable": 2,
    "incomplete": 3,
}
OPERATIONAL_FAILURE_CLASSES = frozenset(
    {
        "permission_denied",
        "rate_limited",
        "service_error",
        "not_found",
        "request_rejected",
        "network_error",
        "transport_error",
        "fixture_missing",
        "http_error",
        "malformed_response",
        "provider_not_ready",
        "unexpected_error",
        "unexpected_normalizer_error",
        "budget_exhausted",
        "insecure_transport",
        "limit_exceeded",
        "privacy_violation",
    }
)
UNVERIFIABLE_SHA_SENTINELS = frozenset(
    {
        "missing",
        "na",
        "n/a",
        "nil",
        "none",
        "not available",
        "not provided",
        "null",
        "undefined",
        "unknown",
        "unavailable",
    }
)
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ENCODED_PATH_SEPARATOR = re.compile(r"(?i)%(?:2f|5c)")
_URI_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")


def contains_url_control(value: str) -> bool:
    """Return whether text contains a C0, DEL, or C1 control character."""
    return any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in value
    )


def _is_legacy_numeric_host(hostname: str) -> bool:
    labels = hostname.removesuffix(".").split(".")
    return bool(labels) and all(
        re.fullmatch(r"(?:[0-9]+|0[xX][0-9A-Fa-f]+)", label) for label in labels
    )


def canonicalize_hostname(hostname: str | None, *, field: str) -> str:
    """Return one strict IDNA2008/IP spelling for an authority host."""
    if not hostname:
        raise ValueError(f"{field} must contain a host")
    try:
        return ipaddress.ip_address(hostname).compressed.lower()
    except ValueError:
        pass
    if _is_legacy_numeric_host(hostname):
        raise ValueError(f"{field} uses a non-canonical numeric address")
    try:
        canonical = (
            idna.encode(
                hostname,
                uts46=True,
                transitional=False,
                std3_rules=True,
            )
            .decode("ascii")
            .lower()
        )
    except idna.IDNAError as exc:
        raise ValueError(f"{field} is not valid IDNA") from exc
    canonical = canonical.removesuffix(".")
    if not canonical:
        raise ValueError(f"{field} must contain a host")
    try:
        ipaddress.ip_address(canonical)
    except ValueError:
        if _is_legacy_numeric_host(canonical):
            raise ValueError(f"{field} uses a non-canonical numeric address")
    else:
        raise ValueError(f"{field} uses a non-canonical numeric address")
    return canonical


def canonicalize_base_path(
    path: str,
    *,
    field: str,
    allow_first_level_encoded_separators: bool = False,
) -> str:
    """Decode a URL path to a bounded fixed point and reject ambiguous forms."""
    encoded = path or "/"
    if _INVALID_PERCENT_ESCAPE.search(encoded):
        raise ValueError(f"{field} contains invalid percent encoding")
    if (
        _ENCODED_PATH_SEPARATOR.search(encoded)
        and not allow_first_level_encoded_separators
    ):
        raise ValueError(f"{field} must not encode path separators")
    try:
        decoded = unquote(encoded, errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{field} contains invalid encoding") from exc
    if "%" in decoded:
        raise ValueError(f"{field} must not contain nested percent encoding")
    if "\\" in decoded or contains_url_control(decoded):
        raise ValueError(f"{field} contains unsafe characters")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ValueError(f"{field} must not contain dot segments")
    normalized = posixpath.normpath("/" + decoded.lstrip("/"))
    return normalized if normalized.startswith("/") else f"/{normalized}"


def git_object_id_algorithm(value: Any) -> str | None:
    """Return the Git object-id algorithm for a full hexadecimal identifier."""
    if not isinstance(value, str):
        return None
    normalized = value.lower()
    if normalized in UNVERIFIABLE_SHA_SENTINELS:
        return None
    if re.fullmatch(r"[0-9a-f]{40}", normalized):
        return "sha1"
    if re.fullmatch(r"[0-9a-f]{64}", normalized):
        return "sha256"
    return None


def is_verifiable_sha(value: Any) -> bool:
    """Return whether value is a full SHA-1 or SHA-256 Git object id."""
    return git_object_id_algorithm(value) is not None


def merge_capability_status(current: Any, incoming: Any) -> str:
    """Combine capability states monotonically using the conservative result."""
    current_priority = CAPABILITY_STATUS_PRIORITY.get(current, -1)
    incoming_priority = CAPABILITY_STATUS_PRIORITY.get(incoming, 3)
    if current_priority >= incoming_priority and current in CAPABILITY_STATUS_PRIORITY:
        return current
    return incoming if incoming in CAPABILITY_STATUS_PRIORITY else "incomplete"


def coverage_blocker(
    *,
    code: str,
    provider: str,
    instance: str,
    repository: str,
    source: str,
    status: str = "incomplete",
    failure_class: str | None = None,
    message: str | None = None,
) -> dict[str, str]:
    """Build the single machine-readable publication-blocker shape."""
    blocker = {
        "code": code,
        "provider": provider,
        "instance": instance,
        "repository": repository,
        "source": source,
        "status": status,
    }
    if failure_class:
        blocker["failure_class"] = failure_class
    if message:
        blocker["message"] = message
    return blocker


def _coverage_failure_classes(value: Any) -> set[str]:
    classes: set[str] = set()
    if isinstance(value, Mapping):
        failure_class = value.get("failure_class")
        if isinstance(failure_class, str) and failure_class:
            classes.add(failure_class)
        failure_classes = value.get("failure_classes")
        if isinstance(failure_classes, (list, tuple, set)):
            classes.update(
                item for item in failure_classes if isinstance(item, str) and item
            )
        for child in value.values():
            classes.update(_coverage_failure_classes(child))
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            classes.update(_coverage_failure_classes(child))
    return classes


def optional_coverage_warning(observation: Mapping[str, Any]) -> dict[str, Any] | None:
    """Build a machine-readable warning for a non-complete optional source."""
    source = observation.get("source")
    status = observation.get("status")
    provider_id = observation.get("provider_id")
    repository_id = observation.get("repository_id")
    if (
        source not in ACTIVITY_SOURCES
        or status == "supported"
        or not isinstance(provider_id, str)
        or not isinstance(repository_id, str)
    ):
        return None
    warning: dict[str, Any] = {
        "code": OPTIONAL_COVERAGE_WARNING_CODE,
        "source": source,
        "provider_id": provider_id,
        "repository_id": repository_id,
        "status": status,
    }
    note = observation.get("note")
    if isinstance(note, str) and note.strip():
        warning["message"] = note
    failure_classes = sorted(_coverage_failure_classes(observation.get("diagnostics")))
    if len(failure_classes) == 1:
        warning["failure_class"] = failure_classes[0]
    elif failure_classes:
        warning["failure_classes"] = failure_classes
    return warning


def append_optional_coverage_warning(
    coverage: dict[str, Any], observation: Mapping[str, Any]
) -> None:
    warning = optional_coverage_warning(observation)
    if warning is None:
        return
    merge_optional_coverage_warning(coverage, warning)


def merge_optional_coverage_warning(
    coverage: dict[str, Any], warning: Mapping[str, Any]
) -> None:
    """Insert or monotonically enrich one optional coverage warning."""
    if warning.get("code") != OPTIONAL_COVERAGE_WARNING_CODE:
        return
    warnings = coverage.setdefault("warnings", [])
    if not isinstance(warnings, list):
        warnings = []
        coverage["warnings"] = warnings
    fields = ("code", "source", "provider_id", "repository_id")
    observation_fields = ("source", "provider_id", "repository_id")
    key = tuple(warning.get(field) for field in fields)
    statuses = [
        status
        for status in (warning.get("status"),)
        if status in OPTIONAL_STATUS_PRIORITY
    ]
    for existing in warnings:
        if (
            not isinstance(existing, dict)
            or tuple(existing.get(field) for field in fields) != key
        ):
            continue
        existing_status = existing.get("status")
        if existing_status in OPTIONAL_STATUS_PRIORITY:
            statuses.append(existing_status)
        if statuses:
            existing["status"] = max(statuses, key=OPTIONAL_STATUS_PRIORITY.__getitem__)
        failure_classes = _coverage_failure_classes(
            existing
        ) | _coverage_failure_classes(warning)
        if len(failure_classes) == 1:
            existing["failure_class"] = next(iter(failure_classes))
            existing.pop("failure_classes", None)
        elif failure_classes:
            existing.pop("failure_class", None)
            existing["failure_classes"] = sorted(failure_classes)
        existing_message = existing.get("message")
        incoming_message = warning.get("message")
        if isinstance(existing_message, str) and existing_message.strip():
            if isinstance(incoming_message, str) and incoming_message.strip():
                if existing_message in incoming_message:
                    existing["message"] = incoming_message
                elif incoming_message not in existing_message:
                    existing["message"] = f"{existing_message}; {incoming_message}"
        elif isinstance(incoming_message, str) and incoming_message.strip():
            existing["message"] = incoming_message
        if statuses:
            observations = coverage.get("observations")
            if isinstance(observations, list):
                for observation in observations:
                    if (
                        isinstance(observation, dict)
                        and tuple(
                            observation.get(field) for field in observation_fields
                        )
                        == key[1:]
                        and observation.get("status") in OPTIONAL_STATUS_PRIORITY
                    ):
                        observation["status"] = existing["status"]
        return
    new_warning = dict(warning)
    if statuses:
        new_warning["status"] = max(statuses, key=OPTIONAL_STATUS_PRIORITY.__getitem__)
    warnings.append(new_warning)
    if statuses:
        observations = coverage.get("observations")
        if isinstance(observations, list):
            for observation in observations:
                if (
                    isinstance(observation, dict)
                    and tuple(observation.get(field) for field in observation_fields)
                    == key[1:]
                    and observation.get("status") in OPTIONAL_STATUS_PRIORITY
                ):
                    observation["status"] = new_warning["status"]


@dataclass(frozen=True)
class ProviderDescriptor:
    """Public provider contract metadata, not a claim of live completeness."""

    kind: str
    display_name: str
    endpoint_style: str
    resource_sources: tuple[str, ...] = RESOURCE_SOURCES
    activity_sources: tuple[str, ...] = ACTIVITY_SOURCES
    implementation_status: str = "contract-only"

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "display_name": self.display_name,
            "endpoint_style": self.endpoint_style,
            "resource_sources": list(self.resource_sources),
            "activity_sources": list(self.activity_sources),
            "implementation_status": self.implementation_status,
        }


@dataclass(frozen=True)
class RepositoryTarget:
    provider_kind: str
    instance: str
    owner: str
    name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "instance", validate_instance(self.instance))
        owner_segments = (
            self.owner.split("/") if self.provider_kind == "gitlab" else [self.owner]
        )
        for index, segment in enumerate(owner_segments):
            _validate_repository_segment(segment, f"owner segment {index}")
        _validate_repository_segment(self.name, "repository name")

    @property
    def canonical_id(self) -> str:
        return f"repo:{self.provider_kind}:{self.instance}:{self.owner}/{self.name}"


def _validate_repository_segment(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    if value in {".", ".."} or not all(
        character.isalnum() or character in {".", "_", "-"} for character in value
    ):
        raise ValueError(f"{field} must be one safe repository path segment")


def validate_instance(instance: Any) -> str:
    """Validate and canonicalize an instance authority plus optional base path."""
    if not isinstance(instance, str) or not instance or instance != instance.strip():
        raise ValueError("instance must be a non-empty URL host or http(s) base")
    if any(character.isspace() for character in instance) or contains_url_control(
        instance
    ):
        raise ValueError("instance must not contain whitespace or control characters")
    if "?" in instance or "#" in instance:
        raise ValueError("instance must not contain a query or fragment")
    scheme_match = _URI_SCHEME.match(instance)
    explicit_scheme = False
    if scheme_match:
        scheme_name = scheme_match.group(1).lower()
        suffix = instance[scheme_match.end() :]
        if scheme_name in {"http", "https"}:
            if re.match(r"(?i)^https?://", instance) is None:
                raise ValueError("instance must use an http or https URL")
            explicit_scheme = True
        elif not suffix.split("/", 1)[0].isdigit():
            raise ValueError("instance must use an http or https URL")
    candidate = instance if explicit_scheme else f"//{instance}"
    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError("instance is not a valid URL authority") from exc
    if parts.scheme and parts.scheme not in {"http", "https"}:
        raise ValueError("instance must use http or https")
    if not parts.netloc or not hostname:
        raise ValueError("instance must contain a host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("instance must not contain URL userinfo")
    if parts.query or parts.fragment:
        raise ValueError("instance must not contain a query or fragment")
    assert hostname is not None
    canonical_host = canonicalize_hostname(hostname, field="instance host")
    host_text = f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    scheme = parts.scheme.lower() if explicit_scheme else "https"
    default_port = {"http": 80, "https": 443}[scheme]
    authority = host_text if port in {None, default_port} else f"{host_text}:{port}"
    normalized_path = canonicalize_base_path(parts.path, field="instance base path")
    normalized_path = (
        ""
        if normalized_path == "/"
        else quote(normalized_path.rstrip("/"), safe="/:@-._~!$&'()*+,;=")
    )
    if scheme == "https" and not normalized_path and port in {None, 443}:
        return authority
    return f"{scheme}://{authority}{normalized_path}"


def validate_timezone(timezone: Any) -> str:
    """Require an explicit IANA timezone identifier without changing instants."""
    if not isinstance(timezone, str) or not timezone or timezone != timezone.strip():
        raise ValueError("timezone must be a non-empty IANA identifier")
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("timezone must be a valid IANA identifier") from exc
    return timezone


def is_loopback_instance(instance: str) -> bool:
    """Return whether an already validated instance targets loopback only."""
    instance = validate_instance(instance)
    candidate = (
        instance if instance.startswith(("http://", "https://")) else f"//{instance}"
    )
    hostname = urlsplit(candidate).hostname
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def instance_web_base(instance: str) -> str:
    """Return an HTTPS-or-explicit-scheme web base for a provider instance."""
    value = validate_instance(instance)
    if value.startswith(("http://", "https://")):
        return value
    return f"https://{value}"


@dataclass(frozen=True)
class CollectionRequest:
    provider_kind: str
    instance: str
    repositories: tuple[RepositoryTarget, ...]
    window_start: str
    window_end: str
    timezone: str
    include_activity_api: bool = False
    actor_ids: tuple[str, ...] = ()
    timeout_seconds: float = 30.0
    max_retries: int = 2
    max_pages: int = 100
    max_requests: int = 1000
    retry_jitter_seconds: float = 0.25
    retry_after_max_seconds: float = 60.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "instance", validate_instance(self.instance))
        object.__setattr__(self, "timezone", validate_timezone(self.timezone))
        if not self.repositories:
            raise ValueError("repositories must be a non-empty allowlist")
        for target in self.repositories:
            if not isinstance(target, RepositoryTarget):
                raise TypeError("repositories must contain RepositoryTarget values")
            if (
                target.provider_kind != self.provider_kind
                or target.instance != self.instance
            ):
                raise ValueError(
                    "repository target provider and instance must match the request"
                )
        canonical_ids = [target.canonical_id for target in self.repositories]
        if len(canonical_ids) != len(set(canonical_ids)):
            raise ValueError(
                "repositories must not contain duplicate canonical targets"
            )
        ordered_repositories = tuple(
            sorted(self.repositories, key=lambda item: item.canonical_id)
        )
        object.__setattr__(self, "repositories", ordered_repositories)
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds < MIN_TIMEOUT_SECONDS
            or self.timeout_seconds > MAX_TIMEOUT_SECONDS
        ):
            raise ValueError(
                f"timeout_seconds must be finite and in [{MIN_TIMEOUT_SECONDS}, {MAX_TIMEOUT_SECONDS}]"
            )
        for name, value, maximum, minimum in (
            ("max_retries", self.max_retries, MAX_RETRIES, 0),
            ("max_pages", self.max_pages, MAX_PAGES, 1),
            ("max_requests", self.max_requests, MAX_REQUESTS, 1),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < minimum
                or value > maximum
            ):
                raise ValueError(f"{name} must be in [{minimum}, {maximum}]")
        minimum_core_budget = MIN_CORE_REQUESTS_PER_REPOSITORY * len(self.repositories)
        if self.max_requests < minimum_core_budget:
            raise ValueError(
                "plan_budget_infeasible: max_requests must be at least "
                f"{minimum_core_budget} for {len(self.repositories)} repositories"
            )
        if (
            isinstance(self.retry_jitter_seconds, bool)
            or not isinstance(self.retry_jitter_seconds, (int, float))
            or not math.isfinite(float(self.retry_jitter_seconds))
            or self.retry_jitter_seconds < 0
            or self.retry_jitter_seconds > MAX_RETRY_JITTER_SECONDS
        ):
            raise ValueError(
                f"retry_jitter_seconds must be finite and in [0, {MAX_RETRY_JITTER_SECONDS}]"
            )
        if (
            isinstance(self.retry_after_max_seconds, bool)
            or not isinstance(self.retry_after_max_seconds, (int, float))
            or not math.isfinite(float(self.retry_after_max_seconds))
            or self.retry_after_max_seconds < MIN_RETRY_AFTER_SECONDS
            or self.retry_after_max_seconds > MAX_RETRY_AFTER_SECONDS
        ):
            raise ValueError(
                f"retry_after_max_seconds must be finite and in [{MIN_RETRY_AFTER_SECONDS}, {MAX_RETRY_AFTER_SECONDS}]"
            )

    @property
    def repository_ids(self) -> tuple[str, ...]:
        return tuple(repository.canonical_id for repository in self.repositories)


class ProviderNotReady(RuntimeError):
    """A provider contract exists but its network collector is not ready."""


class Provider(Protocol):
    descriptor: ProviderDescriptor

    def probe(self) -> dict[str, Any]:
        """Return provider metadata without making a repository claim."""

    def collect(self, request: CollectionRequest) -> dict[str, Any]:
        """Collect a canonical bundle or raise ProviderNotReady."""


def validate_descriptor(descriptor: ProviderDescriptor) -> None:
    if not descriptor.kind or not descriptor.display_name:
        raise ValueError("provider descriptor requires kind and display_name")
    if descriptor.implementation_status not in {
        "contract-only",
        "experimental",
        "stable",
    }:
        raise ValueError("invalid provider implementation_status")
    for source in (*descriptor.resource_sources, *descriptor.activity_sources):
        if not source:
            raise ValueError("provider source names cannot be empty")
