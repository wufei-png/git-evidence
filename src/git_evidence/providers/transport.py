from __future__ import annotations

import hashlib
import json
import math
import os
import posixpath
import random
import re
import ssl
import stat
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import (
    parse_qsl,
    quote,
    unquote,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)
from urllib.request import (
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from ..bounds import InputLimitError, json_size_with_limit, read_bounded_bytes
from ..bounds import validate_json_value_limits as _validate_json_value_limits
from ..limits import (
    MAX_CACHE_ENTRIES,
    MAX_CACHE_FILE_BYTES,
    MAX_CACHE_TTL_SECONDS,
    MAX_JSON_DEPTH,
    MAX_JSON_STRING_CHARS,
    MAX_PAGE_ITEMS,
    MAX_PAGES,
    MAX_PAGINATED_BYTES,
    MAX_PAGINATED_ITEMS,
    MAX_REQUESTS,
    MAX_RESPONSE_BYTES,
    MAX_RETRIES,
    MAX_RETRY_AFTER_SECONDS,
    MAX_RETRY_BACKOFF_SECONDS,
    MAX_RETRY_JITTER_SECONDS,
    MAX_TIMEOUT_SECONDS,
    MIN_RETRY_AFTER_SECONDS,
    MIN_TIMEOUT_SECONDS,
)
from ..privacy import (
    canonicalize_field_name,
    has_auth_material,
    is_redacted_public_url,
    is_sensitive_field,
    is_url_field,
    redact_public_url,
)
from .base import is_loopback_instance, validate_instance

RATE_LIMIT_HEADERS = (
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
)

CACHE_HEADER_NAMES = frozenset(
    canonicalize_field_name(name)
    for name in ("link", "x-next-page", "x-next-page-number", *RATE_LIMIT_HEADERS)
)
CACHE_HEADER_NAMES = CACHE_HEADER_NAMES | frozenset(
    {"x_rate_limit_limit", "x_rate_limit_remaining", "x_rate_limit_reset"}
)
_NEXT_PAGE_HEADER_NAMES = frozenset({"x_next_page", "x_next_page_number"})
_NUMERIC_RATE_HEADER_NAMES = frozenset(
    {
        "x_ratelimit_limit",
        "x_ratelimit_remaining",
        "x_ratelimit_reset",
        "x_rate_limit_limit",
        "x_rate_limit_remaining",
        "x_rate_limit_reset",
    }
)
_LINK_ENTRY_PATTERN = re.compile(
    r"\s*<(?P<url>[^<>]+)>\s*;\s*rel\s*=\s*"
    r"(?P<rel>\"[^\"]+\"|'[^']+'|[^,\s]+)"
    r"(?:\s*;\s*[^,]+)*\s*"
)
_URL_CANDIDATE_PATTERN = re.compile(r"(?:https?://|/)[^\s<>\"']+")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_MAX_PATH_DECODE_PASSES = 8


def _effective_port(scheme: str, port: int | None) -> int | None:
    return port if port is not None else {"http": 80, "https": 443}.get(scheme)


def _canonical_hostname(hostname: str | None) -> str:
    if not hostname:
        raise ValueError("request target must contain a host")
    try:
        return hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("request target host is not valid IDNA") from exc


def _authority_text(scheme: str, hostname: str, port: int | None) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port != _effective_port(scheme, None):
        return f"{host}:{port}"
    return host


def _decoded_safe_path(path: str) -> str:
    decoded = path or "/"
    for _ in range(_MAX_PATH_DECODE_PASSES):
        if _INVALID_PERCENT_ESCAPE.search(decoded):
            raise ValueError("request target path contains invalid percent encoding")
        try:
            next_value = unquote(decoded, errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("request target path contains invalid encoding") from exc
        if next_value == decoded:
            break
        decoded = next_value
    else:
        raise ValueError("request target path contains excessive nested encoding")
    if "\\" in decoded or any(ord(character) < 0x20 for character in decoded):
        raise ValueError("request target path contains unsafe characters")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ValueError("request target path contains a dot segment")
    normalized = posixpath.normpath("/" + decoded.lstrip("/"))
    return normalized if normalized.startswith("/") else f"/{normalized}"


@dataclass(frozen=True)
class AllowedApiTarget:
    """Canonical origin and path boundary for one provider transport."""

    scheme: str
    hostname: str
    port: int | None
    path_prefix: str
    credential_query_names: tuple[str, ...] = ()

    @classmethod
    def from_base_url(
        cls,
        base_url: str,
        *,
        credential_query_names: tuple[str, ...] = (),
    ) -> AllowedApiTarget:
        parts = urlsplit(base_url)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("request target must use http or https")
        if parts.username is not None or parts.password is not None:
            raise ValueError("request target must not contain URL userinfo")
        if parts.query or parts.fragment:
            raise ValueError("request target base must not contain query or fragment")
        prefix = _decoded_safe_path(parts.path)
        if prefix != "/":
            prefix = prefix.rstrip("/")
        return cls(
            scheme=scheme,
            hostname=_canonical_hostname(parts.hostname),
            port=_effective_port(scheme, parts.port),
            path_prefix=prefix,
            credential_query_names=credential_query_names,
        )

    def validate(self, candidate: str) -> str:
        try:
            parts = urlsplit(candidate)
            scheme = parts.scheme.lower()
            hostname = _canonical_hostname(parts.hostname)
            port = _effective_port(scheme, parts.port)
        except ValueError as exc:
            raise ApiError(
                f"request target rejected: {exc}",
                attempts=0,
                failure_class="request_rejected",
            ) from exc
        if scheme not in {"http", "https"}:
            raise ApiError(
                "request target rejected: unsupported scheme",
                attempts=0,
                failure_class="request_rejected",
            )
        if parts.username is not None or parts.password is not None:
            raise ApiError(
                "request target rejected: URL userinfo is forbidden",
                attempts=0,
                failure_class="request_rejected",
            )
        if parts.fragment:
            raise ApiError(
                "request target rejected: fragments are forbidden",
                attempts=0,
                failure_class="request_rejected",
            )
        if (scheme, hostname, port) != (self.scheme, self.hostname, self.port):
            raise ApiError(
                "request target rejected: target is outside the configured API origin",
                attempts=0,
                failure_class="request_rejected",
            )
        try:
            path = _decoded_safe_path(parts.path)
        except ValueError as exc:
            raise ApiError(
                f"request target rejected: {exc}",
                attempts=0,
                failure_class="request_rejected",
            ) from exc
        if self.path_prefix != "/" and not (
            path == self.path_prefix or path.startswith(f"{self.path_prefix}/")
        ):
            raise ApiError(
                "request target rejected: target escaped the configured API path",
                attempts=0,
                failure_class="request_rejected",
            )
        if has_auth_material(
            candidate,
            additional_query_names=self.credential_query_names,
        ):
            raise ApiError(
                "request target rejected: target supplied authentication material",
                attempts=0,
                failure_class="request_rejected",
            )
        return candidate

    def identity(self, candidate: str) -> str:
        validated = self.validate(candidate)
        parts = urlsplit(validated)
        query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
        authority = _authority_text(self.scheme, self.hostname, self.port)
        return urlunsplit(
            (
                self.scheme,
                authority,
                _decoded_safe_path(parts.path),
                query,
                "",
            )
        )

TRANSPORT_METRIC_KEYS = (
    "request_count",
    "page_count",
    "retry_count",
    "budget_exhausted",
    "cache_hits",
    "cache_misses",
    "cache_enabled",
    "insecure_transport",
)


def empty_transport_metrics(*, cache_enabled: bool = False) -> dict[str, Any]:
    return {
        "request_count": 0,
        "page_count": 0,
        "retry_count": 0,
        "budget_exhausted": False,
        "cache_hits": 0,
        "cache_misses": 0,
        "cache_enabled": cache_enabled,
        "insecure_transport": False,
    }


def _is_success_status(status_code: Any) -> bool:
    return (
        isinstance(status_code, int)
        and not isinstance(status_code, bool)
        and 200 <= status_code < 300
    )


def is_success_status(status_code: Any) -> bool:
    """Return true only for a non-boolean HTTP 2xx status."""
    return _is_success_status(status_code)


def _status_failure_class(status_code: Any) -> str:
    if isinstance(status_code, int) and not isinstance(status_code, bool):
        return failure_class_for_status(status_code)
    return "http_error"


def _finite_cache_timestamp(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        timestamp = float(value)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(timestamp) or timestamp < 0:
        return None
    return timestamp


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is not allowed: {value}")


def parse_link_header(value: Any) -> tuple[tuple[str, str], ...] | None:
    """Parse the conservative Link syntax accepted by cache and pagination."""
    if not isinstance(value, str):
        return None
    if not value.strip():
        return ()
    entries: list[tuple[str, str]] = []
    position = 0
    while position < len(value):
        match = _LINK_ENTRY_PATTERN.match(value, position)
        if match is None:
            return None
        entries.append(
            (
                match.group("url"),
                match.group("rel").strip("\"'").strip(),
            )
        )
        position = match.end()
        if position >= len(value):
            break
        if value[position] != ",":
            return None
        position += 1
    return tuple(entries)


def next_link_url(value: Any) -> str | None:
    parsed = parse_link_header(value)
    if parsed is None:
        return None
    for url, relation in parsed:
        if "next" in relation.split():
            return url
    return None


@dataclass
class RequestMetrics:
    request_count: int = 0
    page_count: int = 0
    retry_count: int = 0
    budget_exhausted: bool = False
    cache_hits: int = 0
    cache_misses: int = 0
    cache_enabled: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_count": self.request_count,
            "page_count": self.page_count,
            "retry_count": self.retry_count,
            "budget_exhausted": self.budget_exhausted,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_enabled": self.cache_enabled,
        }


class RequestCoordinator:
    """Bound one provider/instance group without changing GET semantics."""

    def __init__(
        self,
        *,
        max_requests: int | None = 1000,
        cache_enabled: bool = False,
    ) -> None:
        if max_requests is None:
            raise ValueError("max_requests must be a finite integer")
        if isinstance(max_requests, bool) or not isinstance(max_requests, int):
            raise ValueError("max_requests must be an integer")
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        if max_requests > MAX_REQUESTS:
            raise ValueError(f"max_requests must be at most {MAX_REQUESTS}")
        self.max_requests = max_requests
        self.metrics = RequestMetrics(cache_enabled=cache_enabled)

    def reserve_request(self) -> None:
        if self.max_requests is not None and self.metrics.request_count >= self.max_requests:
            self.metrics.budget_exhausted = True
            raise ApiError(
                "request budget exhausted",
                attempts=1,
                retryable=False,
                failure_class="budget_exhausted",
            )
        self.metrics.request_count += 1

    def record_page(self) -> None:
        self.metrics.page_count += 1

    def record_retry(self) -> None:
        self.metrics.retry_count += 1

    def snapshot(self) -> dict[str, Any]:
        return self.metrics.as_dict()


class LocalResponseCache:
    """Small private JSON cache with conservative replay and header allowlisting."""

    def __init__(
        self,
        path: str | Path,
        *,
        ttl_seconds: float,
        max_entries: int,
        clock: Callable[[], float] = time.time,
        credential_query_names: tuple[str, ...] = (),
    ) -> None:
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(float(ttl_seconds))
        ):
            raise ValueError("cache ttl_seconds must be finite numeric")
        if ttl_seconds <= 0 or ttl_seconds > MAX_CACHE_TTL_SECONDS:
            raise ValueError(f"cache ttl_seconds must be in (0, {MAX_CACHE_TTL_SECONDS}]")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int):
            raise ValueError("cache max_entries must be an integer")
        if max_entries < 1 or max_entries > MAX_CACHE_ENTRIES:
            raise ValueError(f"cache max_entries must be in [1, {MAX_CACHE_ENTRIES}]")
        self.path = Path(path).expanduser()
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.clock = clock
        self.credential_query_names = tuple(credential_query_names)

    @staticmethod
    def _contains_sensitive_material(
        value: Any,
        token: str | None,
        credential_query_names: tuple[str, ...] = (),
    ) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                if is_sensitive_field(key):
                    return True
                if is_url_field(key):
                    if has_auth_material(
                        child,
                        additional_query_names=credential_query_names,
                    ) and not is_redacted_public_url(
                        child,
                        additional_query_names=credential_query_names,
                    ):
                        return True
                if LocalResponseCache._contains_sensitive_material(
                    child,
                    token,
                    credential_query_names,
                ):
                    return True
            return False
        if isinstance(value, (list, tuple)):
            return any(
                LocalResponseCache._contains_sensitive_material(
                    item,
                    token,
                    credential_query_names,
                )
                for item in value
            )
        if isinstance(value, str):
            if token and token in value:
                return True
            for candidate in _URL_CANDIDATE_PATTERN.findall(value):
                candidate = candidate.rstrip(".,);]")
                if has_auth_material(
                    candidate,
                    additional_query_names=credential_query_names,
                ) and not is_redacted_public_url(
                    candidate,
                    additional_query_names=credential_query_names,
                ):
                    return True
        return False

    def _read(self) -> dict[str, Any]:
        try:
            mode = stat.S_IMODE(self.path.stat().st_mode)
        except OSError:
            mode = None
        if mode is not None and (mode & 0o077 or self.path.is_symlink()):
            return {"entries": {}}
        try:
            raw = json.loads(
                read_bounded_bytes(self.path, max_bytes=MAX_CACHE_FILE_BYTES),
                parse_constant=_reject_json_constant,
            )
            validate_json_value_limits(raw)
        except (
            OSError,
            json.JSONDecodeError,
            RecursionError,
            ResponseShapeError,
            TypeError,
            ValueError,
        ):
            return {"entries": {}}
        if not isinstance(raw, dict) or not isinstance(raw.get("entries"), dict):
            return {"entries": {}}
        return {"entries": raw["entries"]}

    @staticmethod
    def _header_value_has_sensitive_material(
        value: str,
        token: str | None,
        credential_query_names: tuple[str, ...] = (),
    ) -> bool:
        if LocalResponseCache._contains_sensitive_material(
            value,
            token,
            credential_query_names,
        ):
            return True
        return has_auth_material(
            value,
            additional_query_names=credential_query_names,
        )

    @classmethod
    def _safe_headers(
        cls,
        headers: Mapping[str, Any] | None,
        *,
        token: str | None = None,
        credential_query_names: tuple[str, ...] = (),
    ) -> dict[str, str] | None:
        if not headers:
            return {}
        if not isinstance(headers, Mapping):
            return None
        safe: dict[str, str] = {}
        for key, value in headers.items():
            normalized = canonicalize_field_name(key)
            if normalized not in CACHE_HEADER_NAMES:
                continue
            if not isinstance(value, str) or cls._header_value_has_sensitive_material(
                value,
                token,
                credential_query_names,
            ):
                return None
            if normalized == "link":
                if parse_link_header(value) is None:
                    return None
                urls = re.findall(r"<([^>]+)>", value)
                if any(
                    has_auth_material(
                        url,
                        additional_query_names=credential_query_names,
                    )
                    and not is_redacted_public_url(
                        url,
                        additional_query_names=credential_query_names,
                    )
                    for url in urls
                ):
                    return None
            elif normalized in _NEXT_PAGE_HEADER_NAMES:
                if re.fullmatch(r"[1-9][0-9]*", value.strip()) is None:
                    return None
            elif normalized in _NUMERIC_RATE_HEADER_NAMES:
                if re.fullmatch(r"[0-9]+", value.strip()) is None:
                    return None
            elif normalized == "retry_after":
                try:
                    retry_after = float(value)
                except (TypeError, ValueError):
                    try:
                        parsedate_to_datetime(value)
                    except (TypeError, ValueError, OverflowError):
                        return None
                else:
                    if not math.isfinite(retry_after) or retry_after < 0:
                        return None
            safe[str(key).lower()] = value
        return safe

    def get(self, key: str, *, token: str | None = None) -> ApiResponse | None:
        payload = self._read()
        entry = payload["entries"].get(key)
        if not isinstance(entry, dict):
            return None
        try:
            stored_at = _finite_cache_timestamp(entry["stored_at"])
            response = entry["response"]
            url = response["url"]
            status_code = response["status_code"]
            headers = response["headers"]
            body = response["body"]
        except (KeyError, TypeError, ValueError):
            # A pre-header cache entry cannot prove pagination completeness.
            return None
        if stored_at is None:
            return None
        safe_headers = self._safe_headers(
            headers,
            token=token,
            credential_query_names=self.credential_query_names,
        )
        if safe_headers is None or not isinstance(headers, dict) or headers != safe_headers:
            return None
        now = _finite_cache_timestamp(self.clock())
        if now is None or now - stored_at >= self.ttl_seconds:
            return None
        if not isinstance(url, str) or not _is_success_status(status_code):
            return None
        if (
            has_auth_material(url, additional_query_names=self.credential_query_names)
            and not is_redacted_public_url(
                url,
                additional_query_names=self.credential_query_names,
            )
        ) or self._contains_sensitive_material(
            body,
            token,
            self.credential_query_names,
        ):
            return None
        try:
            validate_json_value_limits(body)
            json_size_with_limit(
                body,
                max_bytes=MAX_RESPONSE_BYTES,
                ensure_ascii=False,
                indent=None,
            )
        except (InputLimitError, ResponseShapeError, TypeError, ValueError):
            return None
        return ApiResponse(url, status_code, headers, body)

    def put(self, key: str, response: ApiResponse, *, token: str | None) -> None:
        stored_at = _finite_cache_timestamp(self.clock())
        if (
            stored_at is None
            or
            not _is_success_status(response.status_code)
            or (
                has_auth_material(
                    response.url,
                    additional_query_names=self.credential_query_names,
                )
                and not is_redacted_public_url(
                    response.url,
                    additional_query_names=self.credential_query_names,
                )
            )
            or self._contains_sensitive_material(
                response.body,
                token,
                self.credential_query_names,
            )
        ):
            return
        safe_headers = self._safe_headers(
            response.headers,
            token=token,
            credential_query_names=self.credential_query_names,
        )
        if safe_headers is None:
            return
        try:
            validate_json_value_limits(response.body)
            encoded_body = json.dumps(
                response.body,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (ResponseShapeError, TypeError, ValueError):
            return
        if len(encoded_body) > MAX_RESPONSE_BYTES:
            return
        payload = self._read()
        entries = payload["entries"]
        entries[key] = {
            "stored_at": stored_at,
            "response": {
                "url": response.url,
                "status_code": response.status_code,
                "headers": safe_headers,
                "body": response.body,
            },
        }
        now = _finite_cache_timestamp(self.clock())
        if now is None:
            return
        live_entries = {
            item_key: item
            for item_key, item in entries.items()
            if isinstance(item, dict)
            and _finite_cache_timestamp(item.get("stored_at")) is not None
            and now - _finite_cache_timestamp(item["stored_at"]) < self.ttl_seconds
        }
        ordered = sorted(
            live_entries.items(),
            key=lambda item: _finite_cache_timestamp(item[1]["stored_at"]) or 0.0,
            reverse=True,
        )[: self.max_entries]
        payload = {"version": 1, "entries": dict(ordered)}
        try:
            serialized_payload = json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
            )
        except (TypeError, ValueError):
            return
        if len(serialized_payload.encode("utf-8")) > MAX_CACHE_FILE_BYTES:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=f"{self.path.name}.", suffix=".tmp", dir=str(self.path.parent)
            )
            temporary = Path(temporary_name)
            try:
                os.fchmod(file_descriptor, 0o600)
                with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
                    handle.write(serialized_payload)
                os.replace(temporary, self.path)
                os.chmod(self.path, 0o600)
            except Exception:
                try:
                    os.close(file_descriptor)
                except OSError:
                    pass
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
                raise
        except (OSError, TypeError, ValueError):
            return


def transport_metrics(transport: Any) -> dict[str, Any]:
    getter = getattr(transport, "metrics", None)
    if not callable(getter):
        return empty_transport_metrics()
    try:
        value = getter()
    except Exception:
        return empty_transport_metrics()
    if not isinstance(value, dict):
        return empty_transport_metrics()
    result = empty_transport_metrics(cache_enabled=bool(value.get("cache_enabled", False)))
    for key in TRANSPORT_METRIC_KEYS:
        if key == "cache_enabled":
            continue
        if key in {"budget_exhausted", "insecure_transport"}:
            result[key] = bool(value.get(key, False))
        else:
            candidate = value.get(key, 0)
            result[key] = candidate if isinstance(candidate, int) and candidate >= 0 else 0
    return result


def rate_limit_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    if not headers:
        return {}
    try:
        items = headers.items()
    except AttributeError:
        return {}
    return {
        str(key).lower(): str(value)
        for key, value in items
        if str(key).lower() in RATE_LIMIT_HEADERS
    }


def _header_get(headers: Any, name: str) -> Any:
    if headers is None:
        return None
    try:
        value = headers.get(name)
        if value is not None:
            return value
        value = headers.get(name.lower())
        if value is not None:
            return value
    except AttributeError:
        return None
    try:
        for key, value in headers.items():
            if str(key).lower() == name.lower():
                return value
    except AttributeError:
        return None
    return None


class ApiError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        *,
        attempts: int = 1,
        retryable: bool = False,
        retry_after: float | None = None,
        failure_class: str | None = None,
        rate_limit: Mapping[str, str] | None = None,
        failure_classes: tuple[str, ...] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.attempts = attempts
        self.retryable = retryable
        self.retry_after = retry_after
        self.failure_class = failure_class
        self.rate_limit = dict(rate_limit or {})
        self.failure_classes = tuple(
            dict.fromkeys(
                value
                for value in ((failure_class,) + tuple(failure_classes or ()))
                if isinstance(value, str) and value
            )
        )

    def add_failure_class(self, failure_class: str | None) -> None:
        if not isinstance(failure_class, str) or not failure_class:
            return
        self.failure_classes = tuple(dict.fromkeys((*self.failure_classes, failure_class)))


class ResponseShapeError(ApiError):
    """The provider returned a successful response with an unexpected shape."""


def validate_json_value_limits(value: Any) -> None:
    """Reject JSON-compatible values that exceed structural or string limits."""
    try:
        _validate_json_value_limits(
            value,
            max_depth=MAX_JSON_DEPTH,
            max_string_chars=MAX_JSON_STRING_CHARS,
        )
    except InputLimitError as exc:
        raise ResponseShapeError(str(exc), failure_class="limit_exceeded") from exc


def _read_bounded_body(response: Any) -> bytes:
    headers = getattr(response, "headers", {})
    content_encoding = _header_get(headers, "content-encoding")
    if isinstance(content_encoding, str) and content_encoding.strip().lower() not in {
        "",
        "identity",
    }:
        raise ResponseShapeError(
            "compressed provider responses are not accepted",
            failure_class="limit_exceeded",
        )
    content_length = _header_get(headers, "content-length")
    if content_length not in (None, ""):
        try:
            declared_length = int(content_length)
        except (TypeError, ValueError) as exc:
            raise ResponseShapeError("provider returned an invalid Content-Length") from exc
        if declared_length < 0:
            raise ResponseShapeError("provider returned an invalid Content-Length")
        if declared_length > MAX_RESPONSE_BYTES:
            raise ResponseShapeError(
                f"provider response exceeds {MAX_RESPONSE_BYTES} bytes",
                failure_class="limit_exceeded",
            )
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if not isinstance(raw, bytes):
        raise ResponseShapeError("provider response body must be bytes")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ResponseShapeError(
            f"provider response exceeds {MAX_RESPONSE_BYTES} bytes",
            failure_class="limit_exceeded",
        )
    return raw


def _append_query_value(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


class _PolicyRedirectHandler(HTTPRedirectHandler):
    """Follow redirects only inside one validated API boundary."""

    def __init__(
        self,
        policy: AllowedApiTarget,
        initial_url: str,
        *,
        token_param: str | None = None,
        token: str | None = None,
    ) -> None:
        super().__init__()
        self.policy = policy
        self.visited = {self._identity_without_own_token(initial_url, token_param, token)}
        self.token_param = token_param
        self.token = token

    @staticmethod
    def _without_own_token(url: str, token_param: str | None, token: str | None) -> str:
        if not token_param or token is None:
            return url
        parts = urlsplit(url)
        query = [
            (key, value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
            if not (key == token_param and value == token)
        ]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))

    def _identity_without_own_token(
        self,
        url: str,
        token_param: str | None,
        token: str | None,
    ) -> str:
        return self.policy.identity(self._without_own_token(url, token_param, token))

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> Request | None:
        del fp
        validated = self.policy.validate(newurl)
        identity = self.policy.identity(validated)
        if identity in self.visited:
            raise ApiError(
                "request target rejected: redirect cycle detected",
                attempts=1,
                failure_class="request_rejected",
            )
        self.visited.add(identity)
        if self.token_param and self.token is not None:
            validated = _append_query_value(validated, self.token_param, self.token)
        return super().redirect_request(req, None, code, msg, headers, validated)


def urlopen(
    request: Request,
    *,
    timeout: float,
    context: ssl.SSLContext,
    redirect_policy: AllowedApiTarget,
    token_param: str | None = None,
    token: str | None = None,
) -> Any:
    """Policy-bound opener kept as a seam for deterministic transport tests."""
    opener = build_opener(
        HTTPHandler(),
        HTTPSHandler(context=context),
        _PolicyRedirectHandler(
            redirect_policy,
            request.full_url,
            token_param=token_param,
            token=token,
        ),
    )
    return opener.open(request, timeout=timeout)


def failure_class_for_status(status_code: int) -> str:
    """Map transport status to a stable operational failure class."""
    if status_code in {401, 403}:
        return "permission_denied"
    if status_code == 404:
        return "not_found"
    if status_code == 429:
        return "rate_limited"
    if 500 <= status_code <= 599:
        return "service_error"
    if 400 <= status_code <= 499:
        return "request_rejected"
    return "http_error"


def _failure_class_for_error(error: ApiError) -> str:
    if error.failure_class:
        return error.failure_class
    if isinstance(error, ResponseShapeError):
        return "malformed_response"
    if error.status_code is not None:
        return failure_class_for_status(error.status_code)
    return "transport_error"


def _merge_api_errors(primary: ApiError, current: ApiError, *, attempts: int) -> None:
    """Keep the first remote cause while retaining later safe failure details."""
    primary.attempts = max(primary.attempts, current.attempts, attempts)
    primary.retryable = primary.retryable or current.retryable
    if primary.retry_after is None:
        primary.retry_after = current.retry_after
    primary.rate_limit.update(current.rate_limit)
    primary.add_failure_class(_failure_class_for_error(current))
    for failure_class in current.failure_classes:
        primary.add_failure_class(failure_class)


@dataclass(frozen=True)
class ApiResponse:
    url: str
    status_code: int
    headers: Mapping[str, str]
    body: Any


def _retry_after_from_headers(headers: Mapping[str, Any] | None) -> float | None:
    if not headers:
        return None
    value = _header_get(headers, "Retry-After")
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError, OverflowError):
        try:
            target = parsedate_to_datetime(str(value))
        except (TypeError, ValueError, OverflowError):
            return None
        return max(0.0, target.timestamp() - time.time())


def response_status_error(
    response: ApiResponse,
    *,
    redact_url: Callable[[str], str] | None = None,
    message: str | None = None,
) -> ApiError:
    """Create one safe, structured error for a non-success API response."""
    status_code = (
        response.status_code
        if isinstance(response.status_code, int) and not isinstance(response.status_code, bool)
        else None
    )
    safe_url = (
        redact_url(response.url)
        if callable(redact_url)
        else redact_public_url(response.url)
    )
    headers = response.headers if callable(getattr(response.headers, "get", None)) else {}
    if message is None:
        message = f"unexpected HTTP status from {safe_url}: {response.status_code}"
    retryable = status_code in {429, 500, 502, 503, 504}
    return ApiError(
        message,
        status_code,
        retryable=retryable,
        retry_after=_retry_after_from_headers(headers),
        failure_class=_status_failure_class(response.status_code),
        rate_limit=rate_limit_headers(headers),
    )


class JsonTransport(Protocol):
    def get(self, path: str, params: Mapping[str, Any] | None = None) -> ApiResponse:
        """GET a JSON resource."""


class UrllibTransport:
    """Small dependency-free JSON transport with explicit auth and TLS policy."""

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        *,
        token_header: str = "Authorization",
        token_prefix: str = "Bearer",
        token_param: str | None = None,
        verify_tls: bool = True,
        allow_insecure_loopback: bool = False,
        timeout: float = 30.0,
        max_retries: int = 2,
        retry_backoff: float = 0.5,
        sleep_fn: Callable[[float], None] = time.sleep,
        provider_kind: str = "",
        instance: str = "",
        max_requests: int | None = 1000,
        retry_jitter: float = 0.25,
        retry_after_max: float = 60.0,
        cache_enabled: bool = False,
        cache_path: str | None = None,
        cache_ttl_seconds: float = 300.0,
        cache_max_entries: int = 256,
        random_fn: Callable[[float, float], float] = random.uniform,
    ) -> None:
        base_url = validate_instance(base_url)
        if not isinstance(verify_tls, bool):
            raise TypeError("verify_tls must be boolean")
        if not isinstance(allow_insecure_loopback, bool):
            raise TypeError("allow_insecure_loopback must be boolean")
        if token_param is not None and (
            not isinstance(token_param, str) or not token_param.strip()
        ):
            raise ValueError("token_param must be a non-empty string")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or timeout < MIN_TIMEOUT_SECONDS
            or timeout > MAX_TIMEOUT_SECONDS
        ):
            raise ValueError(
                f"timeout must be finite and in [{MIN_TIMEOUT_SECONDS}, {MAX_TIMEOUT_SECONDS}]"
            )
        if isinstance(max_retries, bool) or not isinstance(max_retries, int):
            raise ValueError("max_retries must be an integer")
        if max_retries < 0 or max_retries > MAX_RETRIES:
            raise ValueError(f"max_retries must be in [0, {MAX_RETRIES}]")
        for name, value, maximum in (
            ("retry_backoff", retry_backoff, MAX_RETRY_BACKOFF_SECONDS),
            ("retry_jitter", retry_jitter, MAX_RETRY_JITTER_SECONDS),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or value < 0
                or value > maximum
            ):
                raise ValueError(f"{name} must be finite and in [0, {maximum}]")
        if (
            isinstance(retry_after_max, bool)
            or not isinstance(retry_after_max, (int, float))
            or not math.isfinite(float(retry_after_max))
            or retry_after_max < MIN_RETRY_AFTER_SECONDS
            or retry_after_max > MAX_RETRY_AFTER_SECONDS
        ):
            raise ValueError(
                f"retry_after_max must be finite and in [{MIN_RETRY_AFTER_SECONDS}, {MAX_RETRY_AFTER_SECONDS}]"
            )
        if (
            isinstance(cache_ttl_seconds, bool)
            or not isinstance(cache_ttl_seconds, (int, float))
            or not math.isfinite(float(cache_ttl_seconds))
            or cache_ttl_seconds <= 0
            or cache_ttl_seconds > MAX_CACHE_TTL_SECONDS
        ):
            raise ValueError(f"cache_ttl_seconds must be finite and in (0, {MAX_CACHE_TTL_SECONDS}]")
        if (
            isinstance(cache_max_entries, bool)
            or not isinstance(cache_max_entries, int)
            or cache_max_entries < 1
            or cache_max_entries > MAX_CACHE_ENTRIES
        ):
            raise ValueError(f"cache_max_entries must be in [1, {MAX_CACHE_ENTRIES}]")
        if cache_enabled and not cache_path:
            raise ValueError("cache_path is required when cache_enabled is true")
        credential_query_names = (token_param,) if token_param else ()
        target_policy = AllowedApiTarget.from_base_url(
            base_url,
            credential_query_names=credential_query_names,
        )
        if token and (target_policy.scheme != "https" or not verify_tls):
            raise ValueError("authenticated requests require HTTPS with TLS verification")
        insecure_transport = target_policy.scheme == "http" or not verify_tls
        if insecure_transport and not (
            allow_insecure_loopback and is_loopback_instance(base_url) and not token
        ):
            raise ValueError(
                "insecure transport requires explicit credentialless loopback development mode"
            )
        self.base_url = base_url.rstrip("/") + "/"
        self.token = token
        self.token_header = token_header
        self.token_prefix = token_prefix
        self.token_param = token_param
        self.verify_tls = verify_tls
        self.allow_insecure_loopback = allow_insecure_loopback
        self.insecure_transport = insecure_transport
        self._target_policy = target_policy
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self.retry_backoff = max(0.0, retry_backoff)
        self.retry_jitter = max(0.0, retry_jitter)
        self.retry_after_max = retry_after_max
        self.sleep_fn = sleep_fn
        self.provider_kind = provider_kind
        if instance:
            self.instance = validate_instance(instance)
        elif instance == "":
            self.instance = instance
        else:
            raise ValueError("instance must be a non-empty URL host or http(s) base")
        self.coordinator = RequestCoordinator(
            max_requests=max_requests,
            cache_enabled=cache_enabled,
        )
        self._cache = (
            LocalResponseCache(
                cache_path or "",
                ttl_seconds=cache_ttl_seconds,
                max_entries=cache_max_entries,
                credential_query_names=credential_query_names,
            )
            if cache_enabled
            else None
        )
        self.random_fn = random_fn

    def _url(self, path: str, params: Mapping[str, Any] | None) -> str:
        url = (
            path
            if path.startswith(("http://", "https://"))
            else urljoin(self.base_url, path.lstrip("/"))
        )
        parts = urlsplit(url)
        query: list[tuple[str, Any]] = list(parse_qsl(parts.query, keep_blank_values=True))
        if params:
            for key, value in params.items():
                if isinstance(value, (list, tuple)):
                    query.extend((key, item) for item in value)
                elif value is not None:
                    query.append((key, value))
        candidate = urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
        )
        self._target_policy.validate(candidate)
        if self.token and self.token_param:
            candidate = _append_query_value(candidate, self.token_param, self.token)
        return candidate

    def _redact_url(self, url: str) -> str:
        return redact_public_url(
            url,
            additional_query_names=(self.token_param,) if self.token_param else (),
        )

    def _redact_text(self, value: Any) -> str:
        text = str(value)
        if self.token:
            for token in (self.token, quote(self.token, safe="")):
                if token:
                    text = text.replace(token, "[REDACTED]")
        if self.token_param:
            text = re.sub(
                rf"([?&]{re.escape(self.token_param)}=)[^&#\s]+",
                r"\1[REDACTED]",
                text,
                flags=re.IGNORECASE,
            )
        return text

    def _cache_key(self, path: str, params: Mapping[str, Any] | None) -> str:
        scope_digest = hashlib.sha256((self.token or "anonymous").encode("utf-8")).hexdigest()
        identity = {
            "provider": self.provider_kind,
            "instance": self.instance,
            "path": path,
            "params": params or {},
            "token_scope_digest": scope_digest,
        }
        return hashlib.sha256(
            json.dumps(identity, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()

    def metrics(self) -> dict[str, Any]:
        metrics = self.coordinator.snapshot()
        metrics["insecure_transport"] = self.insecure_transport
        return metrics

    def record_page(self) -> None:
        self.coordinator.record_page()

    def _retry_delay(self, attempt: int, retry_after: float | None = None) -> float:
        base = retry_after if retry_after is not None else self.retry_backoff * (2 ** (attempt - 1))
        bounded = min(max(0.0, base), self.retry_after_max)
        if self.retry_jitter <= 0:
            return bounded
        jitter = max(0.0, self.random_fn(0.0, self.retry_jitter))
        return min(self.retry_after_max, bounded + jitter)

    @staticmethod
    def _retry_after(headers: Mapping[str, Any]) -> float | None:
        return _retry_after_from_headers(headers)

    @staticmethod
    def _decode_body(raw: bytes) -> Any:
        if not raw.strip():
            return None
        try:
            value = json.loads(raw.decode("utf-8"))
        except RecursionError as exc:
            raise ResponseShapeError(
                f"provider JSON nesting exceeds {MAX_JSON_DEPTH}",
                failure_class="limit_exceeded",
            ) from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ResponseShapeError("provider returned invalid JSON") from exc
        validate_json_value_limits(value)
        return value

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> ApiResponse:
        url = self._url(path, params)
        cache_key = self._cache_key(path, params) if self._cache is not None else None
        if self._cache is not None and cache_key is not None:
            cached = self._cache.get(cache_key, token=self.token)
            if cached is not None:
                self.coordinator.metrics.cache_hits += 1
                return cached
            self.coordinator.metrics.cache_misses += 1
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "git-evidence/0.1",
        }
        if self.token and not self.token_param:
            headers[self.token_header] = f"{self.token_prefix} {self.token}" if self.token_prefix else self.token
        request = Request(url, headers=headers, method="GET")
        context = ssl.create_default_context() if self.verify_tls else ssl._create_unverified_context()
        retryable_statuses = {429, 500, 502, 503, 504}
        primary_error: ApiError | None = None
        for attempt in range(1, self.max_retries + 2):
            try:
                self.coordinator.reserve_request()
                with urlopen(
                    request,
                    timeout=self.timeout,
                    context=context,
                    redirect_policy=self._target_policy,
                    token_param=self.token_param,
                    token=self.token,
                ) as response:
                    raw = _read_bounded_body(response)
                    response_headers = {key.lower(): value for key, value in response.headers.items()}
                    result = ApiResponse(
                        self._redact_url(url),
                        response.status,
                        response_headers,
                        self._decode_body(raw),
                    )
                    if self._cache is not None and cache_key is not None:
                        self._cache.put(cache_key, result, token=self.token)
                    return result
            except ApiError as exc:
                if primary_error is not None:
                    _merge_api_errors(primary_error, exc, attempts=attempt)
                    raise primary_error from exc
                raise
            except HTTPError as exc:
                raw = _read_bounded_body(exc)
                detail = raw.decode("utf-8", errors="replace")[:300]
                detail = self._redact_text(detail)
                can_retry = exc.code in retryable_statuses and attempt <= self.max_retries
                error = response_status_error(
                    ApiResponse(
                        self._redact_url(url),
                        exc.code,
                        exc.headers or {},
                        None,
                    ),
                    redact_url=self._redact_url,
                    message=f"GET {self._redact_url(url)} failed with HTTP {exc.code}: {detail}",
                )
                error.attempts = attempt
                error.retryable = exc.code in retryable_statuses
                if can_retry:
                    if primary_error is None:
                        primary_error = error
                    else:
                        _merge_api_errors(primary_error, error, attempts=attempt)
                    self.coordinator.record_retry()
                    self.sleep_fn(self._retry_delay(attempt, error.retry_after))
                    continue
                if primary_error is not None:
                    _merge_api_errors(primary_error, error, attempts=attempt)
                    raise primary_error from exc
                raise error from exc
            except URLError as exc:
                can_retry = attempt <= self.max_retries
                error = ApiError(
                    f"GET {self._redact_url(url)} failed: {self._redact_text(getattr(exc, 'reason', exc))}",
                    attempts=attempt,
                    retryable=True,
                    failure_class="network_error",
                )
                if can_retry:
                    if primary_error is None:
                        primary_error = error
                    else:
                        _merge_api_errors(primary_error, error, attempts=attempt)
                    self.coordinator.record_retry()
                    self.sleep_fn(self._retry_delay(attempt))
                    continue
                if primary_error is not None:
                    _merge_api_errors(primary_error, error, attempts=attempt)
                    raise primary_error from exc
                raise error from exc
            except (TimeoutError, OSError) as exc:
                can_retry = attempt <= self.max_retries
                error = ApiError(
                    f"GET {self._redact_url(url)} failed: {self._redact_text(exc)}",
                    attempts=attempt,
                    retryable=True,
                    failure_class="network_error",
                )
                if can_retry:
                    if primary_error is None:
                        primary_error = error
                    else:
                        _merge_api_errors(primary_error, error, attempts=attempt)
                    self.coordinator.record_retry()
                    self.sleep_fn(self._retry_delay(attempt))
                    continue
                if primary_error is not None:
                    _merge_api_errors(primary_error, error, attempts=attempt)
                    raise primary_error from exc
                raise error from exc


@dataclass
class PageResult:
    items: list[dict[str, Any]]
    pages: int
    complete: bool
    diagnostics: dict[str, Any] | None = None


def _pagination_request_identity(
    path: str,
    params: Mapping[str, Any] | None,
) -> str:
    parts = urlsplit(path)
    query = list(parse_qsl(parts.query, keep_blank_values=True))
    for key, value in (params or {}).items():
        if isinstance(value, (list, tuple)):
            query.extend((str(key), str(item)) for item in value)
        elif value is not None:
            query.append((str(key), str(value)))
    encoded_query = urlencode(sorted(query))
    if parts.scheme and parts.netloc:
        scheme = parts.scheme.lower()
        hostname = _canonical_hostname(parts.hostname)
        port = _effective_port(scheme, parts.port)
        authority = _authority_text(scheme, hostname, port)
        return urlunsplit((scheme, authority, _decoded_safe_path(parts.path), encoded_query, ""))
    return f"relative:{parts.path}?{encoded_query}"


def _pagination_page_number(
    path: str,
    params: Mapping[str, Any] | None,
) -> int | None:
    values: list[Any] = []
    if params and "page" in params:
        values.append(params["page"])
    values.extend(value for key, value in parse_qsl(urlsplit(path).query) if key == "page")
    for value in reversed(values):
        try:
            page = int(value)
        except (TypeError, ValueError):
            continue
        return page
    return None


def paginate(
    transport: JsonTransport,
    path: str,
    params: Mapping[str, Any] | None = None,
    *,
    per_page: int = 100,
    max_pages: int = 100,
) -> PageResult:
    """Follow Link, x-next-page, or page-size pagination without silent truncation."""
    if isinstance(per_page, bool) or not isinstance(per_page, int) or per_page < 1:
        raise ValueError("per_page must be a positive integer")
    if per_page > MAX_PAGE_ITEMS:
        raise ValueError(f"per_page must be at most {MAX_PAGE_ITEMS}")
    if isinstance(max_pages, bool) or not isinstance(max_pages, int):
        raise ValueError("max_pages must be an integer")
    if max_pages < 1 or max_pages > MAX_PAGES:
        raise ValueError(f"max_pages must be in [1, {MAX_PAGES}]")
    base_params = dict(params or {})
    base_params.setdefault("per_page", per_page)
    current_path = path
    current_params: Mapping[str, Any] | None = {**base_params, "page": 1}
    items: list[dict[str, Any]] = []
    item_bytes = 0
    diagnostics: dict[str, Any] = {}
    visited_requests: set[str] = set()
    visited_responses: set[str] = set()
    for page_number in range(1, max_pages + 1):
        request_identity = _pagination_request_identity(current_path, current_params)
        if request_identity in visited_requests:
            raise ResponseShapeError(
                "provider pagination repeated a request target",
                failure_class="malformed_response",
            )
        visited_requests.add(request_identity)
        response = transport.get(current_path, current_params)
        record_page = getattr(transport, "record_page", None)
        if callable(record_page):
            record_page()
        if not _is_success_status(response.status_code):
            redact_url = getattr(transport, "_redact_url", None)
            raise response_status_error(
                response,
                redact_url=redact_url if callable(redact_url) else None,
            )
        rate_limit = rate_limit_headers(response.headers)
        if rate_limit:
            diagnostics["rate_limit"] = rate_limit
        if not isinstance(response.body, list):
            raise ResponseShapeError(f"expected a JSON array from {response.url}")
        if len(response.body) > MAX_PAGE_ITEMS:
            raise ResponseShapeError(
                f"provider page exceeds {MAX_PAGE_ITEMS} items",
                failure_class="limit_exceeded",
            )
        if isinstance(response.url, str) and response.url:
            response_identity = _pagination_request_identity(response.url, None)
            if response_identity in visited_responses:
                raise ResponseShapeError(
                    f"provider pagination repeated a response target from {response.url}",
                    failure_class="malformed_response",
                )
            visited_responses.add(response_identity)
        page_items = [item for item in response.body if isinstance(item, dict)]
        if len(page_items) != len(response.body):
            raise ResponseShapeError(f"provider returned a non-object item from {response.url}")
        try:
            page_item_bytes = json_size_with_limit(
                page_items,
                max_bytes=MAX_PAGINATED_BYTES,
                ensure_ascii=False,
                indent=None,
            )
        except (InputLimitError, TypeError, ValueError) as exc:
            raise ResponseShapeError(
                f"paginated source exceeds {MAX_PAGINATED_BYTES} bytes",
                failure_class="limit_exceeded",
            ) from exc
        item_bytes += page_item_bytes
        if item_bytes > MAX_PAGINATED_BYTES:
            raise ResponseShapeError(
                f"paginated source exceeds {MAX_PAGINATED_BYTES} bytes",
                failure_class="limit_exceeded",
            )
        items.extend(page_items)
        if len(items) > MAX_PAGINATED_ITEMS:
            raise ResponseShapeError(
                f"paginated source exceeds {MAX_PAGINATED_ITEMS} items",
                failure_class="limit_exceeded",
            )

        headers = response.headers if callable(getattr(response.headers, "get", None)) else {}
        link_header = _header_get(headers, "link") or ""
        parsed_links = parse_link_header(link_header) if link_header else ()
        if parsed_links is None:
            raise ResponseShapeError(f"invalid Link header from {response.url}")
        next_url = next_link_url(link_header)
        next_page = _header_get(headers, "x-next-page") or _header_get(
            headers,
            "x-next-page-number",
        )
        if next_url:
            next_identity = _pagination_request_identity(next_url, None)
            current_page = _pagination_page_number(current_path, current_params) or page_number
            next_page_from_url = _pagination_page_number(next_url, None)
            if next_identity in visited_requests or next_identity in visited_responses:
                raise ResponseShapeError(
                    f"provider pagination cycle detected from {response.url}",
                    failure_class="malformed_response",
                )
            if next_page_from_url is not None and next_page_from_url <= current_page:
                raise ResponseShapeError(
                    f"provider pagination page regressed from {response.url}",
                    failure_class="malformed_response",
                )
            current_path = next_url
            current_params = None
            continue
        if next_page:
            try:
                next_page_number = int(next_page)
            except ValueError as exc:
                raise ResponseShapeError(f"invalid x-next-page header from {response.url}") from exc
            if next_page_number <= 0:
                return PageResult(items, page_number, True, diagnostics or None)
            current_page = _pagination_page_number(current_path, current_params) or page_number
            if next_page_number <= current_page:
                raise ResponseShapeError(
                    f"provider pagination page regressed from {response.url}",
                    failure_class="malformed_response",
                )
            current_path = path
            current_params = {**base_params, "page": next_page_number}
            continue
        if len(page_items) < per_page:
            return PageResult(items, page_number, True, diagnostics or None)
        current_path = path
        current_params = {**base_params, "page": page_number + 1}
    diagnostics["budget_exhausted"] = True
    return PageResult(items, max_pages, False, diagnostics or None)


class MappingTransport:
    """Recorded response transport for provider contract tests."""

    def __init__(self, responses: Mapping[str, list[ApiResponse] | ApiResponse]) -> None:
        self.responses = {
            key: list(value) if isinstance(value, list) else [value]
            for key, value in responses.items()
        }
        self.calls: list[tuple[str, Mapping[str, Any] | None]] = []
        self._metrics = RequestMetrics()

    def metrics(self) -> dict[str, Any]:
        return self._metrics.as_dict()

    def record_page(self) -> None:
        self._metrics.page_count += 1

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> ApiResponse:
        self.calls.append((path, params))
        self._metrics.request_count += 1
        queue = self.responses.get(path)
        if not queue:
            raise ApiError(f"no recorded response for {path}", failure_class="fixture_missing")
        if len(queue) > 1:
            return queue.pop(0)
        return queue[0]
