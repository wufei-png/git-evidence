from __future__ import annotations

import json
import hashlib
import math
import os
from pathlib import Path
import random
import re
import ssl
import stat
import tempfile
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urljoin
from urllib.request import Request, urlopen

from ..limits import (
    MAX_CACHE_ENTRIES,
    MAX_CACHE_TTL_SECONDS,
    MAX_PAGES,
    MAX_REQUESTS,
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
_LINK_HEADER_PATTERN = re.compile(
    r"\s*<[^<>]+>\s*;\s*rel\s*=\s*(?:\"[^\"]+\"|'[^']+'|[^,\s]+)"
    r"(?:\s*;\s*[^,]+)*(?:\s*,\s*<[^<>]+>\s*;\s*rel\s*=\s*"
    r"(?:\"[^\"]+\"|'[^']+'|[^,\s]+)(?:\s*;\s*[^,]+)*)*\s*"
)

TRANSPORT_METRIC_KEYS = (
    "request_count",
    "page_count",
    "retry_count",
    "budget_exhausted",
    "cache_hits",
    "cache_misses",
    "cache_enabled",
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
    }


def _is_success_status(status_code: Any) -> bool:
    return (
        isinstance(status_code, int)
        and not isinstance(status_code, bool)
        and 200 <= status_code < 300
    )


def _status_failure_class(status_code: Any) -> str:
    if isinstance(status_code, int) and not isinstance(status_code, bool):
        return failure_class_for_status(status_code)
    return "http_error"


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

    @staticmethod
    def _contains_sensitive_material(value: Any, token: str | None) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                if is_sensitive_field(key):
                    return True
                if is_url_field(key):
                    if has_auth_material(child) and not is_redacted_public_url(child):
                        return True
                if LocalResponseCache._contains_sensitive_material(child, token):
                    return True
            return False
        if isinstance(value, (list, tuple)):
            return any(LocalResponseCache._contains_sensitive_material(item, token) for item in value)
        if token and isinstance(value, str) and token in value:
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
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            return {"entries": {}}
        if not isinstance(raw, dict) or not isinstance(raw.get("entries"), dict):
            return {"entries": {}}
        return {"entries": raw["entries"]}

    @staticmethod
    def _header_value_has_sensitive_material(value: str, token: str | None) -> bool:
        if LocalResponseCache._contains_sensitive_material(value, token):
            return True
        return has_auth_material(value)

    @classmethod
    def _safe_headers(
        cls,
        headers: Mapping[str, Any] | None,
        *,
        token: str | None = None,
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
            if not isinstance(value, str) or cls._header_value_has_sensitive_material(value, token):
                return None
            if normalized == "link":
                if _LINK_HEADER_PATTERN.fullmatch(value) is None:
                    return None
                urls = re.findall(r"<([^>]+)>", value)
                if any(has_auth_material(url) and not is_redacted_public_url(url) for url in urls):
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
            stored_at = float(entry["stored_at"])
            response = entry["response"]
            url = response["url"]
            status_code = response["status_code"]
            headers = response["headers"]
            body = response["body"]
        except (KeyError, TypeError, ValueError):
            # A pre-header cache entry cannot prove pagination completeness.
            return None
        safe_headers = self._safe_headers(headers, token=token)
        if safe_headers is None or not isinstance(headers, dict) or headers != safe_headers:
            return None
        if self.clock() - stored_at >= self.ttl_seconds:
            return None
        if not isinstance(url, str) or not _is_success_status(status_code):
            return None
        if (has_auth_material(url) and not is_redacted_public_url(url)) or self._contains_sensitive_material(body, token):
            return None
        return ApiResponse(url, status_code, headers, body)

    def put(self, key: str, response: ApiResponse, *, token: str | None) -> None:
        if (
            not _is_success_status(response.status_code)
            or (has_auth_material(response.url) and not is_redacted_public_url(response.url))
            or self._contains_sensitive_material(response.body, token)
        ):
            return
        safe_headers = self._safe_headers(response.headers, token=token)
        if safe_headers is None:
            return
        try:
            json.dumps(response.body, ensure_ascii=True)
        except (TypeError, ValueError):
            return
        payload = self._read()
        entries = payload["entries"]
        entries[key] = {
            "stored_at": self.clock(),
            "response": {
                "url": response.url,
                "status_code": response.status_code,
                "headers": safe_headers,
                "body": response.body,
            },
        }
        now = self.clock()
        live_entries = {
            item_key: item
            for item_key, item in entries.items()
            if isinstance(item, dict)
            and isinstance(item.get("stored_at"), (int, float))
            and now - float(item["stored_at"]) < self.ttl_seconds
        }
        ordered = sorted(
            live_entries.items(),
            key=lambda item: float(item[1]["stored_at"]),
            reverse=True,
        )[: self.max_entries]
        payload = {"version": 1, "entries": dict(ordered)}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=f"{self.path.name}.", suffix=".tmp", dir=str(self.path.parent)
            )
            temporary = Path(temporary_name)
            try:
                os.fchmod(file_descriptor, 0o600)
                with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(payload, ensure_ascii=True))
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
        if key == "budget_exhausted":
            result[key] = bool(value.get(key, False))
        else:
            candidate = value.get(key, 0)
            result[key] = candidate if isinstance(candidate, int) and candidate >= 0 else 0
    return result


def rate_limit_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {
        str(key).lower(): str(value)
        for key, value in headers.items()
        if str(key).lower() in RATE_LIMIT_HEADERS
    }


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
        self.base_url = base_url.rstrip("/") + "/"
        self.token = token
        self.token_header = token_header
        self.token_prefix = token_prefix
        self.token_param = token_param
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self.retry_backoff = max(0.0, retry_backoff)
        self.retry_jitter = max(0.0, retry_jitter)
        self.retry_after_max = retry_after_max
        self.sleep_fn = sleep_fn
        self.provider_kind = provider_kind
        self.instance = instance
        self.coordinator = RequestCoordinator(
            max_requests=max_requests,
            cache_enabled=cache_enabled,
        )
        self._cache = (
            LocalResponseCache(
                cache_path or "",
                ttl_seconds=cache_ttl_seconds,
                max_entries=cache_max_entries,
            )
            if cache_enabled
            else None
        )
        self.random_fn = random_fn

    def _url(self, path: str, params: Mapping[str, Any] | None) -> str:
        url = path if path.startswith(("http://", "https://")) else urljoin(self.base_url, path.lstrip("/"))
        query: list[tuple[str, Any]] = []
        if params:
            for key, value in params.items():
                if isinstance(value, (list, tuple)):
                    query.extend((key, item) for item in value)
                elif value is not None:
                    query.append((key, value))
        if self.token and self.token_param:
            query.append((self.token_param, self.token))
        if not query:
            return url
        separator = "&" if "?" in url else "?"
        return url + separator + urlencode(query)

    def _redact_url(self, url: str) -> str:
        return redact_public_url(url)

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
        return self.coordinator.snapshot()

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
        value = headers.get("Retry-After") or headers.get("retry-after")
        if value is None:
            return None
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            try:
                target = parsedate_to_datetime(str(value))
            except (TypeError, ValueError, OverflowError):
                return None
            return max(0.0, target.timestamp() - time.time())

    @staticmethod
    def _decode_body(raw: bytes) -> Any:
        if not raw.strip():
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ResponseShapeError("provider returned invalid JSON") from exc

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
                with urlopen(request, timeout=self.timeout, context=context) as response:
                    raw = response.read()
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
                raw = exc.read()
                detail = raw.decode("utf-8", errors="replace")[:300]
                detail = self._redact_text(detail)
                retry_after = self._retry_after(exc.headers or {})
                can_retry = exc.code in retryable_statuses and attempt <= self.max_retries
                error = ApiError(
                    f"GET {self._redact_url(url)} failed with HTTP {exc.code}: {detail}",
                    exc.code,
                    attempts=attempt,
                    retryable=exc.code in retryable_statuses,
                    retry_after=retry_after,
                    failure_class=failure_class_for_status(exc.code),
                    rate_limit=rate_limit_headers(exc.headers),
                )
                if can_retry:
                    if primary_error is None:
                        primary_error = error
                    else:
                        _merge_api_errors(primary_error, error, attempts=attempt)
                    self.coordinator.record_retry()
                    self.sleep_fn(self._retry_delay(attempt, retry_after))
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


_NEXT_LINK = re.compile(r"<([^>]+)>;\s*rel=\"next\"")


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
    if isinstance(max_pages, bool) or not isinstance(max_pages, int):
        raise ValueError("max_pages must be an integer")
    if max_pages < 1 or max_pages > MAX_PAGES:
        raise ValueError(f"max_pages must be in [1, {MAX_PAGES}]")
    base_params = dict(params or {})
    base_params.setdefault("per_page", per_page)
    page = 1
    current_path = path
    current_params: Mapping[str, Any] | None = {**base_params, "page": page}
    items: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {}
    for page_number in range(1, max_pages + 1):
        response = transport.get(current_path, current_params)
        record_page = getattr(transport, "record_page", None)
        if callable(record_page):
            record_page()
        if not _is_success_status(response.status_code):
            status_code = (
                response.status_code
                if isinstance(response.status_code, int) and not isinstance(response.status_code, bool)
                else None
            )
            raise ApiError(
                f"unexpected HTTP status from {response.url}: {response.status_code}",
                status_code,
                failure_class=_status_failure_class(response.status_code),
            )
        rate_limit = rate_limit_headers(response.headers)
        if rate_limit:
            diagnostics["rate_limit"] = rate_limit
        if not isinstance(response.body, list):
            raise ResponseShapeError(f"expected a JSON array from {response.url}")
        page_items = [item for item in response.body if isinstance(item, dict)]
        if len(page_items) != len(response.body):
            raise ResponseShapeError(f"provider returned a non-object item from {response.url}")
        items.extend(page_items)

        next_url = _NEXT_LINK.search(response.headers.get("link", ""))
        next_page = response.headers.get("x-next-page") or response.headers.get("x-next-page-number")
        if next_url:
            current_path = next_url.group(1)
            current_params = None
            continue
        if next_page:
            try:
                next_page_number = int(next_page)
            except ValueError as exc:
                raise ResponseShapeError(f"invalid x-next-page header from {response.url}") from exc
            if next_page_number <= 0:
                return PageResult(items, page_number, True, diagnostics or None)
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
