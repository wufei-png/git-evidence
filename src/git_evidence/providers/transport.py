from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import random
import re
import ssl
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen


RATE_LIMIT_HEADERS = (
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
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
        if max_requests is not None and max_requests < 1:
            raise ValueError("max_requests must be at least 1")
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
    """Small JSON cache that stores only redacted URLs, status, and JSON bodies."""

    def __init__(
        self,
        path: str | Path,
        *,
        ttl_seconds: float,
        max_entries: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("cache ttl_seconds must be greater than zero")
        if max_entries < 1:
            raise ValueError("cache max_entries must be at least 1")
        self.path = Path(path).expanduser()
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.clock = clock

    @staticmethod
    def _contains_sensitive_material(value: Any, token: str | None) -> bool:
        sensitive_names = {
            "authorization",
            "proxy-authorization",
            "access_token",
            "refresh_token",
            "id_token",
            "cookie",
            "set-cookie",
            "headers",
        }
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key).lower().replace("-", "_")
                if normalized in sensitive_names or normalized.endswith("_token") or normalized == "token":
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
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            return {"entries": {}}
        if not isinstance(raw, dict) or not isinstance(raw.get("entries"), dict):
            return {"entries": {}}
        return {"entries": raw["entries"]}

    def get(self, key: str) -> ApiResponse | None:
        payload = self._read()
        entry = payload["entries"].get(key)
        if not isinstance(entry, dict):
            return None
        try:
            stored_at = float(entry["stored_at"])
            response = entry["response"]
            url = response["url"]
            status_code = response["status_code"]
            body = response["body"]
        except (KeyError, TypeError, ValueError):
            return None
        if self.clock() - stored_at >= self.ttl_seconds:
            return None
        if not isinstance(url, str) or not isinstance(status_code, int):
            return None
        return ApiResponse(url, status_code, {}, body)

    def put(self, key: str, response: ApiResponse, *, token: str | None) -> None:
        if self._contains_sensitive_material(response.body, token):
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
            temporary = self.path.with_name(self.path.name + ".tmp")
            temporary.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")
            os.replace(temporary, self.path)
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
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.attempts = attempts
        self.retryable = retryable
        self.retry_after = retry_after
        self.failure_class = failure_class
        self.rate_limit = dict(rate_limit or {})


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
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if max_retries < 0:
            raise ValueError("max_retries must not be negative")
        if retry_backoff < 0 or retry_jitter < 0:
            raise ValueError("retry delays must not be negative")
        if retry_after_max <= 0:
            raise ValueError("retry_after_max must be greater than zero")
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
        if not self.token_param:
            return url
        parts = urlsplit(url)
        query = [
            (key, "[REDACTED]" if key == self.token_param else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

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
            cached = self._cache.get(cache_key)
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
            except HTTPError as exc:
                raw = exc.read()
                detail = raw.decode("utf-8", errors="replace")[:300]
                detail = self._redact_text(detail)
                retry_after = self._retry_after(exc.headers or {})
                can_retry = exc.code in retryable_statuses and attempt <= self.max_retries
                if can_retry:
                    self.coordinator.record_retry()
                    self.sleep_fn(self._retry_delay(attempt, retry_after))
                    continue
                raise ApiError(
                    f"GET {self._redact_url(url)} failed with HTTP {exc.code}: {detail}",
                    exc.code,
                    attempts=attempt,
                    retryable=exc.code in retryable_statuses,
                    retry_after=retry_after,
                    failure_class=failure_class_for_status(exc.code),
                    rate_limit=rate_limit_headers(exc.headers),
                ) from exc
            except URLError as exc:
                can_retry = attempt <= self.max_retries
                if can_retry:
                    self.coordinator.record_retry()
                    self.sleep_fn(self._retry_delay(attempt))
                    continue
                raise ApiError(
                    f"GET {self._redact_url(url)} failed: {self._redact_text(getattr(exc, 'reason', exc))}",
                    attempts=attempt,
                    retryable=True,
                    failure_class="network_error",
                ) from exc
            except (TimeoutError, OSError) as exc:
                can_retry = attempt <= self.max_retries
                if can_retry:
                    self.coordinator.record_retry()
                    self.sleep_fn(self._retry_delay(attempt))
                    continue
                raise ApiError(
                    f"GET {self._redact_url(url)} failed: {self._redact_text(exc)}",
                    attempts=attempt,
                    retryable=True,
                    failure_class="network_error",
                ) from exc


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
