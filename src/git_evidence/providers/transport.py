from __future__ import annotations

import json
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
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.token = token
        self.token_header = token_header
        self.token_prefix = token_prefix
        self.token_param = token_param
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self.retry_backoff = max(0.0, retry_backoff)
        self.sleep_fn = sleep_fn

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
                with urlopen(request, timeout=self.timeout, context=context) as response:
                    raw = response.read()
                    response_headers = {key.lower(): value for key, value in response.headers.items()}
                    return ApiResponse(self._redact_url(url), response.status, response_headers, self._decode_body(raw))
            except HTTPError as exc:
                raw = exc.read()
                detail = raw.decode("utf-8", errors="replace")[:300]
                detail = self._redact_text(detail)
                retry_after = self._retry_after(exc.headers or {})
                can_retry = exc.code in retryable_statuses and attempt <= self.max_retries
                if can_retry:
                    delay = retry_after if retry_after is not None else self.retry_backoff * (2 ** (attempt - 1))
                    self.sleep_fn(min(delay, 60.0))
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
                    self.sleep_fn(min(self.retry_backoff * (2 ** (attempt - 1)), 60.0))
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
                    self.sleep_fn(min(self.retry_backoff * (2 ** (attempt - 1)), 60.0))
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
    return PageResult(items, max_pages, False, diagnostics or None)


class MappingTransport:
    """Recorded response transport for provider contract tests."""

    def __init__(self, responses: Mapping[str, list[ApiResponse] | ApiResponse]) -> None:
        self.responses = {
            key: list(value) if isinstance(value, list) else [value]
            for key, value in responses.items()
        }
        self.calls: list[tuple[str, Mapping[str, Any] | None]] = []

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> ApiResponse:
        self.calls.append((path, params))
        queue = self.responses.get(path)
        if not queue:
            raise ApiError(f"no recorded response for {path}", failure_class="fixture_missing")
        if len(queue) > 1:
            return queue.pop(0)
        return queue[0]
