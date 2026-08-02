from __future__ import annotations

from collections.abc import Iterator
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


class PrivacyError(ValueError):
    """A payload contains material that must not cross the public boundary."""


SENSITIVE_FIELD_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "cookie",
        "credential",
        "credentials",
        "header",
        "headers",
        "id_token",
        "password",
        "passwd",
        "private_token",
        "proxy_authorization",
        "refresh_token",
        "secret",
        "set_cookie",
        "signature",
        "token",
    }
)

AUTH_QUERY_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "credential",
        "credentials",
        "id_token",
        "key",
        "oauth_token",
        "password",
        "passwd",
        "private_token",
        "secret",
        "signature",
        "sig",
        "token",
    }
)


def _normalized_key(value: Any) -> str:
    """Canonicalize snake/kebab/camel/header spellings to one key form."""
    text = str(value).strip()
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    return text.strip("_").lower()


def canonicalize_field_name(value: Any) -> str:
    """Public shared key canonicalization for config, bundles, and cache data."""
    return _normalized_key(value)


def _is_auth_suffix(normalized: str) -> bool:
    return normalized.endswith(
        (
            "_token",
            "_secret",
            "_password",
            "_credential",
            "_credentials",
            "_api_key",
            "_authorization",
            "_auth_header",
        )
    )


def is_sensitive_field(name: Any) -> bool:
    normalized = _normalized_key(name)
    if normalized == "auth_redaction":
        return False
    return (
        normalized in SENSITIVE_FIELD_NAMES
        or _is_auth_suffix(normalized)
        or normalized in {"auth", "auth_header", "authentication_header", "authorization_header"}
        or (
            normalized.startswith("auth_")
            and normalized.removeprefix("auth_")
            in {"header", "headers", "token", "key", "secret", "password", "credential", "credentials", "authorization"}
        )
        or (
            normalized.startswith("x_")
            and normalized.removeprefix("x_")
            in {"api_key", "auth", "auth_token", "token", "secret", "password", "authorization"}
        )
    )


def is_auth_query_name(name: Any) -> bool:
    normalized = _normalized_key(name)
    return (
        normalized in AUTH_QUERY_NAMES
        or _is_auth_suffix(normalized)
        or is_sensitive_field(normalized)
    )


def _fragment_contains_auth(fragment: str) -> bool:
    if not fragment:
        return False
    return any(is_auth_query_name(key) for key, _ in parse_qsl(fragment, keep_blank_values=True))


def has_auth_material(url: Any) -> bool:
    """Return whether a URL contains userinfo or an auth-bearing query/fragment."""
    if not isinstance(url, str) or not url:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.username is not None or parts.password is not None:
        return True
    if any(is_auth_query_name(key) for key, _ in parse_qsl(parts.query, keep_blank_values=True)):
        return True
    return _fragment_contains_auth(parts.fragment)


def is_redacted_public_url(url: Any) -> bool:
    """Return true only for URLs whose auth query values are explicit redactions."""
    if not isinstance(url, str) or not url:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.username is not None or parts.password is not None:
        return False
    auth_values = [
        value
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if is_auth_query_name(key)
    ]
    auth_fragment_values = [
        value
        for key, value in parse_qsl(parts.fragment, keep_blank_values=True)
        if is_auth_query_name(key)
    ]
    return bool(auth_values or auth_fragment_values) and all(
        value == "[REDACTED]" for value in (*auth_values, *auth_fragment_values)
    )


def redact_public_url(value: Any) -> Any:
    """Redact auth query values while retaining a safe diagnostic URL shape."""
    if not isinstance(value, str) or not value:
        return value
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme or not parts.netloc:
        return value
    netloc = parts.netloc.rsplit("@", 1)[-1]
    query = [
        (key, "[REDACTED]" if is_auth_query_name(key) else item)
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
    ]
    fragment = parts.fragment
    if fragment:
        fragment_pairs = parse_qsl(fragment, keep_blank_values=True)
        if fragment_pairs:
            fragment = urlencode(
                [
                    (key, "[REDACTED]" if is_auth_query_name(key) else item)
                    for key, item in fragment_pairs
                ]
            )
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), fragment))


def sanitize_public_url(value: Any) -> Any:
    """Preserve evidence URLs while removing userinfo and auth query material."""
    if not isinstance(value, str) or not value:
        return value
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme or not parts.netloc:
        return value
    # A source URL is useful evidence even when a provider accidentally adds
    # credentials. Keep the host/path and remove userinfo entirely.
    netloc = parts.netloc.rsplit("@", 1)[-1]
    query = [
        (key, item)
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
        if not is_auth_query_name(key)
    ]
    fragment = "" if _fragment_contains_auth(parts.fragment) else parts.fragment
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), fragment))


def is_url_field(name: Any) -> bool:
    normalized = _normalized_key(name)
    return normalized in {"url", "href", "source_url"} or normalized.endswith("_url")


def iter_privacy_violations(value: Any, *, path: str = "$") -> Iterator[tuple[str, str]]:
    """Find sensitive field names and auth-bearing URLs without exposing values."""
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if is_sensitive_field(key):
                yield child_path, "sensitive_field"
            if is_url_field(key) and has_auth_material(child):
                yield child_path, "auth_url"
            yield from iter_privacy_violations(child, path=child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_privacy_violations(child, path=f"{path}[{index}]")


def sanitize_public_payload(value: Any, *, path: str = "$") -> Any:
    """Copy a canonical payload, sanitize URLs, and reject credential fields."""
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if is_sensitive_field(key):
                raise PrivacyError(f"public payload contains a sensitive field at {child_path}")
            result[key] = (
                sanitize_public_url(child)
                if is_url_field(key)
                else sanitize_public_payload(child, path=child_path)
            )
        return result
    if isinstance(value, list):
        return [sanitize_public_payload(child, path=f"{path}[{index}]") for index, child in enumerate(value)]
    if isinstance(value, tuple):
        return tuple(
            sanitize_public_payload(child, path=f"{path}[{index}]") for index, child in enumerate(value)
        )
    return value
