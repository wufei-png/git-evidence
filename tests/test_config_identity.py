from __future__ import annotations

import tomllib
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

from git_evidence.config import (
    ConfigError,
    provider_runtime_options,
    validate_collection_config,
    validate_report_config,
)
from git_evidence.providers.base import (
    CollectionRequest,
    RepositoryTarget,
    instance_web_base,
    validate_instance,
    validate_timezone,
)
from git_evidence.providers.github import GitHubProvider
from git_evidence.providers.gitlab import GitLabProvider
from git_evidence.providers.transport import (
    ApiError,
    ResponseShapeError,
    UrllibTransport,
    _pagination_request_identity,
)


def base_config() -> dict[Any, Any]:
    return {
        "window": {
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-02T00:00:00Z",
            "timezone": "UTC",
        },
        "scope": {
            "repositories": [
                {
                    "provider": "github",
                    "instance": "github.com",
                    "owner": "example",
                    "name": "project",
                }
            ],
            "actors": [],
        },
        "providers": {"github": {}},
        "report": {"privacy": {}},
    }


ROOT = Path(__file__).resolve().parents[1]


class StrictConfigTests(unittest.TestCase):
    def test_unknown_keys_are_rejected_at_every_fixed_mapping_level(self) -> None:
        mutations = (
            ("configuration", lambda config: config.__setitem__("widnow", {})),
            ("window", lambda config: config["window"].__setitem__("time_zone", "UTC")),
            ("scope", lambda config: config["scope"].__setitem__("repository", [])),
            (
                "scope.repositories[0]",
                lambda config: config["scope"]["repositories"][0].__setitem__(
                    "repo", "project"
                ),
            ),
            (
                "providers.github",
                lambda config: config["providers"]["github"].__setitem__(
                    "max_page", 10
                ),
            ),
            (
                "providers.github.cache",
                lambda config: config["providers"]["github"].__setitem__(
                    "cache", {"enable": True}
                ),
            ),
            ("report", lambda config: config["report"].__setitem__("lang", "en")),
            (
                "report.privacy",
                lambda config: config["report"]["privacy"].__setitem__(
                    "source_urls", False
                ),
            ),
        )
        for expected_path, mutate in mutations:
            with self.subTest(path=expected_path):
                config = base_config()
                mutate(config)
                with self.assertRaisesRegex(
                    ConfigError, expected_path.replace("[", r"\[").replace("]", r"\]")
                ):
                    validate_collection_config(config)

    def test_unknown_non_string_key_is_a_config_error(self) -> None:
        config = base_config()
        config[1] = "unexpected"
        with self.assertRaisesRegex(ConfigError, "unknown key"):
            validate_collection_config(config)

    def test_report_only_and_direct_provider_validation_are_strict(self) -> None:
        with self.assertRaisesRegex(ConfigError, "report contains unknown"):
            validate_report_config({"profil": "project-first"})
        with self.assertRaisesRegex(ConfigError, "providers.github contains unknown"):
            provider_runtime_options("github", {"max_page": 10})

    def test_collection_config_without_report_uses_report_defaults(self) -> None:
        config = base_config()
        config.pop("report")
        report = validate_report_config(config)
        self.assertEqual(report["profile"], "project-first")
        self.assertEqual(report["language"], "en")


class InstanceIdentityTests(unittest.TestCase):
    def test_equivalent_instances_have_one_canonical_value(self) -> None:
        equivalents = (
            "github.com",
            "GitHub.com",
            "https://github.com",
            "HTTPS://GITHUB.COM/",
            "https://github.com:443/",
            "github.com:443/",
            "github.com.",
        )
        self.assertEqual(
            {validate_instance(value) for value in equivalents}, {"github.com"}
        )
        self.assertEqual(
            instance_web_base("HTTPS://GITHUB.COM:443/"), "https://github.com"
        )

    def test_hostname_uses_non_transitional_idna(self) -> None:
        self.assertEqual(validate_instance("https://faß.de"), "xn--fa-hia.de")
        self.assertNotEqual(
            validate_instance("https://faß.de"), validate_instance("https://fass.de")
        )

    def test_non_default_transport_and_base_path_are_canonicalized(self) -> None:
        cases = {
            "HtTp://LOCALHOST:80/": "http://localhost",
            "https://Example.COM:8443/base//child/": "https://example.com:8443/base/child",
            "https://例子.测试/团队/": "https://xn--fsqu00a.xn--0zwm56d/%E5%9B%A2%E9%98%9F",
            "https://[0:0:0:0:0:0:0:1]:443/": "[::1]",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(validate_instance(source), expected)

    def test_ambiguous_or_invalid_base_paths_are_rejected(self) -> None:
        for value in (
            "https://example.test/base/../admin",
            r"https://example.test/base\admin",
            "https://example.test/base%2Fadmin",
            "https://example.test/base%ZZ",
            "https://example.test/base%FF",
            "https://example.test/base/%252e%252e/admin",
            "https://example.test/base/%2500/admin",
            "https://example.test/base/%252F/admin",
            "https://example.test/base/%2541",
            "https://example.test/base%7F",
            "https://example.test/base%C2%85",
            "https://example.test/base\nadmin",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_instance(value)

    def test_gitlab_encoded_project_segment_stays_inside_api_boundary(self) -> None:
        target = RepositoryTarget("gitlab", "gitlab.com", "example", "nested-project")
        path = GitLabProvider._project_path(target)
        transport = UrllibTransport("https://gitlab.com/api/v4", max_retries=0)
        self.assertEqual(
            transport._url(path, None),
            "https://gitlab.com/api/v4/projects/example%2Fnested-project",
        )
        with self.assertRaises(ApiError):
            transport._url("/projects/example%252Fnested-project", None)

    def test_encoded_separators_cannot_manufacture_the_api_prefix(self) -> None:
        transport = UrllibTransport("https://example.test/api/v4", max_retries=0)
        for url in (
            "https://example.test/api%2Fv4/projects/example",
            "https://example.test/api/v4%2Fprojects/example",
        ):
            with self.subTest(url=url), self.assertRaises(ApiError):
                transport._url(url, None)

        for url in (
            "https://example.test/api/v4/proj\nects/example",
            "https://example.test/api/v4/projects/example%7F",
            "https://example.test/api/v4/projects/example%C2%85",
        ):
            with self.subTest(control_url=url), self.assertRaises(ApiError):
                transport._url(url, None)

        ascii_prefix = UrllibTransport(
            "https://example.test/team/api/v4", max_retries=0
        )
        self.assertEqual(
            ascii_prefix._url(
                "https://example.test/%74eam/api/v4/projects/example", None
            ),
            "https://example.test/%74eam/api/v4/projects/example",
        )
        unicode_prefix = UrllibTransport(
            "https://example.test/团队/api/v4", max_retries=0
        )
        self.assertEqual(
            unicode_prefix._url(
                "https://example.test/%e5%9b%a2%e9%98%9f/api/v4/projects/example",
                None,
            ),
            "https://example.test/%e5%9b%a2%e9%98%9f/api/v4/projects/example",
        )

    def test_query_controls_and_nested_encoding_fail_before_dispatch(self) -> None:
        transport = UrllibTransport("https://example.test/api/v4", max_retries=0)
        for query in (
            "q=%00",
            "q=%7F",
            "q=%C2%85",
            "q=%2500",
            "q=%GG",
            "q=%FF",
            "q=%C0%AF",
            "q=%25ZZ",
        ):
            url = f"https://example.test/api/v4/projects/example?{query}"
            with self.subTest(url=url), self.assertRaises(ApiError):
                transport._url(url, None)
            with self.assertRaises(ApiError):
                transport._target_policy.validate(url)

        for value in ("\x00", "\x7f", "\x85", "%00", "%ZZ"):
            with self.subTest(param=value), self.assertRaises(ApiError):
                transport._url("/projects/example", {"q": value})

        for token in ("bad\x00token", "bad%token"):
            with self.subTest(token=token):
                token_transport = UrllibTransport(
                    "https://example.test/api/v4",
                    token=token,
                    token_param="access_token",
                    max_retries=0,
                )
                with self.assertRaises(ApiError):
                    token_transport._url("/projects/example", None)

    def test_relative_pagination_identity_is_canonical_and_rejects_nesting(
        self,
    ) -> None:
        encoded = _pagination_request_identity("/projects/example%2Fproject", None)
        literal = _pagination_request_identity("/projects/example/project", None)
        self.assertEqual(encoded, literal)
        with self.assertRaises(ResponseShapeError):
            _pagination_request_identity("/projects/example%252Fproject", None)
        for path in (
            "/projects/example?q=%00",
            "/projects/example?q=%2500",
            "https://example.test/projects/example?q=%7F",
        ):
            with self.subTest(query_path=path), self.assertRaises(ResponseShapeError):
                _pagination_request_identity(path, None)
        with self.assertRaises(ResponseShapeError):
            _pagination_request_identity("/projects/example", {"q": "\x00"})

    def test_unsupported_or_malformed_schemes_are_rejected(self) -> None:
        for value in (
            "ftp://example.test",
            "SSH://example.test",
            "httpx://example.test",
            "https:example.test",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_instance(value)

    def test_legacy_numeric_address_aliases_are_rejected(self) -> None:
        for value in (
            "127.1",
            "2130706433",
            "0x7f000001",
            "017700000001",
            "１２７.０.０.１",
            "127。0。0。1",
            "²¹³⁰⁷⁰⁶⁴³³",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_instance(value)

    def test_repository_identity_components_are_provider_aware(self) -> None:
        for provider, owner, name in (
            ("github", "..", "project"),
            ("github", "team/subteam", "project"),
            ("gitee", "team", "project/name"),
            ("gitlab", "team/subteam", "project/name"),
        ):
            with (
                self.subTest(provider=provider, owner=owner, name=name),
                self.assertRaises(ValueError),
            ):
                RepositoryTarget(provider, f"{provider}.com", owner, name)

        gitlab = RepositoryTarget("gitlab", "gitlab.com", "team/subteam", "project")
        self.assertEqual(gitlab.owner, "team/subteam")
        unicode_target = RepositoryTarget("github", "github.com", "团队", "项目")
        self.assertEqual(
            GitHubProvider._repo_path(unicode_target),
            "/repos/%E5%9B%A2%E9%98%9F/%E9%A1%B9%E7%9B%AE",
        )

    def test_duplicate_canonical_repositories_fail_preflight(self) -> None:
        config = base_config()
        config["scope"]["repositories"].append(
            {
                "provider": "github",
                "instance": "HTTPS://GITHUB.COM:443/",
                "owner": "example",
                "name": "project",
            }
        )
        with self.assertRaisesRegex(ConfigError, "duplicate canonical repository"):
            validate_collection_config(config)

        config = base_config()
        config["scope"]["repositories"].append(
            {
                "provider": "github",
                "instance": "github.com.",
                "owner": "example",
                "name": "project",
            }
        )
        with self.assertRaisesRegex(ConfigError, "duplicate canonical repository"):
            validate_collection_config(config)

    def test_config_targets_and_requests_store_canonical_instances(self) -> None:
        config = base_config()
        config["scope"]["repositories"][0]["instance"] = "HTTPS://GITHUB.COM:443/"
        validated = validate_collection_config(config)
        self.assertEqual(
            validated["scope"]["repositories"][0]["instance"], "github.com"
        )

        target = RepositoryTarget(
            "github", "HTTPS://GITHUB.COM:443/", "example", "project"
        )
        request = CollectionRequest(
            provider_kind="github",
            instance="GitHub.com",
            repositories=(target,),
            window_start="2026-08-01T00:00:00Z",
            window_end="2026-08-02T00:00:00Z",
            timezone="Asia/Shanghai",
        )
        self.assertEqual(target.instance, "github.com")
        self.assertEqual(request.instance, "github.com")
        self.assertEqual(request.timezone, "Asia/Shanghai")

        with self.assertRaisesRegex(ValueError, "duplicate canonical targets"):
            CollectionRequest(
                provider_kind="github",
                instance="github.com",
                repositories=(target, target),
                window_start="2026-08-01T00:00:00Z",
                window_end="2026-08-02T00:00:00Z",
                timezone="UTC",
            )

    def test_timezone_must_be_an_iana_identifier(self) -> None:
        self.assertEqual(validate_timezone("UTC"), "UTC")
        self.assertEqual(validate_timezone("Asia/Shanghai"), "Asia/Shanghai")
        for value in ("", " UTC", "+08:00", "UTC+8", "Mars/Olympus", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_timezone(value)

        for value in ("+08:00", "UTC+8", "Mars/Olympus"):
            with self.subTest(config_timezone=value):
                config = deepcopy(base_config())
                config["window"]["timezone"] = value
                with self.assertRaisesRegex(ConfigError, "window.timezone is invalid"):
                    validate_collection_config(config)

    def test_runtime_dependencies_cover_idna_and_timezone_portability(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]
        dependencies = project["dependencies"]
        self.assertTrue(any(value.startswith("idna>=") for value in dependencies))
        self.assertTrue(any(value.startswith("tzdata>=") for value in dependencies))
