from __future__ import annotations

import os
import tempfile
import tomllib
import unittest
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from git_evidence.collect import collect_config
from git_evidence.config import (
    CollectionConfig,
    ConfigError,
    ProviderInstanceConfig,
    ReportConfig,
    RuntimeOptions,
    load_collection_config,
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
                    "provider_ref": "public-github",
                    "owner": "example",
                    "name": "project",
                }
            ],
            "actors": [],
        },
        "providers": {"public-github": {"kind": "github", "instance": "github.com"}},
        "report": {"privacy": {}},
    }


ROOT = Path(__file__).resolve().parents[1]


class StrictConfigTests(unittest.TestCase):
    def test_validated_network_config_types_cannot_be_constructed_directly(
        self,
    ) -> None:
        runtime = RuntimeOptions(
            timeout_seconds=30,
            max_retries=2,
            max_pages=100,
            max_requests=1000,
            retry_backoff_seconds=0.5,
            retry_jitter_seconds=0.25,
            retry_after_max_seconds=60,
            cache_enabled=False,
            cache_path=None,
            cache_ttl_seconds=300,
            cache_max_entries=256,
        )
        with self.assertRaisesRegex(
            TypeError, "issued only by configuration validation"
        ):
            ProviderInstanceConfig(
                ref="unsafe",
                kind="github",
                instance="http://127.0.0.1",
                token_env="TOKEN",
                include_activity_api=False,
                verify_tls=False,
                allow_insecure_loopback=True,
                runtime=runtime,
            )
        with self.assertRaisesRegex(
            TypeError, "issued only by configuration validation"
        ):
            CollectionConfig(
                window_start=datetime(2026, 8, 1, tzinfo=UTC),
                window_end=datetime(2026, 8, 2, tzinfo=UTC),
                timezone="UTC",
                repositories=(),
                actors=(),
                providers=(),
                report=ReportConfig(),
            )

    def test_yaml_is_not_detected_or_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.yml"
            path.write_text("window:\n  timezone: UTC\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_collection_config(path)

    def test_toml_input_bytes_depth_and_scalar_lengths_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(
                (ROOT / "config.example.toml").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            for constant, limit in (
                ("MAX_CONFIG_BYTES", 16),
                ("MAX_CONFIG_DEPTH", 2),
                ("MAX_CONFIG_SCALAR_CHARS", 4),
            ):
                with (
                    self.subTest(constant=constant),
                    patch(f"git_evidence.config.{constant}", limit),
                    self.assertRaises(ConfigError),
                ):
                    load_collection_config(path)

    def test_provider_references_are_exact_bounded_and_fully_used(self) -> None:
        unknown = base_config()
        unknown["scope"]["repositories"][0]["provider_ref"] = "missing"
        with self.assertRaisesRegex(ConfigError, "provider_ref is unknown"):
            validate_collection_config(unknown)

        unused = base_config()
        unused["providers"]["unused"] = {
            "kind": "gitlab",
            "instance": "gitlab.com",
        }
        with self.assertRaisesRegex(ConfigError, "unused reference"):
            validate_collection_config(unused)

        invalid_ref = base_config()
        invalid_ref["providers"]["Public_GitHub"] = invalid_ref["providers"].pop(
            "public-github"
        )
        invalid_ref["scope"]["repositories"][0]["provider_ref"] = "Public_GitHub"
        with self.assertRaisesRegex(ConfigError, "provider reference"):
            validate_collection_config(invalid_ref)

    def test_duplicate_canonical_provider_instance_is_rejected(self) -> None:
        config = base_config()
        config["providers"]["github-alias"] = {
            "kind": "github",
            "instance": "HTTPS://GITHUB.COM:443/",
        }
        config["scope"]["repositories"].append(
            {
                "provider_ref": "github-alias",
                "owner": "another",
                "name": "project",
            }
        )
        with self.assertRaisesRegex(ConfigError, "duplicate canonical provider"):
            validate_collection_config(config)

    def test_multiple_instances_of_one_kind_keep_separate_runtime_and_credentials(
        self,
    ) -> None:
        config = base_config()
        config["providers"]["public-github"]["token_env"] = "PUBLIC_GITHUB_TOKEN"
        config["providers"]["public-github"]["transport"] = {"max_requests": 7}
        config["providers"]["enterprise-github"] = {
            "kind": "github",
            "instance": "ghe.example",
            "token_env": "ENTERPRISE_GITHUB_TOKEN",
            "transport": {"max_requests": 9},
        }
        config["scope"]["repositories"].append(
            {
                "provider_ref": "enterprise-github",
                "owner": "enterprise",
                "name": "project",
            }
        )
        validated = validate_collection_config(config)
        providers = {provider.ref: provider for provider in validated.providers}
        self.assertEqual(providers["public-github"].token_env, "PUBLIC_GITHUB_TOKEN")
        self.assertEqual(providers["public-github"].runtime.max_requests, 7)
        self.assertEqual(
            providers["enterprise-github"].token_env, "ENTERPRISE_GITHUB_TOKEN"
        )
        self.assertEqual(providers["enterprise-github"].runtime.max_requests, 9)

        observed: list[tuple[str, int, str | None]] = []

        class FailedProvider:
            def collect(self, request: CollectionRequest) -> dict[str, object]:
                del request
                raise RuntimeError("fixture failure")

        def factory(
            kind: str,
            instance: str,
            options: dict[str, Any],
            token: str | None,
        ) -> FailedProvider:
            del kind
            observed.append((instance, options["max_requests"], token))
            return FailedProvider()

        with patch.dict(
            os.environ,
            {
                "PUBLIC_GITHUB_TOKEN": "public-token",
                "ENTERPRISE_GITHUB_TOKEN": "enterprise-token",
            },
        ):
            collect_config(validated, provider_factory=factory)
        self.assertEqual(
            observed,
            [
                ("ghe.example", 9, "enterprise-token"),
                ("github.com", 7, "public-token"),
            ],
        )

    def test_token_env_must_be_an_environment_variable_name(self) -> None:
        for value in ("TOKEN-NAME", "1TOKEN", "TOKEN NAME", ""):
            config = base_config()
            config["providers"]["public-github"]["token_env"] = value
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ConfigError, "environment variable"),
            ):
                validate_collection_config(config)

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
                "providers.public-github",
                lambda config: config["providers"]["public-github"].__setitem__(
                    "max_page", 10
                ),
            ),
            (
                "providers.public-github.cache",
                lambda config: config["providers"]["public-github"].__setitem__(
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
            validate_report_config({"report": {"profil": "project-first"}})
        config = base_config()
        config["providers"]["public-github"]["max_page"] = 10
        with self.assertRaisesRegex(
            ConfigError, "providers.public-github contains unknown"
        ):
            validate_collection_config(config)

    def test_collection_config_without_report_uses_report_defaults(self) -> None:
        config = base_config()
        config.pop("report")
        report = validate_report_config(config)
        self.assertEqual(report.profile, "project-first")
        self.assertEqual(report.language, "en")


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
                "provider_ref": "public-github",
                "owner": "example",
                "name": "project",
            }
        )
        with self.assertRaisesRegex(ConfigError, "duplicate canonical repository"):
            validate_collection_config(config)

        config = base_config()
        config["scope"]["repositories"].append(
            {
                "provider_ref": "public-github",
                "owner": "example",
                "name": "project",
            }
        )
        with self.assertRaisesRegex(ConfigError, "duplicate canonical repository"):
            validate_collection_config(config)

    def test_config_targets_and_requests_store_canonical_instances(self) -> None:
        config = base_config()
        config["providers"]["public-github"]["instance"] = "HTTPS://GITHUB.COM:443/"
        validated = validate_collection_config(config)
        self.assertEqual(validated.repositories[0].target.instance, "github.com")

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
