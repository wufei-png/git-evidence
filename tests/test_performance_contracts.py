from __future__ import annotations

import unittest
from unittest.mock import patch

from git_evidence.providers.github import GitHubProvider
from git_evidence.providers.resource_base import BundleBuilder
from tests.test_contract import github_transport, request_for


class PerformanceContractTests(unittest.TestCase):
    def test_checkpoint_never_deep_copies_historical_entity_payloads(self) -> None:
        builder = BundleBuilder(
            request_for("github", "github.com"),
            GitHubProvider.descriptor,
            github_transport(),
        )
        builder.bundle["commits"] = [
            {"id": f"commit:{index}", "payload": "x" * 10_000} for index in range(500)
        ]

        with patch(
            "git_evidence.providers.resource_base.deepcopy",
            side_effect=AssertionError("checkpoint copied historical payloads"),
        ):
            checkpoint = builder.checkpoint()

        self.assertEqual(checkpoint["collection_lengths"]["commits"], 500)
        self.assertNotIn("payload", repr(checkpoint))


if __name__ == "__main__":
    unittest.main()
