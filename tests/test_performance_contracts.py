from __future__ import annotations

import ast
import unittest
from pathlib import Path

from git_evidence.providers.github import GitHubProvider
from git_evidence.providers.resource_base import BundleBuilder
from tests.test_contract import github_transport, request_for


class PerformanceContractTests(unittest.TestCase):
    def test_checkpoint_cost_does_not_grow_with_historical_indexes(self) -> None:
        builder = BundleBuilder(
            request_for("github", "github.com"),
            GitHubProvider.descriptor,
            github_transport(),
        )
        empty_checkpoint = builder.checkpoint()
        builder.commit(empty_checkpoint)

        historical_count = 10_000
        builder._seen["commits"].update(
            f"commit:historical:{index}" for index in range(historical_count)
        )
        builder._actor_ids.update(
            (str(index), f"actor:{index}") for index in range(historical_count)
        )
        builder._commit_ids_by_sha.update(
            (("repository", str(index)), {f"commit:{index}"})
            for index in range(historical_count)
        )
        builder._change_request_ids_by_sha.update(
            (("repository", str(index)), {f"change-request:{index}"})
            for index in range(historical_count)
        )
        builder._duplicate_counts.update(
            (("commits", str(index)), index) for index in range(historical_count)
        )
        builder._filtered_subjects.update(
            (str(index), {"id": str(index)}) for index in range(historical_count)
        )
        builder._retrieval_ids.update(
            (str(index), f"retrieval:{index}") for index in range(historical_count)
        )
        builder._retrieval_provenance.update(
            (str(index), {"_key": str(index)}) for index in range(historical_count)
        )

        historical_checkpoint = builder.checkpoint()
        self.assertEqual(
            historical_checkpoint, empty_checkpoint | {"transaction_token": 2}
        )
        self.assertEqual(builder._index_undo, [])

        self.assertTrue(builder._add_entity("commits", {"id": "commit:new"}))
        self.assertEqual(len(builder._index_undo), 1)
        builder.restore(historical_checkpoint)
        self.assertNotIn("commit:new", builder._seen["commits"])
        self.assertEqual(builder.bundle["commits"], [])

    def test_sequential_repository_collector_path_is_absent(self) -> None:
        provider_directory = Path(__file__).parents[1] / "src/git_evidence/providers"
        for name in ("resource_base.py", "github.py", "gitlab.py", "gitee.py"):
            with self.subTest(provider=name):
                tree = ast.parse((provider_directory / name).read_text())
                function_names = {
                    node.name
                    for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef)
                }
                self.assertNotIn("_collect_repository", function_names)


if __name__ == "__main__":
    unittest.main()
