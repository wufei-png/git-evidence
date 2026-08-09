from __future__ import annotations

import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from scripts.check_pyright_baseline import main


class PyrightBaselineTests(unittest.TestCase):
    def test_committed_error_baseline_is_a_strict_ratchet(self) -> None:
        for error_count, expected_status in ((68, 0), (69, 1)):
            with self.subTest(error_count=error_count):
                completed = SimpleNamespace(
                    stdout=(
                        '{"summary": {'
                        f'"errorCount": {error_count}, "warningCount": 0'
                        "}}"
                    ),
                    stderr="",
                    returncode=1,
                )
                with (
                    patch(
                        "scripts.check_pyright_baseline.subprocess.run",
                        return_value=completed,
                    ),
                    redirect_stdout(StringIO()),
                    redirect_stderr(StringIO()),
                ):
                    self.assertEqual(main(), expected_status)

    def test_malformed_json_shape_fails_with_a_controlled_diagnostic(self) -> None:
        completed = SimpleNamespace(stdout="{}", stderr="", returncode=1)
        stderr = StringIO()
        with (
            patch(
                "scripts.check_pyright_baseline.subprocess.run", return_value=completed
            ),
            redirect_stderr(stderr),
        ):
            self.assertEqual(main(), 2)
        self.assertIn("did not contain a summary object", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
