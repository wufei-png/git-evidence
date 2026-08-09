from __future__ import annotations

import unittest
from contextlib import redirect_stderr
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from scripts.check_pyright_baseline import main


class PyrightBaselineTests(unittest.TestCase):
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
