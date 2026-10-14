from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from treeforge_bootstrap import (
    development_overrides as overrides,
)


class DevelopmentOverridesTests(
    unittest.TestCase
):
    def test_explicit_save_reuse_remove(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            config = (
                Path(raw)
                / "config"
            )

            provider = (
                Path(raw)
                / "provider"
            )

            provider.mkdir()

            with patch.dict(
                os.environ,
                {
                    "XDG_CONFIG_HOME":
                        str(config),
                },
                clear=False,
            ):
                selected, result = (
                    overrides.activate(
                        "menu",
                        str(provider),
                        prompt_label="unused",
                        validator=lambda path: path,
                    )
                )

                self.assertEqual(
                    selected,
                    provider.resolve(),
                )

                self.assertEqual(
                    result,
                    provider.resolve(),
                )

                selected, _ = (
                    overrides.activate(
                        "menu",
                        "",
                        prompt_label="unused",
                        validator=lambda path: path,
                    )
                )

                self.assertEqual(
                    selected,
                    provider.resolve(),
                )

                self.assertTrue(
                    overrides.remove(
                        "menu"
                    )
                )

                self.assertIsNone(
                    overrides.remembered(
                        "menu"
                    )
                )

                data = json.loads(
                    overrides.config_file()
                    .read_text(
                        encoding="utf-8"
                    )
                )

                self.assertEqual(
                    data["schema"],
                    overrides.SCHEMA,
                )


if __name__ == "__main__":
    unittest.main()
