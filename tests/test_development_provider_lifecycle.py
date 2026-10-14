from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from treeforge_bootstrap import (
    development_provider as provider,
)


class DevelopmentProviderLifecycleTests(
    unittest.TestCase
):
    def test_retains_five_successes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)

            runs = root / "runs"
            runs.mkdir()

            for index in range(7):
                (
                    runs
                    / f"run-{index:02d}"
                ).mkdir()

            with patch.object(
                provider,
                "DEVELOPMENT_RUNS",
                runs,
            ):
                provider._prune_runs()

            self.assertEqual(
                [
                    path.name
                    for path in sorted(
                        runs.iterdir()
                    )
                ],
                [
                    "run-02",
                    "run-03",
                    "run-04",
                    "run-05",
                    "run-06",
                ],
            )

    def test_failed_run_does_not_advance_current(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)

            runs = root / "runs"
            incoming = root / ".incoming"
            current = root / "current"

            runs.mkdir()
            incoming.mkdir()

            previous = (
                runs
                / "previous"
            )

            previous.mkdir()

            current.symlink_to(
                Path("runs")
                / "previous"
            )

            dummy = SimpleNamespace(
                root=root,
                version="test",
                boot_manager_version="test",
            )

            with (
                patch.object(
                    provider,
                    "DEVELOPMENT_ROOT",
                    root,
                ),
                patch.object(
                    provider,
                    "DEVELOPMENT_RUNS",
                    runs,
                ),
                patch.object(
                    provider,
                    "DEVELOPMENT_INCOMING",
                    incoming,
                ),
                patch.object(
                    provider,
                    "DEVELOPMENT_CURRENT",
                    current,
                ),
                patch.object(
                    provider,
                    "LEGACY_DEVELOPMENT_DIR",
                    root / "legacy",
                ),
                patch.object(
                    provider,
                    "_version_fields",
                    return_value={
                        "bootstrap": "test",
                        "runtime_abi": "test",
                    },
                ),
                patch.object(
                    provider,
                    "_run_id",
                    return_value="failed",
                ),
                patch.object(
                    provider,
                    "load_menu_provider",
                    return_value=dummy,
                ),
                patch.object(
                    provider,
                    "load_framebuffer_provider",
                    return_value=dummy,
                ),
                patch.object(
                    provider,
                    "_write_runtime_provider",
                    side_effect=RuntimeError(
                        "expected failure"
                    ),
                ),
            ):
                with self.assertRaises(
                    RuntimeError
                ):
                    provider.package_development_provider()

            self.assertEqual(
                current.resolve(),
                previous.resolve(),
            )

            self.assertFalse(
                (
                    runs
                    / "failed"
                ).exists()
            )

            self.assertFalse(
                (
                    incoming
                    / "failed"
                ).exists()
            )


if __name__ == "__main__":
    unittest.main()
