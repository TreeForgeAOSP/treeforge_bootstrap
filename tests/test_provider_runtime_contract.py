from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import treeforge_bootstrap.runtime as runtime


def _record(path: Path) -> dict[str, object]:
    return {
        "bytes": path.stat().st_size,
        "sha256": hashlib.sha256(
            path.read_bytes()
        ).hexdigest(),
    }


class ProviderRuntimeContractTests(unittest.TestCase):
    def test_packaged_runtime_contract_overrides_source_freeze(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provider_root = root / "provider"
            metadata_root = provider_root / "metadata"
            runtime_root = root / "runtime"

            provider_root.mkdir(parents=True)
            metadata_root.mkdir(parents=True)
            runtime_root.mkdir(parents=True)

            cpio = runtime_root / "initramfs.cpio"
            lz4 = runtime_root / "initramfs.lz4"
            menu = runtime_root / "treeforge-menu"

            cpio.write_bytes(b"cpio")
            lz4.write_bytes(b"lz4!")
            menu.write_bytes(b"menu")

            (
                metadata_root
                / "realizer-provider.json"
            ).write_text(
                json.dumps(
                    {
                        "runtime_payload": {
                            "initramfs.cpio":
                                _record(cpio),
                            "initramfs.lz4":
                                _record(lz4),
                            "treeforge-menu":
                                _record(menu),
                        }
                    }
                ),
                encoding="utf-8",
            )

            with (
                patch.object(
                    runtime,
                    "REPOSITORY_ROOT",
                    provider_root,
                ),
                patch.object(
                    runtime,
                    "RAW_INITRAMFS",
                    cpio,
                ),
                patch.object(
                    runtime,
                    "COMPRESSED_INITRAMFS",
                    lz4,
                ),
                patch.object(
                    runtime,
                    "MENU_BINARY",
                    menu,
                ),
            ):
                expected = (
                    runtime
                    ._packaged_runtime_expectations()
                )

            self.assertIsNotNone(expected)
            self.assertEqual(expected[0][2], 4)
            self.assertEqual(expected[1][2], 4)
            self.assertEqual(expected[2][2], 4)

    def test_source_checkout_uses_frozen_contract(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_root = (
                Path(temporary)
                / "treeforge_bootstrap"
            )

            with patch.object(
                runtime,
                "REPOSITORY_ROOT",
                source_root,
            ):
                expected = (
                    runtime
                    ._packaged_runtime_expectations()
                )

            self.assertIsNone(expected)


if __name__ == "__main__":
    unittest.main()
