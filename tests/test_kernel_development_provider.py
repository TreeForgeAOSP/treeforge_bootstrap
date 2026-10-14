from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from treeforge_bootstrap import (
    kernel_provider,
)


def sha256(
    path: Path,
) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


class KernelDevelopmentProviderTests(
    unittest.TestCase
):
    def tearDown(
        self,
    ) -> None:
        kernel_provider.configure_kernel_provider_override(
            None
        )

    def test_v2_development_provider(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)

            boot = root / "boot.img"
            boot.write_bytes(
                b"treeforge-kernel-test"
            )

            archive = (
                root
                / (
                    "treeforge-kernel-modules-"
                    "tangorpro-android15-test.tar.zst"
                )
            )

            archive.write_bytes(
                b"module-provider-test"
            )

            module = {
                "schema":
                    "treeforge.kernel.module-provider.v2",

                "release":
                    "test",

                "target":
                    "tangorpro",

                "android_base":
                    "android15",

                "boot_sha256":
                    sha256(boot),

                "reconstruction": {
                    "carrier_source":
                        "current-installed",

                    "carrier_policy":
                        "patch-current",

                    "non_module_payload":
                        "preserve-exact",

                    "module_tree_policy":
                        "replace-exact",

                    "regenerate_module_metadata":
                        True,

                    "partition_images_distributed":
                        False,

                    "owner_avb":
                        "local-device-owner-resign",

                    "carriers": {
                        "vendor_kernel_boot": {},
                        "vendor_dlkm": {},
                        "system_dlkm": {},
                    },
                },

                "carriers": {
                    "vendor_kernel_boot": {
                        "module_count": 0,
                        "files": [],
                    },

                    "vendor_dlkm": {
                        "module_count": 0,
                        "files": [],
                    },

                    "system_dlkm": {
                        "module_count": 0,
                        "files": [],
                    },
                },
            }

            (
                root
                / "module-provider.json"
            ).write_text(
                json.dumps(
                    module,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            development = {
                "schema":
                    "treeforge.development-provider.v1",

                "provider":
                    "kernel",

                "channel":
                    "development",

                "release_eligible":
                    False,

                "version":
                    "test",
            }

            (
                root
                / "development-provider.json"
            ).write_text(
                json.dumps(
                    development,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            checked = (
                boot,
                root / "module-provider.json",
                archive,
            )

            (
                root
                / "SHA256SUMS"
            ).write_text(
                "".join(
                    sha256(path)
                    + "  "
                    + path.name
                    + "\n"
                    for path in checked
                ),
                encoding="utf-8",
            )

            kernel_provider.configure_kernel_provider_override(
                root
            )

            resolved = (
                kernel_provider
                .ensure_kernel_reconstruction_provider()
            )

            self.assertEqual(
                resolved["boot"],
                boot,
            )

            self.assertEqual(
                resolved["archive"],
                archive,
            )

            self.assertEqual(
                resolved["release"],
                "test",
            )

            self.assertEqual(
                kernel_provider.ensure_bootstrap_kernel(),
                boot,
            )


if __name__ == "__main__":
    unittest.main()
