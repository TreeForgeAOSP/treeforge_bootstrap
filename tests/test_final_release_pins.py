from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from treeforge_bootstrap import (
    framebuffer_provider,
    kernel_provider,
    menu_provider,
)


class FinalProviderResolutionTests(
    unittest.TestCase
):
    def test_kernel_uses_current_channel(
        self,
    ):
        self.assertEqual(
            kernel_provider.KERNEL_REPOSITORY,
            "TreeForgeAOSP/treeforge_kernel",
        )

        self.assertEqual(
            kernel_provider.KERNEL_CHANNEL,
            "current",
        )

        self.assertIsNotNone(
            kernel_provider.KERNEL_RELEASE_RE.fullmatch(
                "r12.34-v5.6b7"
            )
        )

    def test_public_child_repositories(
        self,
    ):
        self.assertEqual(
            framebuffer_provider.PROVIDER_REPOSITORY,
            "TreeForgeAOSP/"
            "treeforge_bootstrap_framebuffer",
        )

        self.assertEqual(
            menu_provider.PROVIDER_REPOSITORY,
            "TreeForgeAOSP/"
            "treeforge_bootstrap_menu",
        )

        for module in (
            framebuffer_provider,
            menu_provider,
        ):
            request = module._github_request(
                "https://api.github.com/",
                token=None,
                accept=(
                    "application/"
                    "vnd.github+json"
                ),
            )

            self.assertIsNone(
                request.get_header(
                    "Authorization"
                )
            )

    def test_kernel_contract_accepts_resolved_release(
        self,
    ):
        release = (
            "r12.34-v5.6b7"
        )

        boot_sha256 = (
            "1" * 64
        )

        metadata = {
            "schema":
                "treeforge.kernel.module-provider.v2",

            "release":
                release,

            "target":
                "tangorpro",

            "android_base":
                "android15",

            "boot_sha256":
                boot_sha256,

            "supported_baseline": {
                "type":
                    "pixel-partitioner-aosp-backup",

                **kernel_provider.SUPPORTED_BASELINE,
            },

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
                    "vendor_kernel_boot": {
                        "image_structure":
                            "preserve",

                        "module_tree_policy":
                            "replace-exact",

                        "non_module_payload":
                            "preserve-exact",

                        "ramdisk_compression":
                            "lz4",
                    },

                    "vendor_dlkm": {
                        "filesystem_structure":
                            "preserve",

                        "module_tree_policy":
                            "replace-exact",

                        "non_module_payload":
                            "preserve-exact",
                    },

                    "system_dlkm": {
                        "filesystem_structure":
                            "preserve",

                        "module_tree_policy":
                            "replace-exact",

                        "non_module_payload":
                            "preserve-exact",
                    },
                },
            },

            "carriers": {
                "vendor_kernel_boot":
                    {},

                "vendor_dlkm":
                    {},

                "system_dlkm":
                    {},
            },
        }

        with tempfile.TemporaryDirectory() as raw:
            path = (
                Path(raw)
                / "module-provider.json"
            )

            path.write_text(
                json.dumps(
                    metadata
                ),
                encoding="utf-8",
            )

            result = (
                kernel_provider
                ._verify_provider_contract(
                    path,
                    expected_release=release,
                    expected_boot_sha256=(
                        boot_sha256
                    ),
                )
            )

        self.assertEqual(
            result["release"],
            release,
        )


if __name__ == "__main__":
    unittest.main()
