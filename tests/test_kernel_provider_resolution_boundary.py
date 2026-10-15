from __future__ import annotations

from pathlib import Path
import unittest


ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

KERNEL_SOURCE = (
    ROOT
    / "src"
    / "treeforge_bootstrap"
    / "kernel_provider.py"
)

IMAGE_SOURCE = (
    ROOT
    / "src"
    / "treeforge_bootstrap"
    / "image.py"
)


class KernelProviderResolutionBoundaryTests(
    unittest.TestCase
):
    def test_image_has_no_static_kernel_release_pin(
        self,
    ):
        text = IMAGE_SOURCE.read_text(
            encoding="utf-8"
        )

        self.assertNotIn(
            "EXPECTED_KERNEL_BYTES",
            text,
        )

        self.assertNotIn(
            "EXPECTED_KERNEL_SHA256",
            text,
        )

        self.assertNotIn(
            "KERNEL_CHANNEL",
            text,
        )

    def test_image_records_resolved_release_and_sha(
        self,
    ):
        text = IMAGE_SOURCE.read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "resolved_kernel_release()",
            text,
        )

        self.assertIn(
            "_sha256(ensure_bootstrap_kernel())",
            text,
        )

    def test_production_resolver_tracks_github_current(
        self,
    ):
        text = KERNEL_SOURCE.read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "_published_release_tags",
            text,
        )

        self.assertIn(
            "_materialize_release_provider",
            text,
        )

        self.assertIn(
            "SHA256SUMS",
            text,
        )

        self.assertIn(
            'KERNEL_CHANNEL = "current"',
            text,
        )

        self.assertNotIn(
            "EXPECTED_KERNEL_SHA256",
            text,
        )

        self.assertNotIn(
            "EXPECTED_MODULE_PROVIDER_SHA256",
            text,
        )

        self.assertNotIn(
            "EXPECTED_MODULE_ARCHIVE_SHA256",
            text,
        )

        self.assertNotIn(
            '"r0.94-v1.0b1"',
            text,
        )


if __name__ == "__main__":
    unittest.main()
