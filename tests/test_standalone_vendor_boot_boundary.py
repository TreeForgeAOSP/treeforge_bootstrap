from pathlib import Path
import unittest


ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


class StandaloneVendorBootBoundaryTest(
    unittest.TestCase
):
    def test_family_carrier_is_transaction_only(
        self,
    ) -> None:
        source = (
            ROOT
            / "src"
            / "treeforge_bootstrap"
            / "avb_graph.py"
        ).read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "if transaction_request is not None:",
            source,
        )

        self.assertIn(
            'name == "vendor_boot"\n'
            "            and vendor_boot_carrier is not None",
            source,
        )

        self.assertIn(
            'allowed_changed.add(\n'
            '            "vendor_boot"\n'
            "        )",
            source,
        )

    def test_runtime_carrier_is_optional(
        self,
    ) -> None:
        source = (
            ROOT
            / "src"
            / "treeforge_bootstrap"
            / "dispatcher.py"
        ).read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "tfb_vendor_boot_carrier_fd_available",
            source,
        )

        self.assertIn(
            "vendor_boot_carrier_fd >= 0",
            source,
        )

        self.assertIn(
            "FD98 is reserved by Bootstrap",
            source,
        )

        self.assertNotIn(
            '"vendor-boot-carrier-open"',
            source,
        )

        self.assertIn(
            '"vendor-boot-carrier=absent"',
            source,
        )


if __name__ == "__main__":
    unittest.main()
