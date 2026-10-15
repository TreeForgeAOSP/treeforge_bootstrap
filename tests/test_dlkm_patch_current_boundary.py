from __future__ import annotations

import inspect
import unittest

from treeforge_bootstrap import kernel_carriers


class DlkmPatchCurrentBoundaryTests(
    unittest.TestCase
):
    def test_dlkm_realizer_patches_current_carrier(
        self,
    ) -> None:
        signature = inspect.signature(
            kernel_carriers._realize_dlkm
        )

        self.assertIn(
            "source",
            signature.parameters,
        )

        source = inspect.getsource(
            kernel_carriers._realize_dlkm
        )

        #
        # The carrier must begin as an exact copy of the
        # current/source filesystem. Rebuilding a fresh ext4
        # image from only lib/modules caused the original DT2W
        # regression by deleting vendor_dlkm /etc content.
        #
        self.assertIn(
            "shutil.copy2(",
            source,
        )

        self.assertIn(
            "erase_footer",
            source,
        )

        self.assertNotIn(
            "mke2fs",
            source,
        )

        #
        # Metadata updates are scoped to the replaced module
        # tree. Preserved source inodes such as /etc must not
        # have their metadata rewritten.
        #
        self.assertIn(
            "include_root_metadata=False",
            source,
        )

        #
        # Tangorpro's module-init contract is a mandatory
        # preservation gate. Its loss leaves the vendor module
        # readiness properties unset and prevents twoshay from
        # starting.
        #
        self.assertIn(
            "/etc/init.insmod.tangorpro.cfg",
            source,
        )

        self.assertIn(
            "/etc/build.prop",
            source,
        )

        self.assertIn(
            "/etc/fs_config_dirs",
            source,
        )

        self.assertIn(
            "/etc/fs_config_files",
            source,
        )

        #
        # AVB geometry must be inherited from the source carrier
        # rather than from a newly constructed modules-only
        # filesystem.
        #
        self.assertIn(
            "source_partition_bytes",
            source,
        )

        self.assertIn(
            "source_salt",
            source,
        )

    def test_family_supplies_current_dlkm_sources(
        self,
    ) -> None:
        source = inspect.getsource(
            kernel_carriers.realize_kernel_carriers
        )

        self.assertIn(
            "source_dlkm = _source_image(",
            source,
        )

        self.assertIn(
            "source=source_dlkm",
            source,
        )

        for name in (
            "vendor_dlkm",
            "system_dlkm",
        ):
            self.assertIn(
                f'"{name}"',
                source,
            )


if __name__ == "__main__":
    unittest.main()
