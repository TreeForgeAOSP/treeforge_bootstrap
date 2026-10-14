from __future__ import annotations

import hashlib
import struct
import unittest

from treeforge_bootstrap.vendor_boot_carrier import (
    BOOTSTRAP_CARRIER_HEADER_BYTES,
    BOOTSTRAP_CARRIER_MAGIC,
    BOOTSTRAP_CARRIER_RECORD_BYTES,
    BOOTSTRAP_CARRIER_SCHEMA,
    BootstrapCarrierEntry,
    TreeForgeVendorBootCarrierError,
    build_bootstrap_carrier_blob,
    parse_bootstrap_carrier_blob,
)


class BootstrapCarrierFormatTest(
    unittest.TestCase
):
    def _entries(
        self,
    ) -> tuple[
        BootstrapCarrierEntry,
        ...,
    ]:
        return (
            BootstrapCarrierEntry(
                name="proof/retained-fd",
                mode=0o444,
                payload=(
                    b"TREEFORGE_BOOTSTRAP_"
                    b"VENDOR_BOOT_CARRIER_V1\n"
                ),
            ),
            BootstrapCarrierEntry(
                name="transaction/request-v1",
                mode=0o644,
                payload=(
                    b"TREEFORGE_BOOTSTRAP_TRANSACTION_V1\n"
                    b"id="
                    + (
                        b"0123456789abcdef"
                        * 4
                    )
                    + b"\noperation=proof\n"
                ),
            ),
        )

    def test_round_trip(
        self,
    ) -> None:
        entries = self._entries()

        blob = (
            build_bootstrap_carrier_blob(
                entries
            )
        )

        parsed = (
            parse_bootstrap_carrier_blob(
                blob
            )
        )

        self.assertEqual(
            parsed,
            tuple(
                sorted(
                    entries,
                    key=lambda entry:
                        entry.name,
                )
            ),
        )

    def test_deterministic_order(
        self,
    ) -> None:
        entries = self._entries()

        first = (
            build_bootstrap_carrier_blob(
                entries
            )
        )

        second = (
            build_bootstrap_carrier_blob(
                tuple(
                    reversed(entries)
                )
            )
        )

        self.assertEqual(
            first,
            second,
        )

    def test_header_contract(
        self,
    ) -> None:
        entries = self._entries()

        blob = (
            build_bootstrap_carrier_blob(
                entries
            )
        )

        header = struct.Struct(
            "<8sIIIIQQQ32s16s"
        )

        self.assertEqual(
            header.size,
            BOOTSTRAP_CARRIER_HEADER_BYTES,
        )

        (
            magic,
            schema,
            header_bytes,
            record_bytes,
            entry_count,
            table_offset,
            payload_offset,
            total_bytes,
            table_digest,
            reserved,
        ) = header.unpack_from(
            blob,
            0,
        )

        self.assertEqual(
            magic,
            BOOTSTRAP_CARRIER_MAGIC,
        )

        self.assertEqual(
            schema,
            BOOTSTRAP_CARRIER_SCHEMA,
        )

        self.assertEqual(
            header_bytes,
            96,
        )

        self.assertEqual(
            record_bytes,
            128,
        )

        self.assertEqual(
            entry_count,
            2,
        )

        self.assertEqual(
            table_offset,
            96,
        )

        self.assertEqual(
            payload_offset,
            (
                96
                + 2 * 128
            ),
        )

        self.assertEqual(
            total_bytes,
            len(blob),
        )

        self.assertEqual(
            table_digest,
            hashlib.sha256(
                blob[
                    table_offset:
                    payload_offset
                ]
            ).digest(),
        )

        self.assertEqual(
            reserved,
            b"\0" * 16,
        )

    def test_payload_mutation_rejected(
        self,
    ) -> None:
        blob = bytearray(
            build_bootstrap_carrier_blob(
                self._entries()
            )
        )

        blob[-1] ^= 1

        with self.assertRaises(
            TreeForgeVendorBootCarrierError
        ):
            parse_bootstrap_carrier_blob(
                bytes(blob)
            )

    def test_table_mutation_rejected(
        self,
    ) -> None:
        blob = bytearray(
            build_bootstrap_carrier_blob(
                self._entries()
            )
        )

        blob[
            BOOTSTRAP_CARRIER_HEADER_BYTES
        ] ^= 1

        with self.assertRaises(
            TreeForgeVendorBootCarrierError
        ):
            parse_bootstrap_carrier_blob(
                bytes(blob)
            )

    def test_duplicate_name_rejected(
        self,
    ) -> None:
        entry = BootstrapCarrierEntry(
            name="runtime/helper",
            mode=0o755,
            payload=b"x",
        )

        with self.assertRaises(
            TreeForgeVendorBootCarrierError
        ):
            build_bootstrap_carrier_blob(
                (
                    entry,
                    entry,
                )
            )

    def test_unsafe_names_rejected(
        self,
    ) -> None:
        for name in (
            "/absolute",
            "../escape",
            "runtime/../escape",
            "runtime//helper",
            "runtime/",
            "UPPERCASE",
        ):
            with self.subTest(
                name=name
            ):
                with self.assertRaises(
                    TreeForgeVendorBootCarrierError
                ):
                    build_bootstrap_carrier_blob(
                        (
                            BootstrapCarrierEntry(
                                name=name,
                                mode=0o755,
                                payload=b"x",
                            ),
                        )
                    )

    def test_invalid_mode_rejected(
        self,
    ) -> None:
        with self.assertRaises(
            TreeForgeVendorBootCarrierError
        ):
            build_bootstrap_carrier_blob(
                (
                    BootstrapCarrierEntry(
                        name="runtime/helper",
                        mode=0o10000,
                        payload=b"x",
                    ),
                )
            )


if __name__ == "__main__":
    unittest.main()
