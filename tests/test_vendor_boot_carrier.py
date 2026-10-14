from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from treeforge_bootstrap.host_providers import (
    ensure_host_tool,
)

from treeforge_bootstrap.vendor_boot_carrier import (
    TREEFORGE_FRAGMENT_NAME,
    TREEFORGE_FRAGMENT_TYPE,
    realize_vendor_boot_carrier,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for block in iter(
            lambda: stream.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def _run(
    argv: list[str],
    *,
    capture: bool = False,
) -> bytes:
    result = subprocess.run(
        argv,
        stdout=(
            subprocess.PIPE
            if capture
            else None
        ),
        check=True,
    )

    return result.stdout or b""


def _unpack_arguments(
    tool: Path,
    image: Path,
    destination: Path,
) -> list[str]:
    if destination.exists():
        shutil.rmtree(destination)

    destination.mkdir(parents=True)

    raw = _run(
        [
            str(tool),
            "--boot_img",
            str(image),
            "--out",
            str(destination),
            "--format=mkbootimg",
            "-0",
        ],
        capture=True,
    )

    #
    # Empty interior NUL-delimited values are significant.
    # Remove only the final stream terminator.
    #
    parts = raw.split(b"\0")

    if parts and parts[-1] == b"":
        parts = parts[:-1]

    return [
        part.decode(
            "utf-8",
            errors="strict",
        )
        for part in parts
    ]


def _option(
    group: list[str],
    name: str,
    default: str,
) -> str:
    values = []

    for index, value in enumerate(group):
        if value != name:
            continue

        if index + 1 >= len(group):
            raise AssertionError(
                f"unterminated option {name}"
            )

        values.append(
            group[index + 1]
        )

    if not values:
        return default

    if len(values) != 1:
        raise AssertionError(
            f"duplicate option {name}: {values!r}"
        )

    return values[0]


def _type_id(value: str) -> int:
    symbolic = {
        "none": 0,
        "platform": 1,
        "recovery": 2,
        "dlkm": 3,
    }

    value = value.strip().lower()

    if value in symbolic:
        return symbolic[value]

    return int(value, 0)


def _fragments(
    arguments: list[str],
) -> list[dict[str, object]]:
    result = []
    group_start = 0

    for index, value in enumerate(arguments):
        if value != "--vendor_ramdisk_fragment":
            continue

        if index + 1 >= len(arguments):
            raise AssertionError(
                "unterminated vendor ramdisk fragment"
            )

        group = arguments[
            group_start:index + 2
        ]

        payload = Path(
            arguments[index + 1]
        ).resolve()

        if not payload.is_file():
            raise AssertionError(
                f"missing fragment: {payload}"
            )

        result.append(
            {
                "type": _type_id(
                    _option(
                        group,
                        "--ramdisk_type",
                        "0",
                    )
                ),
                "name": _option(
                    group,
                    "--ramdisk_name",
                    "",
                ),
                "board_ids": tuple(
                    int(
                        _option(
                            group,
                            f"--board_id{number}",
                            "0",
                        ),
                        0,
                    )
                    for number in range(16)
                ),
                "bytes": payload.stat().st_size,
                "sha256": _sha256(payload),
            }
        )

        group_start = index + 2

    return result


class VendorBootCarrierTest(
    unittest.TestCase
):

    def test_single_fragment_prefix_append(
        self,
    ) -> None:
        import hashlib

        mkbootimg = ensure_host_tool(
            "mkbootimg"
        )

        unpack_bootimg = ensure_host_tool(
            "unpack_bootimg"
        )

        avbtool = ensure_host_tool(
            "avbtool"
        )

        with tempfile.TemporaryDirectory(
            prefix="treeforge-vendor-boot-test-"
        ) as temporary:
            root = Path(temporary)

            factory = (
                root
                / "factory-fragment"
            )

            bootconfig = (
                root
                / "bootconfig"
            )

            factory_bytes = (
                b"TREEFORGE-FACTORY-FRAGMENT-0\n"
            )

            factory.write_bytes(
                factory_bytes
            )

            bootconfig.write_bytes(
                b"treeforge.test=1\n"
            )

            source = (
                root
                / "source"
                / "vendor_boot.img"
            )

            final = (
                root
                / "final"
                / "vendor_boot.img"
            )

            source.parent.mkdir()
            final.parent.mkdir()

            _run(
                [
                    str(mkbootimg),

                    "--header_version",
                    "4",

                    "--pagesize",
                    "4096",

                    "--base",
                    "0",

                    "--kernel_offset",
                    "0x10008000",

                    "--ramdisk_offset",
                    "0x11000000",

                    "--tags_offset",
                    "0x10000100",

                    "--dtb_offset",
                    "0x11f00000",

                    "--vendor_cmdline",
                    "",

                    "--board",
                    "",

                    "--vendor_bootconfig",
                    str(bootconfig),

                    "--ramdisk_type",
                    "platform",

                    "--ramdisk_name",
                    "factory_platform",

                    "--board_id0",
                    "0x12345678",

                    "--board_id1",
                    "1",

                    "--vendor_ramdisk_fragment",
                    str(factory),

                    "--vendor_boot",
                    str(source),
                ]
            )

            _run(
                [
                    str(avbtool),
                    "add_hash_footer",

                    "--image",
                    str(source),

                    "--partition_name",
                    "vendor_boot",

                    "--partition_size",
                    str(
                        8
                        * 1024
                        * 1024
                    ),

                    "--algorithm",
                    "NONE",

                    "--hash_algorithm",
                    "sha256",

                    "--salt",
                    "00" * 32,

                    "--prop",
                    (
                        "com.android.build."
                        "vendor_boot.fingerprint:"
                        "TreeForge/test/vendor_boot"
                    ),
                ]
            )

            _run(
                [
                    str(avbtool),
                    "verify_image",
                    "--image",
                    str(source),
                ]
            )

            source_sha = (
                _sha256(
                    source
                )
            )

            source_unpack = (
                root
                / "source-unpack"
            )

            source_arguments = (
                _unpack_arguments(
                    unpack_bootimg,
                    source,
                    source_unpack,
                )
            )

            source_fragments = (
                _fragments(
                    source_arguments
                )
            )

            self.assertEqual(
                len(source_fragments),
                1,
            )

            self.assertEqual(
                source_fragments[0]["type"],
                1,
            )

            self.assertEqual(
                source_fragments[0]["name"],
                "factory_platform",
            )

            self.assertEqual(
                source_fragments[0][
                    "board_ids"
                ][0],
                0x12345678,
            )

            self.assertEqual(
                source_fragments[0][
                    "board_ids"
                ][1],
                1,
            )

            realize_vendor_boot_carrier(
                source=source,
                output=final,
            )

            self.assertEqual(
                _sha256(source),
                source_sha,
            )

            _run(
                [
                    str(avbtool),
                    "verify_image",
                    "--image",
                    str(final),
                ]
            )

            final_unpack = (
                root
                / "final-unpack"
            )

            final_arguments = (
                _unpack_arguments(
                    unpack_bootimg,
                    final,
                    final_unpack,
                )
            )

            final_fragments = (
                _fragments(
                    final_arguments
                )
            )

            self.assertEqual(
                len(final_fragments),
                1,
            )

            self.assertEqual(
                final_fragments[0]["type"],
                source_fragments[0]["type"],
            )

            self.assertEqual(
                final_fragments[0]["name"],
                source_fragments[0]["name"],
            )

            self.assertEqual(
                final_fragments[0][
                    "board_ids"
                ],
                source_fragments[0][
                    "board_ids"
                ],
            )

            fragment_indexes = [
                index
                for index, value
                in enumerate(
                    final_arguments
                )
                if (
                    value
                    == "--vendor_ramdisk_fragment"
                )
            ]

            self.assertEqual(
                len(fragment_indexes),
                1,
            )

            final_fragment_path = Path(
                final_arguments[
                    fragment_indexes[0]
                    + 1
                ]
            )

            if (
                not final_fragment_path
                .is_absolute()
            ):
                final_fragment_path = (
                    final_unpack
                    / final_fragment_path
                ).resolve()

            payload = (
                final_fragment_path
                .read_bytes()
            )

            self.assertEqual(
                payload[
                    :len(factory_bytes)
                ],
                factory_bytes,
            )

            stream = payload[
                len(factory_bytes):
            ]

            self.assertEqual(
                len(stream),
                328,
            )

            self.assertEqual(
                hashlib.sha256(
                    stream
                ).hexdigest(),
                (
                    "0d198178ec0baa7e9d05e5f30c73b84b"
                        "356d4817723354bf9a622b16d7109594"
                ),
            )

            self.assertEqual(
                final_fragments[0][
                    "bytes"
                ],
                len(factory_bytes)
                + 328,
            )

            self.assertEqual(
                final.stat().st_size,
                source.stat().st_size,
            )


if __name__ == "__main__":
    unittest.main()
