from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile

from .paths import OUT
from .runtime import (
    COMPRESSED_INITRAMFS,
    MENU_BINARY,
    RAW_INITRAMFS,
    verify_runtime,
)


class TreeForgeBootstrapProviderError(
    RuntimeError
):
    pass


PROVIDER_NAME = (
    "treeforge-bootstrap"
)

PROVIDER_VARIANT = (
    "tangorpro-android15-runtime"
)

PROVIDER_ROOT_NAME = (
    PROVIDER_NAME
    + "-"
    + PROVIDER_VARIANT
)

PROVIDER_OUT = (
    OUT
    / "provider"
)

PROVIDER_ARCHIVE = (
    PROVIDER_OUT
    / (
        PROVIDER_ROOT_NAME
        + ".tar.xz"
    )
)

PROVIDER_METADATA = (
    PROVIDER_OUT
    / "provider.json"
)

PROVIDER_CHECKSUMS = (
    PROVIDER_OUT
    / "SHA256SUMS"
)

EXPECTED_RUNTIME = {
    "initramfs.cpio":
        (
            "b35a6497880950cc0eb28bffc60077f6"
            "4b7b05621fb8cc42b25773dedbdbce35"
        ),

    "initramfs.lz4":
        (
            "ee0deacd5551109330491451034d55b4"
            "0264483b11b01f4b82eae05155eb6095"
        ),

    "treeforge-menu":
        (
            "9e90410312a7f003fef1b3912904f303"
            "5cbbd115fba7511beae274e7558dd110"
        ),
}


def _sha256_bytes(
    payload: bytes,
) -> str:
    return hashlib.sha256(
        payload
    ).hexdigest()


def _sha256_path(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for block in iter(
            lambda: stream.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def _accepted_payloads() -> dict[str, bytes]:
    verify_runtime()

    paths = {
        "initramfs.cpio":
            RAW_INITRAMFS,

        "initramfs.lz4":
            COMPRESSED_INITRAMFS,

        "treeforge-menu":
            MENU_BINARY,
    }

    payloads = {}

    for name, path in paths.items():
        if not path.is_file():
            raise TreeForgeBootstrapProviderError(
                f"accepted runtime file "
                f"missing: {path}"
            )

        actual = _sha256_path(
            path
        )

        expected = (
            EXPECTED_RUNTIME[
                name
            ]
        )

        if actual != expected:
            raise TreeForgeBootstrapProviderError(
                "accepted runtime identity "
                f"changed for {name}: "
                f"{actual} != {expected}"
            )

        payloads[
            name
        ] = path.read_bytes()

    return payloads


def _provider_metadata(
    payloads: dict[str, bytes],
) -> bytes:
    metadata = {
        "schema": 1,
        "provider":
            PROVIDER_NAME,
        "variant":
            PROVIDER_VARIANT,
        "repository":
            "TreeForgeAOSP/treeforge_bootstrap",
        "role":
            "persistent-installed-bootstrap",
        "device":
            "tangorpro",
        "platform":
            "android-15",
        "menu_identity":
            "TreeForge Boot Manager",
        "signed_image":
            False,
        "signing_owner":
            "downstream_consumer",
        "payload": {
            name: {
                "bytes":
                    len(payload),
                "sha256":
                    _sha256_bytes(
                        payload
                    ),
            }
            for name, payload
            in sorted(
                payloads.items()
            )
        },
        "low_level_runtime_abi": {
            "treeforge_bootstrap_framebuffer":
                "v1",
            "first_stage_handoff":
                "v1",
        },
    }

    return (
        json.dumps(
            metadata,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode(
        "utf-8"
    )


def _checksums(
    files: dict[str, bytes],
) -> bytes:
    lines = []

    for name in sorted(
        files
    ):
        lines.append(
            _sha256_bytes(
                files[name]
            )
            + "  "
            + name
        )

    return (
        "\n".join(lines)
        + "\n"
    ).encode(
        "utf-8"
    )


def _add_directory(
    archive: tarfile.TarFile,
    name: str,
) -> None:
    info = tarfile.TarInfo(
        name.rstrip("/")
        + "/"
    )

    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.size = 0

    archive.addfile(
        info
    )


def _add_file(
    archive: tarfile.TarFile,
    name: str,
    payload: bytes,
    *,
    executable: bool = False,
) -> None:
    info = tarfile.TarInfo(
        name
    )

    info.type = tarfile.REGTYPE

    info.mode = (
        0o755
        if executable
        else 0o644
    )

    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.size = len(
        payload
    )

    archive.addfile(
        info,
        io.BytesIO(
            payload
        ),
    )


def package_provider() -> Path:
    payloads = (
        _accepted_payloads()
    )

    metadata = (
        _provider_metadata(
            payloads
        )
    )

    checksum_inputs = {
        "payload/initramfs.cpio":
            payloads[
                "initramfs.cpio"
            ],

        "payload/initramfs.lz4":
            payloads[
                "initramfs.lz4"
            ],

        "payload/bin/treeforge-menu":
            payloads[
                "treeforge-menu"
            ],

        "metadata/provider.json":
            metadata,
    }

    checksums = _checksums(
        checksum_inputs
    )

    PROVIDER_OUT.mkdir(
        parents=True,
        exist_ok=True,
    )

    PROVIDER_METADATA.write_bytes(
        metadata
    )

    PROVIDER_CHECKSUMS.write_bytes(
        checksums
    )

    if PROVIDER_ARCHIVE.exists():
        PROVIDER_ARCHIVE.unlink()

    root = PROVIDER_ROOT_NAME

    with tarfile.open(
        PROVIDER_ARCHIVE,
        mode="w:xz",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        for directory in (
            root,
            f"{root}/payload",
            f"{root}/payload/bin",
            f"{root}/metadata",
        ):
            _add_directory(
                archive,
                directory,
            )

        _add_file(
            archive,
            f"{root}/payload/initramfs.cpio",
            payloads[
                "initramfs.cpio"
            ],
        )

        _add_file(
            archive,
            f"{root}/payload/initramfs.lz4",
            payloads[
                "initramfs.lz4"
            ],
        )

        _add_file(
            archive,
            f"{root}/payload/bin/treeforge-menu",
            payloads[
                "treeforge-menu"
            ],
            executable=True,
        )

        _add_file(
            archive,
            f"{root}/metadata/provider.json",
            metadata,
        )

        _add_file(
            archive,
            f"{root}/SHA256SUMS",
            checksums,
        )

    print(
        "TreeForge Bootstrap Provider"
    )
    print(
        "============================"
    )
    print()
    print(
        f"Archive:       "
        f"{PROVIDER_ARCHIVE}"
    )
    print(
        f"Archive bytes: "
        f"{PROVIDER_ARCHIVE.stat().st_size}"
    )
    print(
        f"Archive SHA:   "
        f"{_sha256_path(PROVIDER_ARCHIVE)}"
    )
    print()
    print(
        "SIGNED_IMAGE=NO"
    )
    print(
        "SIGNING_OWNER=DOWNSTREAM_CONSUMER"
    )
    print(
        "TREEFORGE_BOOTSTRAP_PROVIDER_PACKAGE=PASS"
    )

    return PROVIDER_ARCHIVE


def verify_provider() -> Path:
    if not PROVIDER_ARCHIVE.is_file():
        raise TreeForgeBootstrapProviderError(
            "provider archive is missing: "
            f"{PROVIDER_ARCHIVE}"
        )

    expected_members = (
        f"{PROVIDER_ROOT_NAME}",
        f"{PROVIDER_ROOT_NAME}/payload",
        f"{PROVIDER_ROOT_NAME}/payload/bin",
        f"{PROVIDER_ROOT_NAME}/metadata",
        (
            f"{PROVIDER_ROOT_NAME}/"
            "payload/initramfs.cpio"
        ),
        (
            f"{PROVIDER_ROOT_NAME}/"
            "payload/initramfs.lz4"
        ),
        (
            f"{PROVIDER_ROOT_NAME}/"
            "payload/bin/treeforge-menu"
        ),
        (
            f"{PROVIDER_ROOT_NAME}/"
            "metadata/provider.json"
        ),
        (
            f"{PROVIDER_ROOT_NAME}/"
            "SHA256SUMS"
        ),
    )

    with tarfile.open(
        PROVIDER_ARCHIVE,
        mode="r:xz",
    ) as archive:
        members = (
            archive.getmembers()
        )

        names = tuple(
            member.name
            for member in members
        )

        if names != expected_members:
            raise TreeForgeBootstrapProviderError(
                "provider member contract "
                f"changed: {names}"
            )

        for member in members:
            if member.uid != 0:
                raise TreeForgeBootstrapProviderError(
                    "provider uid is not deterministic"
                )

            if member.gid != 0:
                raise TreeForgeBootstrapProviderError(
                    "provider gid is not deterministic"
                )

            if member.mtime != 0:
                raise TreeForgeBootstrapProviderError(
                    "provider mtime is not deterministic"
                )

        def read_member(
            relative: str,
        ) -> bytes:
            member = archive.getmember(
                f"{PROVIDER_ROOT_NAME}/"
                + relative
            )

            stream = archive.extractfile(
                member
            )

            if stream is None:
                raise TreeForgeBootstrapProviderError(
                    f"provider file unreadable: "
                    f"{relative}"
                )

            return stream.read()

        raw = read_member(
            "payload/initramfs.cpio"
        )

        compressed = read_member(
            "payload/initramfs.lz4"
        )

        menu = read_member(
            "payload/bin/treeforge-menu"
        )

        metadata_bytes = read_member(
            "metadata/provider.json"
        )

        checksums = read_member(
            "SHA256SUMS"
        )

    actual = {
        "initramfs.cpio":
            _sha256_bytes(
                raw
            ),
        "initramfs.lz4":
            _sha256_bytes(
                compressed
            ),
        "treeforge-menu":
            _sha256_bytes(
                menu
            ),
    }

    for name, wanted in (
        EXPECTED_RUNTIME.items()
    ):
        if actual[name] != wanted:
            raise TreeForgeBootstrapProviderError(
                "archive runtime identity "
                f"changed for {name}"
            )

    if (
        compressed[:4]
        != b"\x02\x21\x4c\x18"
    ):
        raise TreeForgeBootstrapProviderError(
            "archive LZ4 framing changed"
        )

    metadata = json.loads(
        metadata_bytes.decode(
            "utf-8"
        )
    )

    if (
        metadata.get(
            "menu_identity"
        )
        != "TreeForge Boot Manager"
    ):
        raise TreeForgeBootstrapProviderError(
            "provider menu identity changed"
        )

    if (
        metadata.get(
            "signed_image"
        )
        is not False
    ):
        raise TreeForgeBootstrapProviderError(
            "provider unexpectedly owns signing"
        )

    if (
        metadata.get(
            "signing_owner"
        )
        != "downstream_consumer"
    ):
        raise TreeForgeBootstrapProviderError(
            "provider signing ownership changed"
        )

    expected_checksums = (
        _checksums(
            {
                "payload/initramfs.cpio":
                    raw,

                "payload/initramfs.lz4":
                    compressed,

                "payload/bin/treeforge-menu":
                    menu,

                "metadata/provider.json":
                    metadata_bytes,
            }
        )
    )

    if checksums != expected_checksums:
        raise TreeForgeBootstrapProviderError(
            "provider SHA256SUMS mismatch"
        )

    print(
        "PROVIDER_NAME="
        f"{PROVIDER_NAME}"
    )
    print(
        "PROVIDER_VARIANT="
        f"{PROVIDER_VARIANT}"
    )
    print(
        "VISIBLE_MENU_IDENTITY="
        "TreeForge Boot Manager"
    )
    print(
        "TREEFORGE_BOOTSTRAP_RUNTIME_ABI="
        "V1"
    )
    print(
        "SIGNED_IMAGE=NO"
    )
    print(
        "SIGNING_OWNER=DOWNSTREAM_CONSUMER"
    )
    print(
        f"PROVIDER_ARCHIVE_SHA256="
        f"{_sha256_path(PROVIDER_ARCHIVE)}"
    )
    print(
        "TREEFORGE_BOOTSTRAP_PROVIDER_VERIFY=PASS"
    )

    return PROVIDER_ARCHIVE
