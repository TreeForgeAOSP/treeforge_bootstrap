from __future__ import annotations

from .version import runtime_abi_version

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

# TREEFORGE_MANAGER_BOOTSTRAP_UPDATE_V1
#
# This is a release-side contract only. TreeForge Manager and the
# privileged on-device updater are implemented separately later.
#
# The complete init_boot image is never a Bootstrap release asset.
# Manager consumes this manifest plus the released runtime provider
# and reconstructs the currently installed init_boot locally.
MANAGER_UPDATE_MANIFEST = (
    PROVIDER_OUT
    / (
        PROVIDER_ROOT_NAME
        + "-update-manifest.json"
    )
)

VERSION_FILE = (
    Path(__file__).resolve().parents[2]
    / "VERSION"
)

SUPPORTED_KERNEL_ABI = (
    "6.1.99-android14-11-"
    "g3c76c2d71bb3-ab13202328"
)

EXPECTED_RUNTIME = {
    "initramfs.cpio": (
            "d98b8447561330bccd8caf7ee4a4748c"
            "9e56a18fc985efbe60f4bede8cdebc4a"
        ),

    "initramfs.lz4": (
            "0f2de3768b8f28d8ea74d0a64a7c194a"
            "c4f8bc428ae859fc334bfa1d42c57ee7"
        ),

    "treeforge-menu": (
            "79384e134f8be1812a7cd0616073e8d9"
            "d3d3fc201bfb943f84c2233f8def5fad"
        ),

}


def _component_versions() -> dict[str, str]:
    if not VERSION_FILE.is_file():
        raise TreeForgeBootstrapProviderError(
            f"VERSION metadata missing: {VERSION_FILE}"
        )

    values = {}

    for raw in VERSION_FILE.read_text(
        encoding="utf-8"
    ).splitlines():
        line = raw.strip()

        if (
            not line
            or line.startswith("#")
        ):
            continue

        if "=" not in line:
            raise TreeForgeBootstrapProviderError(
                f"invalid VERSION record: {line}"
            )

        key, value = line.split(
            "=",
            1,
        )

        values[key.strip()] = value.strip()

    required = {
        "bootstrap":
            "TREEFORGE_BOOTSTRAP_VERSION",
        "boot_menu":
            "TREEFORGE_BOOT_MENU_VERSION",
        "boot_manager":
            "TREEFORGE_BOOT_MANAGER_VERSION",
        "runtime_abi":
            "TREEFORGE_RUNTIME_ABI_VERSION",
        "framebuffer":
            "TREEFORGE_FRAMEBUFFER_VERSION",
    }

    result = {}

    for name, key in required.items():
        value = values.get(key)

        if not value:
            raise TreeForgeBootstrapProviderError(
                f"VERSION field missing: {key}"
            )

        result[name] = value

    return result


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
    versions = _component_versions()

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
        "components": {
            "bootstrap":
                versions["bootstrap"],
            "boot_menu":
                versions["boot_menu"],
            "boot_manager":
                versions["boot_manager"],
            "runtime_abi":
                versions["runtime_abi"],
            "framebuffer":
                versions["framebuffer"],
        },
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
            "version":
                runtime_abi_version(),
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


def _manager_update_metadata() -> bytes:
    if not PROVIDER_ARCHIVE.is_file():
        raise TreeForgeBootstrapProviderError(
            "runtime provider must be packaged before "
            "the Manager update manifest"
        )

    versions = _component_versions()

    metadata = {
        "schema":
            "treeforge.manager.update.v1",

        "component":
            "bootstrap",

        "release":
            versions["bootstrap"],

        "device":
            "tangorpro",

        "platform":
            "android15",

        "kernel_abi":
            SUPPORTED_KERNEL_ABI,

        "applicability": {
            "requires_treeforge_installed":
                True,

            "install_state_schema":
                "treeforge.manager.install-state.v1",

            "device":
                "tangorpro",

            "accepted_kernel_abis": [
                SUPPORTED_KERNEL_ABI
            ],
        },

        "artifacts": {
            "runtime": {
                "filename":
                    PROVIDER_ARCHIVE.name,

                "sha256":
                    _sha256_path(
                        PROVIDER_ARCHIVE
                    ),

                "identity_scope":
                    "release-download",

                "bytes":
                    PROVIDER_ARCHIVE.stat().st_size,

                "redistribution":
                    "public",

                "install_realization":
                    "as-downloaded",
            },
        },

        "partitions": {
            "boot": {
                "operation":
                    "preserve",
            },

            "init_boot": {
                "operation":
                    "reconstruct_current",

                "source":
                    "current-installed",

                "replacements": [
                    {
                        "path":
                            "ramdisk",

                        "artifact":
                            "runtime",
                    }
                ],

                "signing":
                    "owner-avb-local",

                "avb_parent":
                    "vbmeta",

                "avb_parent_action":
                    "preserve-chain",
            },

            "vendor_boot": {
                "operation":
                    "preserve",
            },

            "vendor_kernel_boot": {
                "operation":
                    "preserve",
            },

            "vendor_dlkm": {
                "operation":
                    "preserve",
            },

            "system_dlkm": {
                "operation":
                    "preserve",
            },

            "vbmeta": {
                "operation":
                    "preserve",
            },

            "vbmeta_system": {
                "operation":
                    "preserve",
            },

            "vbmeta_vendor": {
                "operation":
                    "preserve",
            },
        },

        "reconstruction": {
            "carrier_source":
                "current-installed",

            "proprietary_payload_distribution":
                False,

            "binary_patch_deltas":
                False,

            "supported_operations": [
                "preserve",
                "replace_whole",
                "reconstruct_current",
            ],
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


def _verify_manager_update_manifest() -> None:
    if not MANAGER_UPDATE_MANIFEST.is_file():
        raise TreeForgeBootstrapProviderError(
            "Manager update manifest missing: "
            f"{MANAGER_UPDATE_MANIFEST}"
        )

    try:
        metadata = json.loads(
            MANAGER_UPDATE_MANIFEST.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise TreeForgeBootstrapProviderError(
            "Manager update manifest unreadable"
        ) from exc

    versions = _component_versions()

    expected = {
        "schema":
            "treeforge.manager.update.v1",

        "component":
            "bootstrap",

        "release":
            versions["bootstrap"],

        "device":
            "tangorpro",

        "kernel_abi":
            SUPPORTED_KERNEL_ABI,
    }

    for key, wanted in expected.items():
        actual = metadata.get(key)

        if actual != wanted:
            raise TreeForgeBootstrapProviderError(
                "Manager update manifest "
                f"{key} changed: "
                f"{actual!r} != {wanted!r}"
            )

    artifacts = metadata.get(
        "artifacts",
        {}
    )

    runtime = artifacts.get(
        "runtime",
        {}
    )

    if (
        runtime.get("filename")
        != PROVIDER_ARCHIVE.name
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager runtime filename changed"
        )

    if (
        runtime.get("sha256")
        != _sha256_path(
            PROVIDER_ARCHIVE
        )
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager runtime provider SHA changed"
        )

    if (
        runtime.get("bytes")
        != PROVIDER_ARCHIVE.stat().st_size
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager runtime provider size changed"
        )

    if (
        runtime.get("identity_scope")
        != "release-download"
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager runtime identity scope changed"
        )

    if (
        runtime.get("install_realization")
        != "as-downloaded"
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager runtime installation "
            "realization changed"
        )

    partitions = metadata.get(
        "partitions",
        {}
    )

    init_boot = partitions.get(
        "init_boot",
        {}
    )

    if (
        init_boot.get("operation")
        != "reconstruct_current"
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager init_boot update operation changed"
        )

    if (
        init_boot.get("source")
        != "current-installed"
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager init_boot source changed"
        )

    if (
        init_boot.get("signing")
        != "owner-avb-local"
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager init_boot signing ownership changed"
        )

    if (
        init_boot.get("avb_parent")
        != "vbmeta"
        or
        init_boot.get("avb_parent_action")
        != "preserve-chain"
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager init_boot AVB contract changed"
        )

    replacements = init_boot.get(
        "replacements"
    )

    if replacements != [
        {
            "artifact": "runtime",
            "path": "ramdisk",
        }
    ]:
        raise TreeForgeBootstrapProviderError(
            "Manager init_boot replacement "
            "contract changed"
        )

    for name in (
        "boot",
        "vendor_boot",
        "vendor_kernel_boot",
        "vendor_dlkm",
        "system_dlkm",
        "vbmeta",
        "vbmeta_system",
        "vbmeta_vendor",
    ):
        operation = (
            partitions.get(
                name,
                {}
            ).get(
                "operation"
            )
        )

        if operation != "preserve":
            raise TreeForgeBootstrapProviderError(
                "Manager partition unexpectedly "
                f"modified: {name}"
            )

    reconstruction = metadata.get(
        "reconstruction",
        {}
    )

    if (
        reconstruction.get(
            "carrier_source"
        )
        != "current-installed"
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager carrier source changed"
        )

    if (
        reconstruction.get(
            "proprietary_payload_distribution"
        )
        is not False
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager contract unexpectedly "
            "distributes proprietary carriers"
        )

    if (
        reconstruction.get(
            "binary_patch_deltas"
        )
        is not False
    ):
        raise TreeForgeBootstrapProviderError(
            "Manager contract unexpectedly "
            "uses binary carrier deltas"
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

    MANAGER_UPDATE_MANIFEST.write_bytes(
        _manager_update_metadata()
    )

    _verify_manager_update_manifest()

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
        f"Manager manifest: "
        f"{MANAGER_UPDATE_MANIFEST}"
    )

    print(
        f"Manager manifest SHA: "
        f"{_sha256_path(MANAGER_UPDATE_MANIFEST)}"
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

    _verify_manager_update_manifest()

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
        + runtime_abi_version()
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
        f"MANAGER_UPDATE_MANIFEST="
        f"{MANAGER_UPDATE_MANIFEST}"
    )

    print(
        f"MANAGER_UPDATE_MANIFEST_SHA256="
        f"{_sha256_path(MANAGER_UPDATE_MANIFEST)}"
    )

    print(
        "TREEFORGE_BOOTSTRAP_MANAGER_UPDATE_CONTRACT=PASS"
    )

    print(
        "TREEFORGE_BOOTSTRAP_PROVIDER_VERIFY=PASS"
    )

    return PROVIDER_ARCHIVE
