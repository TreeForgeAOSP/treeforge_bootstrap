from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from .host_providers import ensure_host_tool

from .kernel_provider import (
    EXPECTED_KERNEL_BYTES,
    EXPECTED_KERNEL_SHA256,
    KERNEL_ASSET,
    KERNEL_RELEASE_TAG,
    KERNEL_REPOSITORY,
    ensure_bootstrap_kernel,
)

from .paths import (
    OUT,
    REPOSITORY_ROOT,
    WORK,
)

from .runtime import verify_runtime


class TreeForgeBootstrapImageError(
    RuntimeError
):
    pass


IMAGE_OUT = (
    OUT
    / "image"
)

IMAGE_WORK = (
    WORK
    / "image"
)

OUTPUT_BOOT_IMAGE = (
    IMAGE_OUT
    / "boot.img"
)

OUTPUT_IMAGE = (
    IMAGE_OUT
    / "init_boot.img"
)

OUTPUT_METADATA = (
    IMAGE_OUT
    / "image.json"
)

RUNTIME_RAMDISK = (
    OUT
    / "runtime"
    / "initramfs.lz4"
)


AOSP_PRODUCT_OUT = (
    REPOSITORY_ROOT.parent
    / "treeforge"
    / "aosp"
    / "out"
    / "target"
    / "product"
    / "tangorpro"
)

SOURCE_INIT_BOOT = (
    AOSP_PRODUCT_OUT
    / "init_boot.img"
)

SOURCE_VBMETA = (
    AOSP_PRODUCT_OUT
    / "vbmeta.img"
)

AOSP_AVB_ROOT = (
    REPOSITORY_ROOT.parent
    / "treeforge"
    / "aosp"
    / "external"
    / "avb"
    / "test"
    / "data"
)

SIGNING_KEY = (
    AOSP_AVB_ROOT
    / "testkey_rsa2048.pem"
)


EXPECTED_SOURCE_SHA256 = (
    "0c00f8912debab670395355722b7dc9e8"
    "519b0d260b81521093ea0a3cd5a4203"
)

EXPECTED_SOURCE_VBMETA_SHA256 = (
    "4855a1b8f76a417b057c7ab0e326c321"
    "3d6653f21172b8c2861c5dc49a101064"
)

EXPECTED_KEY_SHA256 = (
    "f1d5765a2bdfb92fb08aee021107c7ac"
    "1a7a3f590dafd853771c85375ef0fbd7"
)

EXPECTED_PUBLIC_KEY_SHA1 = (
    "cdbb77177f731920bbe0a0f94f84d903"
    "8ae0617d"
)


INIT_BOOT_PARTITION_NAME = (
    "init_boot"
)

INIT_BOOT_PARTITION_SIZE = (
    8388608
)

BOOT_PARTITION_NAME = "boot"

BOOT_PARTITION_SIZE = (
    67108864
)

ALGORITHM = (
    "SHA256_RSA2048"
)

ROLLBACK_INDEX = (
    1746403200
)

INIT_BOOT_SALT = (
    "19da436f1331dc5782f956e67a0b7daa"
    "6548f7a01537056159fe114225adb679"
    "b86f168d310f1f03cadfc3db8ed8c57"
    "787e741abbb24fdcb4dd663c1117ccbb8"
)

BOOT_SALT = (
    "cbc9c29eb6c742b8b7b135aa200dc237"
    "64e17aad7b1be3d0301ce55a0ce845de"
)

PROP_OS_VERSION = (
    "com.android.build.init_boot.os_version:15"
)

PROP_FINGERPRINT = (
    "com.android.build.init_boot.fingerprint:"
    "Android/aosp_tangorpro/tangorpro:15/"
    "BP1A.250505.005.D1/"
    "eng.skelit:userdebug/test-keys"
)

PROP_SECURITY_PATCH = (
    "com.android.build.init_boot.security_patch:"
    "2025-05-05"
)


def _sha256(
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


def _sha1(
    path: Path,
) -> str:
    digest = hashlib.sha1()

    with path.open("rb") as stream:
        for block in iter(
            lambda: stream.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def _run(
    command: list[str],
) -> str:
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise TreeForgeBootstrapImageError(
            "command failed:\n"
            + " ".join(command)
            + "\n\n"
            + result.stdout
        )

    return result.stdout


def _validate_inputs(
    *,
    source_init_boot: Path | None = None,
    source_vbmeta: Path | None = None,
) -> None:
    resolved_source_init_boot = (
        SOURCE_INIT_BOOT
        if source_init_boot is None
        else source_init_boot
    )

    resolved_source_vbmeta = (
        SOURCE_VBMETA
        if source_vbmeta is None
        else source_vbmeta
    )

    verify_runtime()

    if not RUNTIME_RAMDISK.is_file():
        raise TreeForgeBootstrapImageError(
            "accepted runtime ramdisk missing: "
            f"{RUNTIME_RAMDISK}"
        )

    if not resolved_source_init_boot.is_file():
        raise TreeForgeBootstrapImageError(
            "locked AOSP tangorpro init_boot "
            "missing: "
            f"{resolved_source_init_boot}"
        )

    source_sha = _sha256(
        resolved_source_init_boot
    )

    if (
        source_init_boot is None
        and source_sha
        != EXPECTED_SOURCE_SHA256
    ):
        raise TreeForgeBootstrapImageError(
            "locked AOSP tangorpro "
            "init_boot identity changed: "
            f"{source_sha}"
        )

    if not resolved_source_vbmeta.is_file():
        raise TreeForgeBootstrapImageError(
            "locked AOSP tangorpro vbmeta "
            f"missing: {resolved_source_vbmeta}"
        )

    vbmeta_sha = _sha256(
        resolved_source_vbmeta
    )

    if (
        source_vbmeta is None
        and vbmeta_sha
        != EXPECTED_SOURCE_VBMETA_SHA256
    ):
        raise TreeForgeBootstrapImageError(
            "locked AOSP tangorpro vbmeta "
            "identity changed: "
            f"{vbmeta_sha}"
        )

    if not SIGNING_KEY.is_file():
        raise TreeForgeBootstrapImageError(
            "AOSP RSA-2048 AVB key missing: "
            f"{SIGNING_KEY}"
        )

    key_sha = _sha256(
        SIGNING_KEY
    )

    if key_sha != EXPECTED_KEY_SHA256:
        raise TreeForgeBootstrapImageError(
            "AOSP RSA-2048 AVB key "
            "identity changed: "
            f"{key_sha}"
        )


def _verify_public_key(
    avbtool: Path,
) -> None:
    IMAGE_WORK.mkdir(
        parents=True,
        exist_ok=True,
    )

    public_key = (
        IMAGE_WORK
        / "treeforge-bootstrap.avbpubkey"
    )

    if public_key.exists():
        public_key.unlink()

    _run(
        [
            str(avbtool),
            "extract_public_key",
            "--key",
            str(SIGNING_KEY),
            "--output",
            str(public_key),
        ]
    )

    actual = _sha1(
        public_key
    )

    if (
        actual
        != EXPECTED_PUBLIC_KEY_SHA1
    ):
        raise TreeForgeBootstrapImageError(
            "AVB signing public-key "
            "identity changed: "
            f"{actual}"
        )


def _verify_parent_chain(
    avbtool: Path,
    *,
    source_vbmeta: Path | None = None,
) -> None:
    resolved_source_vbmeta = (
        SOURCE_VBMETA
        if source_vbmeta is None
        else source_vbmeta
    )
    info = _run(
        [
            str(avbtool),
            "info_image",
            "--image",
            str(resolved_source_vbmeta),
        ]
    )

    for partition in (
        "boot",
        "init_boot",
    ):
        marker = (
            "Partition Name:          "
            + partition
        )

        index = info.find(
            marker
        )

        if index < 0:
            raise TreeForgeBootstrapImageError(
                "root vbmeta is missing "
                f"{partition} chain"
            )

        block = info[
            index:index + 500
        ]

        key_marker = (
            "Public key (sha1):       "
            + EXPECTED_PUBLIC_KEY_SHA1
        )

        if key_marker not in block:
            raise TreeForgeBootstrapImageError(
                "root vbmeta "
                f"{partition} chain key changed"
            )


def _expected_metadata(
    init_boot_sha: str,
    *,
    source_init_boot: Path | None = None,
    source_vbmeta: Path | None = None,
) -> dict[str, object]:
    resolved_source_init_boot = (
        SOURCE_INIT_BOOT
        if source_init_boot is None
        else source_init_boot
    )

    resolved_source_vbmeta = (
        SOURCE_VBMETA
        if source_vbmeta is None
        else source_vbmeta
    )

    return {
        "schema":
            1,

        "device":
            "tangorpro",

        "platform":
            "android-15",

        "source_family":
            "aosp-tangorpro-"
            "BP1A.250505.005.D1",

        "source_init_boot_sha256":
            _sha256(
                resolved_source_init_boot
            ),

        "source_vbmeta_sha256":
            _sha256(
                resolved_source_vbmeta
            ),

        "runtime_ramdisk_sha256":
            _sha256(
                RUNTIME_RAMDISK
            ),

        "signing_key_sha256":
            EXPECTED_KEY_SHA256,

        "signing_public_key_sha1":
            EXPECTED_PUBLIC_KEY_SHA1,

        "signed_image":
            True,

        "signing_owner":
            "treeforge-bootstrap",

        "vbmeta_rewrite_required":
            False,

        "kernel": {
            "repository":
                KERNEL_REPOSITORY,

            "release_tag":
                KERNEL_RELEASE_TAG,

            "asset":
                KERNEL_ASSET,

            "image_bytes":
                OUTPUT_BOOT_IMAGE.stat().st_size,

            "image_sha256":
                _sha256(
                    OUTPUT_BOOT_IMAGE
                ),
        },

        "init_boot": {
            "partition_name":
                INIT_BOOT_PARTITION_NAME,

            "partition_size":
                INIT_BOOT_PARTITION_SIZE,

            "algorithm":
                ALGORITHM,

            "rollback_index":
                ROLLBACK_INDEX,

            "salt":
                INIT_BOOT_SALT,

            "properties": [
                PROP_OS_VERSION,
                PROP_FINGERPRINT,
                PROP_SECURITY_PATCH,
            ],

            "image_bytes":
                OUTPUT_IMAGE.stat().st_size,

            "image_sha256":
                init_boot_sha,
        },
    }


def build_image(
    *,
    source_init_boot: Path | None = None,
    source_vbmeta: Path | None = None,
) -> Path:
    _validate_inputs(
        source_init_boot=source_init_boot,
        source_vbmeta=source_vbmeta,
    )

    kernel = ensure_bootstrap_kernel()

    if (
        kernel.stat().st_size
        != EXPECTED_KERNEL_BYTES
    ):
        raise TreeForgeBootstrapImageError(
            "released Bootstrap kernel "
            "size changed"
        )

    if (
        _sha256(kernel)
        != EXPECTED_KERNEL_SHA256
    ):
        raise TreeForgeBootstrapImageError(
            "released Bootstrap kernel "
            "identity changed"
        )

    mkbootimg = ensure_host_tool(
        "mkbootimg"
    )

    avbtool = ensure_host_tool(
        "avbtool"
    )

    _verify_public_key(
        avbtool
    )

    _verify_parent_chain(
        avbtool,
        source_vbmeta=source_vbmeta,
    )

    IMAGE_WORK.mkdir(
        parents=True,
        exist_ok=True,
    )

    IMAGE_OUT.mkdir(
        parents=True,
        exist_ok=True,
    )

    unsigned = (
        IMAGE_WORK
        / "init_boot.unsigned.img"
    )

    for path in (
        unsigned,
        OUTPUT_BOOT_IMAGE,
        OUTPUT_IMAGE,
        OUTPUT_METADATA,
    ):
        if path.exists():
            path.unlink()

    shutil.copyfile(
        kernel,
        OUTPUT_BOOT_IMAGE,
    )

    _run(
        [
            str(mkbootimg),
            "--header_version",
            "4",
            "--ramdisk",
            str(RUNTIME_RAMDISK),
            "--output",
            str(unsigned),
        ]
    )

    if unsigned.stat().st_size <= 0:
        raise TreeForgeBootstrapImageError(
            "mkbootimg produced an empty "
            "init_boot image"
        )

    shutil.copyfile(
        unsigned,
        OUTPUT_IMAGE,
    )

    _run(
        [
            str(avbtool),
            "add_hash_footer",

            "--image",
            str(OUTPUT_IMAGE),

            "--partition_name",
            INIT_BOOT_PARTITION_NAME,

            "--partition_size",
            str(INIT_BOOT_PARTITION_SIZE),

            "--algorithm",
            ALGORITHM,

            "--key",
            str(SIGNING_KEY),

            "--rollback_index",
            str(ROLLBACK_INDEX),

            "--salt",
            INIT_BOOT_SALT,

            "--prop",
            PROP_OS_VERSION,

            "--prop",
            PROP_FINGERPRINT,

            "--prop",
            PROP_SECURITY_PATCH,
        ]
    )

    if (
        OUTPUT_IMAGE.stat().st_size
        != INIT_BOOT_PARTITION_SIZE
    ):
        raise TreeForgeBootstrapImageError(
            "signed init_boot partition "
            "size changed: "
            f"{OUTPUT_IMAGE.stat().st_size}"
        )

    init_boot_sha = _sha256(
        OUTPUT_IMAGE
    )

    metadata = _expected_metadata(
        init_boot_sha,
        source_init_boot=source_init_boot,
        source_vbmeta=source_vbmeta,
    )

    OUTPUT_METADATA.write_text(
        json.dumps(
            metadata,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        "TreeForge Bootstrap Image Family"
    )
    print(
        "================================"
    )
    print()

    print(
        f"Boot:       {OUTPUT_BOOT_IMAGE}"
    )
    print(
        f"Boot bytes: {OUTPUT_BOOT_IMAGE.stat().st_size}"
    )
    print(
        f"Boot SHA:   {_sha256(OUTPUT_BOOT_IMAGE)}"
    )

    print()

    print(
        f"Init boot:       {OUTPUT_IMAGE}"
    )
    print(
        f"Init boot bytes: {OUTPUT_IMAGE.stat().st_size}"
    )
    print(
        f"Init boot SHA:   {init_boot_sha}"
    )

    print(
        f"Metadata:        {OUTPUT_METADATA}"
    )

    print()
    print(
        "IMAGE_FAMILY=boot,init_boot"
    )
    print(
        "SIGNED_IMAGE=YES"
    )
    print(
        "SIGNING_OWNER=TREEFORGE_BOOTSTRAP"
    )
    print(
        "VBMETA_REWRITE_REQUIRED=NO"
    )
    print(
        "TREEFORGE_BOOTSTRAP_IMAGE_BUILD=PASS"
    )

    return OUTPUT_IMAGE


def verify_image(
    *,
    source_init_boot: Path | None = None,
    source_vbmeta: Path | None = None,
) -> Path:
    _validate_inputs(
        source_init_boot=source_init_boot,
        source_vbmeta=source_vbmeta,
    )

    kernel = ensure_bootstrap_kernel()

    if not OUTPUT_BOOT_IMAGE.is_file():
        raise TreeForgeBootstrapImageError(
            "TreeForge Bootstrap boot image "
            f"missing: {OUTPUT_BOOT_IMAGE}"
        )

    if not OUTPUT_IMAGE.is_file():
        raise TreeForgeBootstrapImageError(
            "TreeForge Bootstrap init_boot "
            f"missing: {OUTPUT_IMAGE}"
        )

    if not OUTPUT_METADATA.is_file():
        raise TreeForgeBootstrapImageError(
            "TreeForge Bootstrap image "
            f"metadata missing: {OUTPUT_METADATA}"
        )

    if (
        OUTPUT_BOOT_IMAGE.stat().st_size
        != BOOT_PARTITION_SIZE
    ):
        raise TreeForgeBootstrapImageError(
            "boot image size changed: "
            f"{OUTPUT_BOOT_IMAGE.stat().st_size}"
        )

    boot_sha = _sha256(
        OUTPUT_BOOT_IMAGE
    )

    if boot_sha != EXPECTED_KERNEL_SHA256:
        raise TreeForgeBootstrapImageError(
            "output boot image identity "
            "changed: "
            f"{boot_sha}"
        )

    if (
        _sha256(kernel)
        != boot_sha
    ):
        raise TreeForgeBootstrapImageError(
            "output boot image no longer "
            "matches released Bootstrap kernel"
        )

    if (
        OUTPUT_IMAGE.stat().st_size
        != INIT_BOOT_PARTITION_SIZE
    ):
        raise TreeForgeBootstrapImageError(
            "init_boot image size changed: "
            f"{OUTPUT_IMAGE.stat().st_size}"
        )

    avbtool = ensure_host_tool(
        "avbtool"
    )

    unpack_bootimg = ensure_host_tool(
        "unpack_bootimg"
    )

    _verify_public_key(
        avbtool
    )

    _verify_parent_chain(
        avbtool,
        source_vbmeta=source_vbmeta,
    )

    _run(
        [
            str(avbtool),
            "verify_image",
            "--image",
            str(OUTPUT_BOOT_IMAGE),
            "--key",
            str(SIGNING_KEY),
        ]
    )

    _run(
        [
            str(avbtool),
            "verify_image",
            "--image",
            str(OUTPUT_IMAGE),
            "--key",
            str(SIGNING_KEY),
        ]
    )

    boot_info = _run(
        [
            str(avbtool),
            "info_image",
            "--image",
            str(OUTPUT_BOOT_IMAGE),
        ]
    )

    required_boot_info = (
        "Image size:               "
        "67108864 bytes",

        "Original image size:      "
        "16506880 bytes",

        "Public key (sha1):        "
        + EXPECTED_PUBLIC_KEY_SHA1,

        "Algorithm:                "
        + ALGORITHM,

        "Rollback Index:           "
        + str(ROLLBACK_INDEX),

        "Partition Name:        boot",

        "Salt:                  "
        + BOOT_SALT,

        "com.android.build.boot."
        "os_version -> '15'",

        "com.android.build.boot."
        "security_patch -> "
        "'2025-05-05'",
    )

    for marker in required_boot_info:
        if marker not in boot_info:
            raise TreeForgeBootstrapImageError(
                "Bootstrap boot AVB "
                "contract changed: "
                f"{marker}"
            )

    init_boot_info = _run(
        [
            str(avbtool),
            "info_image",
            "--image",
            str(OUTPUT_IMAGE),
        ]
    )

    required_init_boot_info = (
        "Image size:               "
        "8388608 bytes",

        "Public key (sha1):        "
        + EXPECTED_PUBLIC_KEY_SHA1,

        "Algorithm:                "
        + ALGORITHM,

        "Rollback Index:           "
        + str(ROLLBACK_INDEX),

        "Partition Name:        "
        + INIT_BOOT_PARTITION_NAME,

        "Salt:                  "
        + INIT_BOOT_SALT,

        "com.android.build."
        "init_boot.os_version -> '15'",

        "com.android.build."
        "init_boot.security_patch "
        "-> '2025-05-05'",
    )

    for marker in required_init_boot_info:
        if marker not in init_boot_info:
            raise TreeForgeBootstrapImageError(
                "signed init_boot AVB "
                "contract changed: "
                f"{marker}"
            )

    boot_unpack = (
        IMAGE_WORK
        / "verify-boot-unpack"
    )

    if boot_unpack.exists():
        shutil.rmtree(
            boot_unpack
        )

    boot_unpack.mkdir(
        parents=True
    )

    boot_unpack_output = _run(
        [
            str(unpack_bootimg),
            "--boot_img",
            str(OUTPUT_BOOT_IMAGE),
            "--out",
            str(boot_unpack),
        ]
    )

    kernel_size = None

    for line in boot_unpack_output.splitlines():
        if line.startswith("kernel_size:"):
            raw_size = line.split(
                ":",
                1,
            )[1].strip()

            try:
                kernel_size = int(raw_size)
            except ValueError as exc:
                raise TreeForgeBootstrapImageError(
                    "Bootstrap boot kernel size "
                    "is not an integer: "
                    f"{raw_size}"
                ) from exc

            break

    if kernel_size is None or kernel_size <= 0:
        raise TreeForgeBootstrapImageError(
            "Bootstrap boot kernel is "
            "missing or empty"
        )

    unpacked_kernel = (
        boot_unpack
        / "kernel"
    )

    if not unpacked_kernel.is_file():
        raise TreeForgeBootstrapImageError(
            "unpacked Bootstrap kernel missing"
        )

    unpacked_kernel_size = (
        unpacked_kernel.stat().st_size
    )

    if unpacked_kernel_size != kernel_size:
        raise TreeForgeBootstrapImageError(
            "Bootstrap kernel header/file "
            "size mismatch: "
            f"header={kernel_size} "
            f"file={unpacked_kernel_size}"
        )

    for marker in (
        "ramdisk size: 0",
        "boot image header version: 4",
        "boot.img signature size: 0",
    ):
        if marker not in boot_unpack_output:
            raise TreeForgeBootstrapImageError(
                "Bootstrap boot structure "
                "changed: "
                f"{marker}"
            )

    verify_unpack = (
        IMAGE_WORK
        / "verify-init-boot-unpack"
    )

    if verify_unpack.exists():
        shutil.rmtree(
            verify_unpack
        )

    verify_unpack.mkdir(
        parents=True
    )

    unpack_output = _run(
        [
            str(unpack_bootimg),
            "--boot_img",
            str(OUTPUT_IMAGE),
            "--out",
            str(verify_unpack),
        ]
    )

    for marker in (
        "kernel_size: 0",
        "boot image header version: 4",
        "boot.img signature size: 0",
    ):
        if marker not in unpack_output:
            raise TreeForgeBootstrapImageError(
                "init_boot structural "
                "contract changed: "
                f"{marker}"
            )

    unpacked_ramdisk = (
        verify_unpack
        / "ramdisk"
    )

    if not unpacked_ramdisk.is_file():
        raise TreeForgeBootstrapImageError(
            "unpacked init_boot ramdisk "
            "missing"
        )

    runtime_sha = _sha256(
        RUNTIME_RAMDISK
    )

    unpacked_sha = _sha256(
        unpacked_ramdisk
    )

    if runtime_sha != unpacked_sha:
        raise TreeForgeBootstrapImageError(
            "signed init_boot ramdisk "
            "does not match accepted "
            "TreeForge runtime: "
            f"{unpacked_sha} != "
            f"{runtime_sha}"
        )

    init_boot_sha = _sha256(
        OUTPUT_IMAGE
    )

    expected_metadata = (
        _expected_metadata(
            init_boot_sha,
            source_init_boot=source_init_boot,
            source_vbmeta=source_vbmeta,
        )
    )

    try:
        actual_metadata = json.loads(
            OUTPUT_METADATA.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        raise TreeForgeBootstrapImageError(
            "unable to read image "
            "metadata"
        ) from exc

    if (
        actual_metadata
        != expected_metadata
    ):
        raise TreeForgeBootstrapImageError(
            "image metadata contract "
            "changed"
        )

    print(
        "TreeForge Bootstrap Image Family Verify"
    )
    print(
        "======================================="
    )
    print()

    print(
        f"Boot:          {OUTPUT_BOOT_IMAGE}"
    )
    print(
        f"Boot bytes:    {OUTPUT_BOOT_IMAGE.stat().st_size}"
    )
    print(
        f"Boot SHA:      {boot_sha}"
    )

    print()

    print(
        f"Init boot:     {OUTPUT_IMAGE}"
    )
    print(
        f"Init bytes:    {OUTPUT_IMAGE.stat().st_size}"
    )
    print(
        f"Init SHA:      {init_boot_sha}"
    )
    print(
        f"Ramdisk SHA:   {runtime_sha}"
    )

    print(
        "Public key:    "
        + EXPECTED_PUBLIC_KEY_SHA1
    )

    print()
    print(
        "IMAGE_FAMILY=boot,init_boot"
    )
    print(
        "BOOT_HEADER_VERSION=4"
    )
    print(
        "INIT_BOOT_HEADER_VERSION=4"
    )
    print(
        "SIGNED_IMAGE=YES"
    )
    print(
        "SIGNING_OWNER=TREEFORGE_BOOTSTRAP"
    )
    print(
        "BOOT_VBMETA_CHAIN_MATCH=PASS"
    )
    print(
        "INIT_BOOT_VBMETA_CHAIN_MATCH=PASS"
    )
    print(
        "VBMETA_REWRITE_REQUIRED=NO"
    )
    print(
        "TREEFORGE_BOOTSTRAP_IMAGE_VERIFY=PASS"
    )

    return OUTPUT_IMAGE
