from __future__ import annotations

import hashlib
import json
import re
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

from .runtime import verify_frozen_runtime


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


INIT_BOOT_PARTITION_NAME = "init_boot"
BOOT_PARTITION_NAME = "boot"


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


def _resolve_signing_key(
    signing_key: Path | None,
) -> Path:
    """
    Resolve an already-unlocked downstream AVB child key.

    TreeForge Bootstrap never creates, persists, encrypts, decrypts,
    or otherwise owns private signing material. Pixel Partitioner /
    Manager owns that lifecycle and supplies the temporary unlocked key.
    """

    if signing_key is None:
        raise TreeForgeBootstrapImageError(
            "an explicit downstream RSA-2048 AVB child key "
            "is required"
        )

    resolved = (
        signing_key
        .expanduser()
        .resolve()
    )

    if not resolved.is_file():
        raise TreeForgeBootstrapImageError(
            "explicit AVB child signing key missing: "
            f"{resolved}"
        )

    return resolved


def _validate_inputs(
    *,
    source_init_boot: Path | None,
    source_vbmeta: Path | None,
    signing_key: Path | None,
) -> tuple[Path, Path, Path]:
    verify_frozen_runtime()

    if not RUNTIME_RAMDISK.is_file():
        raise TreeForgeBootstrapImageError(
            "accepted runtime ramdisk missing: "
            f"{RUNTIME_RAMDISK}"
        )

    if source_init_boot is None:
        raise TreeForgeBootstrapImageError(
            "source init_boot is required; Bootstrap no longer "
            "falls back to a local AOSP checkout"
        )

    if source_vbmeta is None:
        raise TreeForgeBootstrapImageError(
            "source vbmeta is required; Bootstrap no longer "
            "falls back to a local AOSP checkout"
        )

    resolved_source_init_boot = (
        source_init_boot
        .expanduser()
        .resolve()
    )

    resolved_source_vbmeta = (
        source_vbmeta
        .expanduser()
        .resolve()
    )

    if not resolved_source_init_boot.is_file():
        raise TreeForgeBootstrapImageError(
            "source init_boot missing: "
            f"{resolved_source_init_boot}"
        )

    if not resolved_source_vbmeta.is_file():
        raise TreeForgeBootstrapImageError(
            "source vbmeta missing: "
            f"{resolved_source_vbmeta}"
        )

    return (
        resolved_source_init_boot,
        resolved_source_vbmeta,
        _resolve_signing_key(
            signing_key
        ),
    )


def _avb_info(
    avbtool: Path,
    image: Path,
) -> str:
    return _run(
        [
            str(avbtool),
            "info_image",
            "--image",
            str(image),
        ]
    )


def _top_field(
    info: str,
    name: str,
) -> str:
    prefix = name + ":"

    for line in info.splitlines():
        if line.startswith(prefix):
            return line[
                len(prefix):
            ].strip()

    raise TreeForgeBootstrapImageError(
        f"AVB image is missing top-level field: {name}"
    )


def _properties(
    info: str,
) -> tuple[tuple[str, str], ...]:
    result = []

    expression = re.compile(
        r"^\s+Prop: (.*?) -> '(.*)'$"
    )

    for line in info.splitlines():
        match = expression.match(
            line
        )

        if match is not None:
            result.append(
                (
                    match.group(1),
                    match.group(2),
                )
            )

    return tuple(result)


def _hash_descriptor(
    info: str,
) -> dict[str, str]:
    lines = info.splitlines()

    index = None

    for current, line in enumerate(lines):
        if line.strip() == "Hash descriptor:":
            index = current
            break

    if index is None:
        raise TreeForgeBootstrapImageError(
            "AVB image has no hash descriptor"
        )

    wanted = {
        "Image Size",
        "Hash Algorithm",
        "Partition Name",
        "Salt",
        "Flags",
    }

    result = {}

    for line in lines[
        index + 1:
    ]:
        stripped = line.strip()

        if stripped.startswith("Prop:"):
            break

        if (
            stripped.endswith("descriptor:")
            and stripped != "Hash descriptor:"
        ):
            break

        if ":" not in stripped:
            continue

        name, value = stripped.split(
            ":",
            1,
        )

        if name in wanted:
            result[name] = value.strip()

    missing = sorted(
        wanted - set(result)
    )

    if missing:
        raise TreeForgeBootstrapImageError(
            "AVB hash descriptor is incomplete: "
            + ",".join(missing)
        )

    return result


def _hash_contract(
    avbtool: Path,
    image: Path,
    *,
    expected_partition: str,
) -> dict[str, object]:
    info = _avb_info(
        avbtool,
        image,
    )

    descriptor = _hash_descriptor(
        info
    )

    contract = {
        "algorithm":
            _top_field(
                info,
                "Algorithm",
            ),

        "rollback_index":
            _top_field(
                info,
                "Rollback Index",
            ),

        "rollback_index_location":
            _top_field(
                info,
                "Rollback Index Location",
            ),

        "header_flags":
            _top_field(
                info,
                "Flags",
            ),

        "public_key_sha1":
            _top_field(
                info,
                "Public key (sha1)",
            ),

        "hash_algorithm":
            descriptor[
                "Hash Algorithm"
            ],

        "partition_name":
            descriptor[
                "Partition Name"
            ],

        "salt":
            descriptor[
                "Salt"
            ],

        "hash_flags":
            descriptor[
                "Flags"
            ],

        "properties":
            _properties(
                info
            ),
    }

    if (
        contract["partition_name"]
        != expected_partition
    ):
        raise TreeForgeBootstrapImageError(
            "AVB partition identity changed: "
            f"{contract['partition_name']} != "
            f"{expected_partition}"
        )

    if (
        contract["algorithm"]
        != "SHA256_RSA2048"
    ):
        raise TreeForgeBootstrapImageError(
            f"{expected_partition} requires "
            "the RSA-2048 child AVB identity; "
            f"found {contract['algorithm']}"
        )

    if contract["header_flags"] != "0":
        raise TreeForgeBootstrapImageError(
            f"{expected_partition} has unsupported "
            "AVB header flags"
        )

    if contract["hash_flags"] != "0":
        raise TreeForgeBootstrapImageError(
            f"{expected_partition} has unsupported "
            "AVB hash-descriptor flags"
        )

    return contract


def _extract_signing_public_key(
    avbtool: Path,
    signing_key: Path,
) -> tuple[bytes, str]:
    IMAGE_WORK.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = (
        IMAGE_WORK
        / "downstream-child.avbpubkey"
    )

    if output.exists():
        output.unlink()

    _run(
        [
            str(avbtool),
            "extract_public_key",
            "--key",
            str(signing_key),
            "--output",
            str(output),
        ]
    )

    public = output.read_bytes()

    if len(public) < 4:
        raise TreeForgeBootstrapImageError(
            "supplied child AVB public key is truncated"
        )

    bits = int.from_bytes(
        public[:4],
        byteorder="big",
        signed=False,
    )

    if bits != 2048:
        raise TreeForgeBootstrapImageError(
            "Bootstrap boot/init_boot signing requires "
            f"the RSA-2048 owner child key; found RSA-{bits}"
        )

    identity = hashlib.sha1(
        public
    ).hexdigest()

    output.unlink()

    return (
        public,
        identity,
    )


def _chain_key(
    info: str,
    partition: str,
) -> str:
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
        index:index + 800
    ]

    prefix = (
        "Public key (sha1):       "
    )

    for line in block.splitlines():
        stripped = line.strip()

        if stripped.startswith(
            "Public key (sha1):"
        ):
            value = stripped.split(
                ":",
                1,
            )[1].strip()

            if not re.fullmatch(
                r"[0-9a-f]{40}",
                value,
            ):
                raise TreeForgeBootstrapImageError(
                    "invalid root-vbmeta chain key "
                    f"for {partition}: {value}"
                )

            return value

    raise TreeForgeBootstrapImageError(
        "root vbmeta chain is missing "
        f"the {partition} public key"
    )


def _verify_parent_chain(
    avbtool: Path,
    *,
    source_vbmeta: Path,
    signing_public_key_sha1: str,
    require_match: bool,
) -> tuple[str, bool]:
    info = _avb_info(
        avbtool,
        source_vbmeta,
    )

    boot_key = _chain_key(
        info,
        "boot",
    )

    init_boot_key = _chain_key(
        info,
        "init_boot",
    )

    if boot_key != init_boot_key:
        raise TreeForgeBootstrapImageError(
            "source root vbmeta delegates boot and init_boot "
            "to different child AVB identities"
        )

    rewrite_required = (
        boot_key
        != signing_public_key_sha1
    )

    if rewrite_required and require_match:
        raise TreeForgeBootstrapImageError(
            "supplied owner child key does not match the "
            "existing boot/init_boot root-vbmeta chain: "
            f"source={boot_key} "
            f"supplied={signing_public_key_sha1}"
        )

    return (
        boot_key,
        rewrite_required,
    )


def _assert_contract_preserved(
    before: dict[str, object],
    after: dict[str, object],
    *,
    expected_public_key_sha1: str,
) -> None:
    for field in (
        "algorithm",
        "rollback_index",
        "rollback_index_location",
        "header_flags",
        "hash_algorithm",
        "partition_name",
        "salt",
        "hash_flags",
        "properties",
    ):
        if before[field] != after[field]:
            raise TreeForgeBootstrapImageError(
                "AVB contract changed while signing: "
                f"{field}: "
                f"{before[field]} != {after[field]}"
            )

    if (
        after["public_key_sha1"]
        != expected_public_key_sha1
    ):
        raise TreeForgeBootstrapImageError(
            "realized AVB public-key identity does not "
            "match the supplied downstream child key"
        )


def _resign_boot_image(
    image: Path,
    *,
    signing_key: Path,
    signing_public: bytes,
) -> None:
    #
    # Reuse the same payload-preserving owner-signing primitive used
    # by Pixel Partitioner. Import lazily to avoid module import cycles:
    # owner_family -> avb_graph -> image.
    #
    from .owner_family import (
        OwnerFamilyError,
        read_metadata,
        resign,
        sha256 as owner_sha256,
    )

    try:
        (
            _header,
            _descriptors,
            before_offset,
            _footer,
        ) = read_metadata(
            image
        )

        before_payload = owner_sha256(
            image,
            before_offset,
        )

        resign(
            image,
            signing_key,
            signing_public,
            signing_public,
        )

        (
            _header,
            _descriptors,
            after_offset,
            _footer,
        ) = read_metadata(
            image
        )

        after_payload = owner_sha256(
            image,
            after_offset,
        )

    except OwnerFamilyError as exc:
        raise TreeForgeBootstrapImageError(
            "unable to apply the downstream owner child "
            "identity to Bootstrap boot"
        ) from exc

    if (
        before_offset != after_offset
        or before_payload != after_payload
    ):
        raise TreeForgeBootstrapImageError(
            "Bootstrap boot payload changed while "
            "applying the owner AVB identity"
        )


def _add_hash_footer(
    avbtool: Path,
    *,
    image: Path,
    partition_size: int,
    contract: dict[str, object],
    signing_key: Path,
) -> None:
    command = [
        str(avbtool),
        "add_hash_footer",

        "--image",
        str(image),

        "--partition_name",
        str(
            contract[
                "partition_name"
            ]
        ),

        "--partition_size",
        str(partition_size),

        "--algorithm",
        str(
            contract[
                "algorithm"
            ]
        ),

        "--key",
        str(signing_key),

        "--rollback_index",
        str(
            contract[
                "rollback_index"
            ]
        ),

        "--rollback_index_location",
        str(
            contract[
                "rollback_index_location"
            ]
        ),

        "--hash_algorithm",
        str(
            contract[
                "hash_algorithm"
            ]
        ),

        "--salt",
        str(
            contract[
                "salt"
            ]
        ),
    ]

    for key, value in contract[
        "properties"
    ]:
        command.extend(
            [
                "--prop",
                f"{key}:{value}",
            ]
        )

    _run(
        command
    )


def _expected_metadata(
    *,
    boot_sha: str,
    init_boot_sha: str,
    source_init_boot: Path,
    source_vbmeta: Path,
    source_child_public_key_sha1: str,
    signing_public_key_sha1: str,
    source_init_contract: dict[str, object],
    vbmeta_rewrite_required: bool,
) -> dict[str, object]:
    return {
        "schema":
            2,

        "device":
            "tangorpro",

        "platform":
            "android-15",

        "source_family":
            "caller-supplied-device-family",

        "source_init_boot_sha256":
            _sha256(
                source_init_boot
            ),

        "source_vbmeta_sha256":
            _sha256(
                source_vbmeta
            ),

        "source_boot_chain_public_key_sha1":
            source_child_public_key_sha1,

        "runtime_ramdisk_sha256":
            _sha256(
                RUNTIME_RAMDISK
            ),

        "signing_public_key_sha1":
            signing_public_key_sha1,

        "signed_image":
            True,

        "signing_owner":
            "downstream_consumer",

        "vbmeta_rewrite_required":
            vbmeta_rewrite_required,

        "kernel": {
            "repository":
                KERNEL_REPOSITORY,

            "release_tag":
                KERNEL_RELEASE_TAG,

            "asset":
                KERNEL_ASSET,

            "provider_image_sha256":
                EXPECTED_KERNEL_SHA256,

            "realized_image_bytes":
                OUTPUT_BOOT_IMAGE.stat().st_size,

            "realized_image_sha256":
                boot_sha,
        },

        "init_boot": {
            "partition_name":
                source_init_contract[
                    "partition_name"
                ],

            "partition_size":
                source_init_boot.stat().st_size,

            "algorithm":
                source_init_contract[
                    "algorithm"
                ],

            "rollback_index":
                source_init_contract[
                    "rollback_index"
                ],

            "rollback_index_location":
                source_init_contract[
                    "rollback_index_location"
                ],

            "hash_algorithm":
                source_init_contract[
                    "hash_algorithm"
                ],

            "salt":
                source_init_contract[
                    "salt"
                ],

            "properties": [
                f"{key}:{value}"
                for key, value
                in source_init_contract[
                    "properties"
                ]
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
    signing_key: Path | None = None,
    require_parent_match: bool = True,
) -> Path:
    (
        resolved_source_init_boot,
        resolved_source_vbmeta,
        resolved_signing_key,
    ) = _validate_inputs(
        source_init_boot=source_init_boot,
        source_vbmeta=source_vbmeta,
        signing_key=signing_key,
    )

    kernel = ensure_bootstrap_kernel()

    if (
        kernel.stat().st_size
        != EXPECTED_KERNEL_BYTES
    ):
        raise TreeForgeBootstrapImageError(
            "released Bootstrap kernel size changed"
        )

    if (
        _sha256(kernel)
        != EXPECTED_KERNEL_SHA256
    ):
        raise TreeForgeBootstrapImageError(
            "released Bootstrap kernel identity changed"
        )

    mkbootimg = ensure_host_tool(
        "mkbootimg"
    )

    avbtool = ensure_host_tool(
        "avbtool"
    )

    (
        signing_public,
        signing_public_key_sha1,
    ) = _extract_signing_public_key(
        avbtool,
        resolved_signing_key,
    )

    (
        source_child_public_key_sha1,
        vbmeta_rewrite_required,
    ) = _verify_parent_chain(
        avbtool,
        source_vbmeta=(
            resolved_source_vbmeta
        ),
        signing_public_key_sha1=(
            signing_public_key_sha1
        ),
        require_match=(
            require_parent_match
        ),
    )

    source_init_contract = (
        _hash_contract(
            avbtool,
            resolved_source_init_boot,
            expected_partition=(
                INIT_BOOT_PARTITION_NAME
            ),
        )
    )

    if (
        source_init_contract[
            "public_key_sha1"
        ]
        != source_child_public_key_sha1
    ):
        raise TreeForgeBootstrapImageError(
            "source init_boot AVB identity does not match "
            "the root-vbmeta init_boot chain"
        )

    kernel_contract = (
        _hash_contract(
            avbtool,
            kernel,
            expected_partition=(
                BOOT_PARTITION_NAME
            ),
        )
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

    #
    # The published kernel boot image is the immutable payload
    # provider. Replace only its AVB signing identity.
    #
    shutil.copyfile(
        kernel,
        OUTPUT_BOOT_IMAGE,
    )

    _resign_boot_image(
        OUTPUT_BOOT_IMAGE,
        signing_key=(
            resolved_signing_key
        ),
        signing_public=(
            signing_public
        ),
    )

    realized_boot_contract = (
        _hash_contract(
            avbtool,
            OUTPUT_BOOT_IMAGE,
            expected_partition=(
                BOOT_PARTITION_NAME
            ),
        )
    )

    _assert_contract_preserved(
        kernel_contract,
        realized_boot_contract,
        expected_public_key_sha1=(
            signing_public_key_sha1
        ),
    )

    #
    # Construct the TreeForge runtime payload, then inherit the
    # source init_boot AVB contract and sign it with the same child
    # owner identity.
    #
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
            "mkbootimg produced an empty init_boot image"
        )

    shutil.copyfile(
        unsigned,
        OUTPUT_IMAGE,
    )

    _add_hash_footer(
        avbtool,
        image=OUTPUT_IMAGE,
        partition_size=(
            resolved_source_init_boot
            .stat()
            .st_size
        ),
        contract=(
            source_init_contract
        ),
        signing_key=(
            resolved_signing_key
        ),
    )

    if (
        OUTPUT_IMAGE.stat().st_size
        != resolved_source_init_boot.stat().st_size
    ):
        raise TreeForgeBootstrapImageError(
            "realized init_boot partition size changed: "
            f"{OUTPUT_IMAGE.stat().st_size} != "
            f"{resolved_source_init_boot.stat().st_size}"
        )

    realized_init_contract = (
        _hash_contract(
            avbtool,
            OUTPUT_IMAGE,
            expected_partition=(
                INIT_BOOT_PARTITION_NAME
            ),
        )
    )

    _assert_contract_preserved(
        source_init_contract,
        realized_init_contract,
        expected_public_key_sha1=(
            signing_public_key_sha1
        ),
    )

    boot_sha = _sha256(
        OUTPUT_BOOT_IMAGE
    )

    init_boot_sha = _sha256(
        OUTPUT_IMAGE
    )

    metadata = _expected_metadata(
        boot_sha=boot_sha,
        init_boot_sha=init_boot_sha,
        source_init_boot=(
            resolved_source_init_boot
        ),
        source_vbmeta=(
            resolved_source_vbmeta
        ),
        source_child_public_key_sha1=(
            source_child_public_key_sha1
        ),
        signing_public_key_sha1=(
            signing_public_key_sha1
        ),
        source_init_contract=(
            source_init_contract
        ),
        vbmeta_rewrite_required=(
            vbmeta_rewrite_required
        ),
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
        f"Boot SHA:   {boot_sha}"
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
    print(
        "Public key:      "
        + signing_public_key_sha1
    )
    print()
    print(
        "IMAGE_FAMILY=boot,init_boot"
    )
    print(
        "SIGNED_IMAGE=YES"
    )
    print(
        "SIGNING_OWNER=DOWNSTREAM_CONSUMER"
    )
    print(
        "VBMETA_REWRITE_REQUIRED="
        + (
            "YES"
            if vbmeta_rewrite_required
            else "NO"
        )
    )
    print(
        "TREEFORGE_BOOTSTRAP_IMAGE_BUILD=PASS"
    )

    return OUTPUT_IMAGE


def verify_image(
    *,
    source_init_boot: Path | None = None,
    source_vbmeta: Path | None = None,
    signing_key: Path | None = None,
    require_parent_match: bool = True,
) -> Path:
    (
        resolved_source_init_boot,
        resolved_source_vbmeta,
        resolved_signing_key,
    ) = _validate_inputs(
        source_init_boot=source_init_boot,
        source_vbmeta=source_vbmeta,
        signing_key=signing_key,
    )

    kernel = ensure_bootstrap_kernel()

    if (
        _sha256(kernel)
        != EXPECTED_KERNEL_SHA256
    ):
        raise TreeForgeBootstrapImageError(
            "released Bootstrap kernel provider identity changed"
        )

    if not OUTPUT_BOOT_IMAGE.is_file():
        raise TreeForgeBootstrapImageError(
            "TreeForge Bootstrap boot image missing: "
            f"{OUTPUT_BOOT_IMAGE}"
        )

    if not OUTPUT_IMAGE.is_file():
        raise TreeForgeBootstrapImageError(
            "TreeForge Bootstrap init_boot missing: "
            f"{OUTPUT_IMAGE}"
        )

    if not OUTPUT_METADATA.is_file():
        raise TreeForgeBootstrapImageError(
            "TreeForge Bootstrap image metadata missing: "
            f"{OUTPUT_METADATA}"
        )

    if (
        OUTPUT_BOOT_IMAGE.stat().st_size
        != kernel.stat().st_size
    ):
        raise TreeForgeBootstrapImageError(
            "realized boot partition size changed"
        )

    if (
        OUTPUT_IMAGE.stat().st_size
        != resolved_source_init_boot.stat().st_size
    ):
        raise TreeForgeBootstrapImageError(
            "realized init_boot partition size changed"
        )

    avbtool = ensure_host_tool(
        "avbtool"
    )

    unpack_bootimg = ensure_host_tool(
        "unpack_bootimg"
    )

    (
        _signing_public,
        signing_public_key_sha1,
    ) = _extract_signing_public_key(
        avbtool,
        resolved_signing_key,
    )

    (
        source_child_public_key_sha1,
        vbmeta_rewrite_required,
    ) = _verify_parent_chain(
        avbtool,
        source_vbmeta=(
            resolved_source_vbmeta
        ),
        signing_public_key_sha1=(
            signing_public_key_sha1
        ),
        require_match=(
            require_parent_match
        ),
    )

    source_init_contract = (
        _hash_contract(
            avbtool,
            resolved_source_init_boot,
            expected_partition=(
                INIT_BOOT_PARTITION_NAME
            ),
        )
    )

    if (
        source_init_contract[
            "public_key_sha1"
        ]
        != source_child_public_key_sha1
    ):
        raise TreeForgeBootstrapImageError(
            "source init_boot AVB identity does not match "
            "the source root-vbmeta chain"
        )

    kernel_contract = (
        _hash_contract(
            avbtool,
            kernel,
            expected_partition=(
                BOOT_PARTITION_NAME
            ),
        )
    )

    realized_boot_contract = (
        _hash_contract(
            avbtool,
            OUTPUT_BOOT_IMAGE,
            expected_partition=(
                BOOT_PARTITION_NAME
            ),
        )
    )

    realized_init_contract = (
        _hash_contract(
            avbtool,
            OUTPUT_IMAGE,
            expected_partition=(
                INIT_BOOT_PARTITION_NAME
            ),
        )
    )

    _assert_contract_preserved(
        kernel_contract,
        realized_boot_contract,
        expected_public_key_sha1=(
            signing_public_key_sha1
        ),
    )

    _assert_contract_preserved(
        source_init_contract,
        realized_init_contract,
        expected_public_key_sha1=(
            signing_public_key_sha1
        ),
    )

    _run(
        [
            str(avbtool),
            "verify_image",
            "--image",
            str(OUTPUT_BOOT_IMAGE),
            "--key",
            str(resolved_signing_key),
        ]
    )

    _run(
        [
            str(avbtool),
            "verify_image",
            "--image",
            str(OUTPUT_IMAGE),
            "--key",
            str(resolved_signing_key),
        ]
    )

    #
    # Verify that changing the boot signer did not alter the
    # published r0.94-v1.0b1 boot payload.
    #
    from .owner_family import (
        OwnerFamilyError,
        read_metadata,
        sha256 as owner_sha256,
    )

    try:
        (
            _header,
            _descriptors,
            kernel_payload_bytes,
            _footer,
        ) = read_metadata(
            kernel
        )

        (
            _header,
            _descriptors,
            realized_payload_bytes,
            _footer,
        ) = read_metadata(
            OUTPUT_BOOT_IMAGE
        )

        kernel_payload_sha = owner_sha256(
            kernel,
            kernel_payload_bytes,
        )

        realized_payload_sha = owner_sha256(
            OUTPUT_BOOT_IMAGE,
            realized_payload_bytes,
        )

    except OwnerFamilyError as exc:
        raise TreeForgeBootstrapImageError(
            "unable to verify owner-signed boot payload identity"
        ) from exc

    if (
        kernel_payload_bytes
        != realized_payload_bytes
        or kernel_payload_sha
        != realized_payload_sha
    ):
        raise TreeForgeBootstrapImageError(
            "owner signing changed the released "
            "Bootstrap boot payload"
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
                kernel_size = int(
                    raw_size
                )
            except ValueError as exc:
                raise TreeForgeBootstrapImageError(
                    "Bootstrap boot kernel size "
                    f"is not an integer: {raw_size}"
                ) from exc

            break

    if kernel_size is None or kernel_size <= 0:
        raise TreeForgeBootstrapImageError(
            "Bootstrap boot kernel is missing or empty"
        )

    unpacked_kernel = (
        boot_unpack
        / "kernel"
    )

    if not unpacked_kernel.is_file():
        raise TreeForgeBootstrapImageError(
            "unpacked Bootstrap kernel missing"
        )

    if (
        unpacked_kernel.stat().st_size
        != kernel_size
    ):
        raise TreeForgeBootstrapImageError(
            "Bootstrap kernel header/file size mismatch"
        )

    for marker in (
        "ramdisk size: 0",
        "boot image header version: 4",
        "boot.img signature size: 0",
    ):
        if marker not in boot_unpack_output:
            raise TreeForgeBootstrapImageError(
                "Bootstrap boot structure changed: "
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
                "init_boot structural contract changed: "
                f"{marker}"
            )

    unpacked_ramdisk = (
        verify_unpack
        / "ramdisk"
    )

    if not unpacked_ramdisk.is_file():
        raise TreeForgeBootstrapImageError(
            "unpacked init_boot ramdisk missing"
        )

    runtime_sha = _sha256(
        RUNTIME_RAMDISK
    )

    unpacked_sha = _sha256(
        unpacked_ramdisk
    )

    if runtime_sha != unpacked_sha:
        raise TreeForgeBootstrapImageError(
            "signed init_boot ramdisk does not match "
            "the accepted TreeForge runtime: "
            f"{unpacked_sha} != {runtime_sha}"
        )

    boot_sha = _sha256(
        OUTPUT_BOOT_IMAGE
    )

    init_boot_sha = _sha256(
        OUTPUT_IMAGE
    )

    expected_metadata = (
        _expected_metadata(
            boot_sha=boot_sha,
            init_boot_sha=init_boot_sha,
            source_init_boot=(
                resolved_source_init_boot
            ),
            source_vbmeta=(
                resolved_source_vbmeta
            ),
            source_child_public_key_sha1=(
                source_child_public_key_sha1
            ),
            signing_public_key_sha1=(
                signing_public_key_sha1
            ),
            source_init_contract=(
                source_init_contract
            ),
            vbmeta_rewrite_required=(
                vbmeta_rewrite_required
            ),
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
            "unable to read image metadata"
        ) from exc

    if actual_metadata != expected_metadata:
        raise TreeForgeBootstrapImageError(
            "image metadata contract changed"
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
        + signing_public_key_sha1
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
        "SIGNING_OWNER=DOWNSTREAM_CONSUMER"
    )

    if vbmeta_rewrite_required:
        print(
            "BOOT_VBMETA_CHAIN_MATCH=PENDING_REWRITE"
        )
        print(
            "INIT_BOOT_VBMETA_CHAIN_MATCH=PENDING_REWRITE"
        )
    else:
        print(
            "BOOT_VBMETA_CHAIN_MATCH=PASS"
        )
        print(
            "INIT_BOOT_VBMETA_CHAIN_MATCH=PASS"
        )

    print(
        "VBMETA_REWRITE_REQUIRED="
        + (
            "YES"
            if vbmeta_rewrite_required
            else "NO"
        )
    )

    print(
        "BOOT_PROVIDER_PAYLOAD_IDENTITY=PASS"
    )

    print(
        "TREEFORGE_BOOTSTRAP_IMAGE_VERIFY=PASS"
    )

    return OUTPUT_IMAGE
