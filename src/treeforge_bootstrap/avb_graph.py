from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

from .host_providers import ensure_host_tool

from .image import (
    OUTPUT_BOOT_IMAGE,
    OUTPUT_IMAGE,
    build_image,
    verify_image,
)

from .paths import (
    OUT,
    WORK,
)


class TreeForgeBootstrapAvbGraphError(
    RuntimeError
):
    pass


REQUIRED_PARTITIONS = (
    "boot",
    "init_boot",
    "vendor_boot",
    "vendor_kernel_boot",
    "dtbo",
    "pvmfw",
    "system",
    "system_dlkm",
    "system_ext",
    "product",
    "vendor",
    "vendor_dlkm",
    "vbmeta",
    "vbmeta_system",
    "vbmeta_vendor",
)


EXPECTED_ROOT_CHAIN_LOCATIONS = {
    "boot": 2,
    "init_boot": 4,
    "vbmeta_system": 1,
    "vbmeta_vendor": 3,
}


ROOT_DESCRIPTOR_TARGETS = (
    "dtbo",
    "vendor_boot",
    "vendor_kernel_boot",
    "vendor_dlkm",
)


SYSTEM_DESCRIPTOR_TARGETS = (
    "pvmfw",
    "product",
    "system",
    "system_dlkm",
    "system_ext",
)


VENDOR_DESCRIPTOR_TARGETS = (
    "vendor",
)


REALIZED_OUT = (
    OUT
    / "realized"
)


REALIZED_WORK = (
    WORK
    / "realized-stage"
)


REALIZED_KEY_WORK = (
    WORK
    / "realized-key-work"
)


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
        raise TreeForgeBootstrapAvbGraphError(
            "command failed:\n"
            + " ".join(command)
            + "\n\n"
            + result.stdout
        )

    return result.stdout


def _input_roots(
    input_family: Path,
) -> tuple[
    Path,
    Path,
    Path | None,
]:
    root = (
        input_family
        .expanduser()
        .resolve()
    )

    if not root.is_dir():
        raise TreeForgeBootstrapAvbGraphError(
            "input family directory is missing: "
            f"{root}"
        )

    images = (
        root / "images"
        if (root / "images").is_dir()
        else root
    )

    manifest_candidates = (
        root / "source-manifest.json",
        images.parent / "source-manifest.json",
    )

    manifest = next(
        (
            path
            for path in manifest_candidates
            if path.is_file()
        ),
        None,
    )

    return (
        root,
        images,
        manifest,
    )


def _resolve_source_images(
    images_root: Path,
) -> dict[str, Path]:
    resolved: dict[str, Path] = {}

    for name in REQUIRED_PARTITIONS:
        candidates = tuple(
            path
            for path in (
                images_root / f"{name}.img",
                images_root / f"{name}_a.img",
                images_root / f"{name}_b.img",
            )
            if path.is_file()
        )

        if len(candidates) != 1:
            raise TreeForgeBootstrapAvbGraphError(
                "expected exactly one source image "
                f"for {name}, found "
                f"{len(candidates)}"
            )

        resolved[name] = (
            candidates[0]
            .resolve()
        )

    return resolved


def _validate_source_manifest(
    manifest_path: Path | None,
    images: dict[str, Path],
) -> dict[str, Any] | None:
    if manifest_path is None:
        return None

    try:
        manifest = json.loads(
            manifest_path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        raise TreeForgeBootstrapAvbGraphError(
            "unable to read source family manifest"
        ) from exc

    if manifest.get("complete") is not True:
        raise TreeForgeBootstrapAvbGraphError(
            "source family manifest is not complete"
        )

    if (
        manifest.get("expected_image_count")
        != 15
        or manifest.get("acquired_image_count")
        != 15
    ):
        raise TreeForgeBootstrapAvbGraphError(
            "source family manifest is not 15/15"
        )

    records = {
        value.get("base_name"): value
        for value in manifest.get(
            "images",
            []
        )
        if isinstance(
            value,
            dict,
        )
    }

    for name, path in images.items():
        record = records.get(name)

        if record is None:
            raise TreeForgeBootstrapAvbGraphError(
                "source manifest is missing "
                f"{name}"
            )

        expected_sha = record.get(
            "sha256"
        )

        actual_sha = _sha256(
            path
        )

        if expected_sha != actual_sha:
            raise TreeForgeBootstrapAvbGraphError(
                "source family manifest SHA mismatch "
                f"for {name}: "
                f"{actual_sha} != "
                f"{expected_sha}"
            )

        expected_size = record.get(
            "size_bytes"
        )

        if (
            expected_size
            != path.stat().st_size
        ):
            raise TreeForgeBootstrapAvbGraphError(
                "source family manifest size mismatch "
                f"for {name}"
            )

    return manifest


def _info_image(
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


def _verify_avb_image(
    avbtool: Path,
    image: Path,
    *,
    follow_chain_partitions: bool = False,
) -> None:
    command = [
        str(avbtool),
        "verify_image",
        "--image",
        str(image),
    ]

    if follow_chain_partitions:
        command.append(
            "--follow_chain_partitions"
        )

    _run(
        command
    )


def _header_fields(
    info: str,
) -> dict[str, str]:
    fields: dict[str, str] = {}

    for line in info.splitlines():
        if line.strip() == "Descriptors:":
            break

        if ":" not in line:
            continue

        key, value = line.split(
            ":",
            1,
        )

        key = key.strip()
        value = value.strip()

        if key:
            fields[key] = value

    return fields


def _descriptor_blocks(
    info: str,
) -> tuple[
    tuple[
        str,
        dict[str, str],
    ],
    ...,
]:
    lines = info.splitlines()
    blocks: list[
        tuple[
            str,
            dict[str, str],
        ]
    ] = []

    index = 0

    while index < len(lines):
        line = lines[index]

        match = re.match(
            r"^ {4}"
            r"(Hash|Hashtree|Chain Partition)"
            r" descriptor:$",
            line,
        )

        if match is None:
            index += 1
            continue

        kind = match.group(1)
        fields: dict[str, str] = {}

        index += 1

        while index < len(lines):
            current = lines[index]

            indent = (
                len(current)
                - len(
                    current.lstrip(" ")
                )
            )

            if (
                current.strip()
                and indent <= 4
            ):
                break

            stripped = current.strip()

            if ":" in stripped:
                key, value = stripped.split(
                    ":",
                    1,
                )

                fields[
                    key.strip()
                ] = value.strip()

            index += 1

        blocks.append(
            (
                kind,
                fields,
            )
        )

    return tuple(
        blocks
    )


def _chain_map(
    info: str,
) -> dict[
    str,
    dict[str, str],
]:
    result: dict[
        str,
        dict[str, str],
    ] = {}

    for kind, fields in (
        _descriptor_blocks(info)
    ):
        if kind != "Chain Partition":
            continue

        partition = fields.get(
            "Partition Name"
        )

        if not partition:
            raise TreeForgeBootstrapAvbGraphError(
                "chain descriptor is missing "
                "Partition Name"
            )

        if partition in result:
            raise TreeForgeBootstrapAvbGraphError(
                "duplicate chain descriptor for "
                f"{partition}"
            )

        result[partition] = fields

    return result


def _descriptor_map(
    info: str,
) -> dict[
    str,
    tuple[
        str,
        dict[str, str],
    ],
]:
    result: dict[
        str,
        tuple[
            str,
            dict[str, str],
        ],
    ] = {}

    for kind, fields in (
        _descriptor_blocks(info)
    ):
        if kind not in {
            "Hash",
            "Hashtree",
        }:
            continue

        partition = fields.get(
            "Partition Name"
        )

        if not partition:
            raise TreeForgeBootstrapAvbGraphError(
                f"{kind} descriptor is missing "
                "Partition Name"
            )

        if partition in result:
            raise TreeForgeBootstrapAvbGraphError(
                "duplicate hash/hashtree descriptor "
                f"for {partition}"
            )

        result[partition] = (
            kind,
            fields,
        )

    return result


def _compare_descriptor_binding(
    *,
    parent_name: str,
    target_name: str,
    parent_info: str,
    target_info: str,
) -> None:
    parent = _descriptor_map(
        parent_info
    )

    target = _descriptor_map(
        target_info
    )

    if target_name not in parent:
        raise TreeForgeBootstrapAvbGraphError(
            f"{parent_name} is missing "
            f"{target_name} descriptor"
        )

    if target_name not in target:
        raise TreeForgeBootstrapAvbGraphError(
            f"{target_name} image is missing "
            "its own AVB descriptor"
        )

    parent_kind, parent_fields = (
        parent[target_name]
    )

    target_kind, target_fields = (
        target[target_name]
    )

    if parent_kind != target_kind:
        raise TreeForgeBootstrapAvbGraphError(
            f"{parent_name}->{target_name} "
            "descriptor kind mismatch: "
            f"{parent_kind} != "
            f"{target_kind}"
        )

    if parent_fields != target_fields:
        raise TreeForgeBootstrapAvbGraphError(
            f"{parent_name}->{target_name} "
            "descriptor fields differ"
        )


def _copy_passthrough(
    source: Path,
    destination: Path,
) -> None:
    if destination.exists():
        destination.unlink()

    result = subprocess.run(
        [
            "cp",
            "--reflink=auto",
            "--preserve=mode,timestamps",
            "--",
            str(source),
            str(destination),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise TreeForgeBootstrapAvbGraphError(
            "unable to materialize independent "
            "passthrough image:\n"
            f"{source} -> {destination}\n"
            + result.stdout
        )


def _copy_generated(
    source: Path,
    destination: Path,
) -> None:
    if destination.exists():
        destination.unlink()

    shutil.copy2(
        source,
        destination,
    )


def _verify_chain_edges(
    infos: dict[str, str],
) -> dict[str, dict[str, Any]]:
    root_chains = _chain_map(
        infos["vbmeta"]
    )

    if (
        set(root_chains)
        != set(
            EXPECTED_ROOT_CHAIN_LOCATIONS
        )
    ):
        raise TreeForgeBootstrapAvbGraphError(
            "root vbmeta chain population changed: "
            f"{sorted(root_chains)}"
        )

    result: dict[
        str,
        dict[str, Any],
    ] = {}

    for (
        partition,
        expected_location,
    ) in (
        EXPECTED_ROOT_CHAIN_LOCATIONS.items()
    ):
        chain = root_chains[
            partition
        ]

        raw_location = chain.get(
            "Rollback Index Location"
        )

        try:
            actual_location = int(
                raw_location
                if raw_location is not None
                else ""
            )
        except ValueError as exc:
            raise TreeForgeBootstrapAvbGraphError(
                "invalid rollback location "
                f"for {partition}: "
                f"{raw_location}"
            ) from exc

        if (
            actual_location
            != expected_location
        ):
            raise TreeForgeBootstrapAvbGraphError(
                "rollback location changed "
                f"for {partition}: "
                f"{actual_location} != "
                f"{expected_location}"
            )

        child_header = _header_fields(
            infos[partition]
        )

        child_public_key = (
            child_header.get(
                "Public key (sha1)"
            )
        )

        delegated_public_key = (
            chain.get(
                "Public key (sha1)"
            )
        )

        if (
            not child_public_key
            or child_public_key
            != delegated_public_key
        ):
            raise TreeForgeBootstrapAvbGraphError(
                "root trust delegation does not "
                f"match {partition}: "
                f"{delegated_public_key} != "
                f"{child_public_key}"
            )

        if chain.get("Flags") != "0":
            raise TreeForgeBootstrapAvbGraphError(
                "non-zero chain flags for "
                f"{partition}"
            )

        result[partition] = {
            "rollback_index_location":
                actual_location,

            "public_key_sha1":
                child_public_key,

            "flags":
                0,
        }

    return result


def _verify_descriptor_graph(
    infos: dict[str, str],
) -> None:
    for target in (
        ROOT_DESCRIPTOR_TARGETS
    ):
        _compare_descriptor_binding(
            parent_name="vbmeta",
            target_name=target,
            parent_info=infos["vbmeta"],
            target_info=infos[target],
        )

    for target in (
        SYSTEM_DESCRIPTOR_TARGETS
    ):
        _compare_descriptor_binding(
            parent_name="vbmeta_system",
            target_name=target,
            parent_info=infos[
                "vbmeta_system"
            ],
            target_info=infos[target],
        )

    for target in (
        VENDOR_DESCRIPTOR_TARGETS
    ):
        _compare_descriptor_binding(
            parent_name="vbmeta_vendor",
            target_name=target,
            parent_info=infos[
                "vbmeta_vendor"
            ],
            target_info=infos[target],
        )


def _verify_passthrough_identity(
    source_images: dict[str, Path],
    realized_images: dict[str, Path],
    *,
    allowed_changed: set[str] | None = None,
) -> None:
    changed = (
        {"boot", "init_boot"}
        if allowed_changed is None
        else set(allowed_changed)
    )

    for name in REQUIRED_PARTITIONS:
        if name in changed:
            continue

        source_sha = _sha256(
            source_images[name]
        )

        realized_sha = _sha256(
            realized_images[name]
        )

        if source_sha != realized_sha:
            raise TreeForgeBootstrapAvbGraphError(
                "passthrough image changed: "
                f"{name}"
            )


def _verify_replaced_child_contract(
    *,
    partition: str,
    source_info: str,
    realized_info: str,
) -> None:
    source_header = _header_fields(
        source_info
    )

    realized_header = _header_fields(
        realized_info
    )

    for field in (
        "Public key (sha1)",
        "Algorithm",
        "Rollback Index",
        "Flags",
    ):
        if (
            source_header.get(field)
            != realized_header.get(field)
        ):
            raise TreeForgeBootstrapAvbGraphError(
                f"{partition} AVB field changed: "
                f"{field}: "
                f"{source_header.get(field)} != "
                f"{realized_header.get(field)}"
            )


def _properties(
    info: str,
) -> tuple[tuple[str, str], ...]:
    result: list[
        tuple[str, str]
    ] = []

    expression = re.compile(
        r"^\s+Prop: (.*?) -> '(.*)'$"
    )

    for line in info.splitlines():
        match = expression.match(
            line
        )

        if match is None:
            continue

        result.append(
            (
                match.group(1),
                match.group(2),
            )
        )

    return tuple(result)


def _extract_private_public_key(
    avbtool: Path,
    private_key: Path,
    output: Path,
) -> Path:
    private_key = (
        private_key
        .expanduser()
        .resolve()
    )

    if not private_key.is_file():
        raise TreeForgeBootstrapAvbGraphError(
            "AVB private key is missing: "
            f"{private_key}"
        )

    if output.exists():
        output.unlink()

    _run(
        [
            str(avbtool),
            "extract_public_key",
            "--key",
            str(private_key),
            "--output",
            str(output),
        ]
    )

    if not output.is_file():
        raise TreeForgeBootstrapAvbGraphError(
            "AVB public-key extraction failed: "
            f"{private_key}"
        )

    return output


def _extract_embedded_public_key(
    avbtool: Path,
    image: Path,
    output: Path,
) -> Path:
    #
    # AvbVBMetaImageHeader is always 256 bytes.
    #
    # Relevant big-endian offsets:
    #
    #   12: authentication_data_block_size (uint64)
    #   64: public_key_offset             (uint64)
    #   72: public_key_size               (uint64)
    #
    # public_key_offset is relative to the beginning of the
    # auxiliary block.
    #
    header_size = 256

    with image.open("rb") as stream:
        header = stream.read(
            header_size
        )

        if len(header) != header_size:
            raise TreeForgeBootstrapAvbGraphError(
                "vbmeta header is truncated: "
                f"{image}"
            )

        if header[0:4] != b"AVB0":
            raise TreeForgeBootstrapAvbGraphError(
                "image is not standalone vbmeta: "
                f"{image}"
            )

        authentication_size = int.from_bytes(
            header[12:20],
            byteorder="big",
            signed=False,
        )

        public_key_offset = int.from_bytes(
            header[64:72],
            byteorder="big",
            signed=False,
        )

        public_key_size = int.from_bytes(
            header[72:80],
            byteorder="big",
            signed=False,
        )

        if public_key_size <= 0:
            raise TreeForgeBootstrapAvbGraphError(
                "vbmeta image has no embedded "
                f"public key: {image}"
            )

        absolute_offset = (
            header_size
            + authentication_size
            + public_key_offset
        )

        stream.seek(
            absolute_offset
        )

        public_key = stream.read(
            public_key_size
        )

    if len(public_key) != public_key_size:
        raise TreeForgeBootstrapAvbGraphError(
            "embedded AVB public key is "
            f"truncated: {image}"
        )

    #
    # Cross-check the raw extraction against avbtool's own reported
    # SHA-1 identity. This makes the parser fail closed if the AVB
    # layout ever differs from the expected format.
    #
    info = _info_image(
        avbtool,
        image,
    )

    reported = (
        _header_fields(info)
        .get(
            "Public key (sha1)"
        )
    )

    if reported is None:
        raise TreeForgeBootstrapAvbGraphError(
            "avbtool did not report an embedded "
            f"public key for {image}"
        )

    actual = hashlib.sha1(
        public_key
    ).hexdigest()

    if actual != reported:
        raise TreeForgeBootstrapAvbGraphError(
            "raw embedded AVB public-key "
            "extraction does not match "
            "avbtool identity: "
            f"{actual} != {reported}"
        )

    if output.exists():
        output.unlink()

    output.write_bytes(
        public_key
    )

    return output


def _resign_hash_child(
    *,
    avbtool: Path,
    image: Path,
    partition: str,
    signing_key: Path,
    expected_public_key_sha1: str,
) -> str:
    before = _info_image(
        avbtool,
        image,
    )

    before_header = _header_fields(
        before
    )

    before_descriptors = _descriptor_map(
        before
    )

    descriptor_entry = (
        before_descriptors.get(
            partition
        )
    )

    if descriptor_entry is None:
        raise TreeForgeBootstrapAvbGraphError(
            f"{partition} has no AVB descriptor"
        )

    kind, descriptor = (
        descriptor_entry
    )

    if kind != "Hash":
        raise TreeForgeBootstrapAvbGraphError(
            f"{partition} is not a hash-footer "
            f"image: {kind}"
        )

    if (
        before_header.get("Flags")
        != "0"
    ):
        raise TreeForgeBootstrapAvbGraphError(
            f"{partition} has unsupported "
            "AVB header flags"
        )

    if descriptor.get("Flags") != "0":
        raise TreeForgeBootstrapAvbGraphError(
            f"{partition} has unsupported "
            "hash-descriptor flags"
        )

    partition_size = (
        image.stat().st_size
    )

    algorithm = (
        before_header.get(
            "Algorithm"
        )
    )

    rollback_index = (
        before_header.get(
            "Rollback Index"
        )
    )

    rollback_location = (
        before_header.get(
            "Rollback Index Location"
        )
    )

    hash_algorithm = (
        descriptor.get(
            "Hash Algorithm"
        )
    )

    salt = descriptor.get(
        "Salt"
    )

    required = {
        "algorithm": algorithm,
        "rollback_index": rollback_index,
        "rollback_location":
            rollback_location,
        "hash_algorithm":
            hash_algorithm,
        "salt":
            salt,
    }

    missing = [
        name
        for name, value
        in required.items()
        if value is None
    ]

    if missing:
        raise TreeForgeBootstrapAvbGraphError(
            f"{partition} AVB contract "
            "is incomplete: "
            + ",".join(missing)
        )

    _run(
        [
            str(avbtool),
            "erase_footer",
            "--image",
            str(image),
        ]
    )

    command = [
        str(avbtool),
        "add_hash_footer",

        "--image",
        str(image),

        "--partition_name",
        partition,

        "--partition_size",
        str(partition_size),

        "--algorithm",
        str(algorithm),

        "--key",
        str(signing_key),

        "--rollback_index",
        str(rollback_index),

        "--rollback_index_location",
        str(rollback_location),

        "--hash_algorithm",
        str(hash_algorithm),

        "--salt",
        str(salt),
    ]

    for key, value in _properties(
        before
    ):
        command.extend(
            [
                "--prop",
                f"{key}:{value}",
            ]
        )

    _run(command)

    after = _info_image(
        avbtool,
        image,
    )

    if (
        _descriptor_map(after)
        != before_descriptors
    ):
        raise TreeForgeBootstrapAvbGraphError(
            f"{partition} descriptor "
            "population changed while "
            "re-signing"
        )

    if (
        _properties(after)
        != _properties(before)
    ):
        raise TreeForgeBootstrapAvbGraphError(
            f"{partition} AVB properties "
            "changed while re-signing"
        )

    after_header = _header_fields(
        after
    )

    for field in (
        "Algorithm",
        "Rollback Index",
        "Flags",
        "Rollback Index Location",
    ):
        if (
            after_header.get(field)
            != before_header.get(field)
        ):
            raise TreeForgeBootstrapAvbGraphError(
                f"{partition} AVB header "
                f"field changed: {field}"
            )

    actual_key = after_header.get(
        "Public key (sha1)"
    )

    if (
        actual_key
        != expected_public_key_sha1
    ):
        raise TreeForgeBootstrapAvbGraphError(
            f"{partition} replacement AVB "
            "public key mismatch"
        )

    return after


def _rebuild_root_for_boot_chain_key(
    *,
    avbtool: Path,
    realized_images: dict[str, Path],
    replacement_child_pubkey: Path,
    replacement_child_sha1: str,
    parent_vbmeta_key: Path,
) -> None:
    root_image = (
        realized_images["vbmeta"]
    )

    before = _info_image(
        avbtool,
        root_image,
    )

    before_header = _header_fields(
        before
    )

    before_chains = _chain_map(
        before
    )

    before_descriptors = _descriptor_map(
        before
    )

    before_properties = _properties(
        before
    )

    if (
        set(before_chains)
        != set(
            EXPECTED_ROOT_CHAIN_LOCATIONS
        )
    ):
        raise TreeForgeBootstrapAvbGraphError(
            "root chain population changed"
        )

    #
    # The parent key must preserve the existing root trust identity.
    # If it does not, this would require bootloader root-trust
    # provisioning and is deliberately not publishable through this
    # production path.
    #
    existing_root_pub = (
        REALIZED_KEY_WORK
        / "existing-root.avbpubkey"
    )

    supplied_root_pub = (
        REALIZED_KEY_WORK
        / "supplied-root.avbpubkey"
    )

    _extract_embedded_public_key(
        avbtool,
        root_image,
        existing_root_pub,
    )

    _extract_private_public_key(
        avbtool,
        parent_vbmeta_key,
        supplied_root_pub,
    )

    if (
        existing_root_pub.read_bytes()
        != supplied_root_pub.read_bytes()
    ):
        raise TreeForgeBootstrapAvbGraphError(
            "parent vbmeta private key does not "
            "match the existing root AVB identity; "
            "bootloader root-trust replacement is "
            "not allowed by this realization policy"
        )

    system_pub = (
        REALIZED_KEY_WORK
        / "vbmeta-system.avbpubkey"
    )

    vendor_pub = (
        REALIZED_KEY_WORK
        / "vbmeta-vendor.avbpubkey"
    )

    _extract_embedded_public_key(
        avbtool,
        realized_images[
            "vbmeta_system"
        ],
        system_pub,
    )

    _extract_embedded_public_key(
        avbtool,
        realized_images[
            "vbmeta_vendor"
        ],
        vendor_pub,
    )

    temporary = (
        REALIZED_WORK
        / ".vbmeta.rewritten.img"
    )

    if temporary.exists():
        temporary.unlink()

    required_header = (
        "Algorithm",
        "Rollback Index",
        "Rollback Index Location",
        "Flags",
    )

    for field in required_header:
        if before_header.get(field) is None:
            raise TreeForgeBootstrapAvbGraphError(
                "root vbmeta is missing "
                f"{field}"
            )

    command = [
        str(avbtool),
        "make_vbmeta_image",

        "--output",
        str(temporary),

        "--algorithm",
        before_header["Algorithm"],

        "--key",
        str(parent_vbmeta_key),

        "--rollback_index",
        before_header["Rollback Index"],

        "--rollback_index_location",
        before_header[
            "Rollback Index Location"
        ],

        "--flags",
        before_header["Flags"],

        "--padding_size",
        str(root_image.stat().st_size),

        "--chain_partition",
        "boot:"
        + str(
            EXPECTED_ROOT_CHAIN_LOCATIONS[
                "boot"
            ]
        )
        + ":"
        + str(
            replacement_child_pubkey
        ),

        "--chain_partition",
        "init_boot:"
        + str(
            EXPECTED_ROOT_CHAIN_LOCATIONS[
                "init_boot"
            ]
        )
        + ":"
        + str(
            replacement_child_pubkey
        ),

        "--chain_partition",
        "vbmeta_system:"
        + str(
            EXPECTED_ROOT_CHAIN_LOCATIONS[
                "vbmeta_system"
            ]
        )
        + ":"
        + str(system_pub),

        "--chain_partition",
        "vbmeta_vendor:"
        + str(
            EXPECTED_ROOT_CHAIN_LOCATIONS[
                "vbmeta_vendor"
            ]
        )
        + ":"
        + str(vendor_pub),
    ]

    #
    # This ordering already reproduced the accepted tangorpro root
    # descriptor population in the host proof.
    #
    for name in (
        "vendor_boot",
        "vendor_kernel_boot",
        "vendor_dlkm",
        "dtbo",
    ):
        command.extend(
            [
                "--include_descriptors_from_image",
                str(
                    realized_images[name]
                ),
            ]
        )

    _run(command)

    if (
        temporary.stat().st_size
        != root_image.stat().st_size
    ):
        raise TreeForgeBootstrapAvbGraphError(
            "rewritten root vbmeta size changed"
        )

    after = _info_image(
        avbtool,
        temporary,
    )

    after_header = _header_fields(
        after
    )

    after_chains = _chain_map(
        after
    )

    if (
        _descriptor_map(after)
        != before_descriptors
    ):
        raise TreeForgeBootstrapAvbGraphError(
            "root non-chain AVB descriptors "
            "changed"
        )

    if (
        _properties(after)
        != before_properties
    ):
        raise TreeForgeBootstrapAvbGraphError(
            "root AVB properties changed"
        )

    for field in (
        "Algorithm",
        "Rollback Index",
        "Rollback Index Location",
        "Flags",
        "Public key (sha1)",
    ):
        if (
            after_header.get(field)
            != before_header.get(field)
        ):
            raise TreeForgeBootstrapAvbGraphError(
                "root AVB identity/header "
                f"changed: {field}"
            )

    for name, location in (
        EXPECTED_ROOT_CHAIN_LOCATIONS.items()
    ):
        before_edge = before_chains[
            name
        ]

        after_edge = after_chains.get(
            name
        )

        if after_edge is None:
            raise TreeForgeBootstrapAvbGraphError(
                f"rewritten root lost {name}"
            )

        if (
            after_edge.get(
                "Rollback Index Location"
            )
            != str(location)
        ):
            raise TreeForgeBootstrapAvbGraphError(
                f"rewritten root changed "
                f"{name} rollback location"
            )

        if (
            after_edge.get("Flags")
            != before_edge.get("Flags")
        ):
            raise TreeForgeBootstrapAvbGraphError(
                f"rewritten root changed "
                f"{name} chain flags"
            )

        actual_key = after_edge.get(
            "Public key (sha1)"
        )

        if name in {
            "boot",
            "init_boot",
        }:
            if (
                actual_key
                != replacement_child_sha1
            ):
                raise TreeForgeBootstrapAvbGraphError(
                    "rewritten root did not "
                    f"delegate {name} to the "
                    "replacement child key"
                )

        elif (
            actual_key
            != before_edge.get(
                "Public key (sha1)"
            )
        ):
            raise TreeForgeBootstrapAvbGraphError(
                "rewritten root unexpectedly "
                f"changed {name} trust identity"
            )

    temporary.replace(
        root_image
    )


def _apply_explicit_boot_chain_policy(
    *,
    avbtool: Path,
    realized_images: dict[str, Path],
    source_infos: dict[str, str],
    avb_key: Path | None,
    parent_vbmeta_key: Path | None,
) -> dict[str, object]:
    source_chains = _chain_map(
        source_infos["vbmeta"]
    )

    source_boot_key = (
        source_chains["boot"][
            "Public key (sha1)"
        ]
    )

    source_init_key = (
        source_chains["init_boot"][
            "Public key (sha1)"
        ]
    )

    if avb_key is None:
        if parent_vbmeta_key is not None:
            raise TreeForgeBootstrapAvbGraphError(
                "--parent-vbmeta-key requires "
                "--avb-key"
            )

        return {
            "graph_policy":
                "preserve-compatible-trust",

            "root_vbmeta_rewritten":
                False,

            "source_boot_chain_public_key_sha1":
                source_boot_key,

            "realized_boot_chain_public_key_sha1":
                source_boot_key,

            "root_signing_identity_preserved":
                True,

            "bootloader_root_trust_update_required":
                False,
        }

    avb_key = (
        avb_key
        .expanduser()
        .resolve()
    )

    replacement_pub = (
        REALIZED_KEY_WORK
        / "replacement-boot-chain.avbpubkey"
    )

    _extract_private_public_key(
        avbtool,
        avb_key,
        replacement_pub,
    )

    replacement_sha1 = _sha1(
        replacement_pub
    )

    if (
        replacement_sha1
        == source_boot_key
        and replacement_sha1
        == source_init_key
    ):
        return {
            "graph_policy":
                "preserve-compatible-trust",

            "root_vbmeta_rewritten":
                False,

            "source_boot_chain_public_key_sha1":
                source_boot_key,

            "realized_boot_chain_public_key_sha1":
                replacement_sha1,

            "root_signing_identity_preserved":
                True,

            "bootloader_root_trust_update_required":
                False,
        }

    if parent_vbmeta_key is None:
        raise TreeForgeBootstrapAvbGraphError(
            "boot/init_boot AVB signing identity "
            "changed, but no --parent-vbmeta-key "
            "was supplied to rewrite root vbmeta"
        )

    parent_vbmeta_key = (
        parent_vbmeta_key
        .expanduser()
        .resolve()
    )

    for partition in (
        "boot",
        "init_boot",
    ):
        _resign_hash_child(
            avbtool=avbtool,
            image=realized_images[
                partition
            ],
            partition=partition,
            signing_key=avb_key,
            expected_public_key_sha1=(
                replacement_sha1
            ),
        )

    _rebuild_root_for_boot_chain_key(
        avbtool=avbtool,
        realized_images=realized_images,
        replacement_child_pubkey=(
            replacement_pub
        ),
        replacement_child_sha1=(
            replacement_sha1
        ),
        parent_vbmeta_key=(
            parent_vbmeta_key
        ),
    )

    return {
        "graph_policy":
            "replace-boot-chain-trust",

        "root_vbmeta_rewritten":
            True,

        "source_boot_chain_public_key_sha1":
            source_boot_key,

        "realized_boot_chain_public_key_sha1":
            replacement_sha1,

        "root_signing_identity_preserved":
            True,

        "bootloader_root_trust_update_required":
            False,
    }


def realize_family(
    input_family: Path,
    *,
    output_family: Path | None = None,
    avb_key: Path | None = None,
    parent_vbmeta_key: Path | None = None,
    keyset_id: str | None = None,
    keyset_manifest_sha256: str | None = None,
) -> Path:
    (
        input_root,
        images_root,
        source_manifest_path,
    ) = _input_roots(
        input_family
    )

    realized_out = (
        realized_out
        if output_family is None
        else (
            output_family
            .expanduser()
            .resolve()
        )
    )

    source_images = (
        _resolve_source_images(
            images_root
        )
    )

    source_manifest = (
        _validate_source_manifest(
            source_manifest_path,
            source_images,
        )
    )

    avbtool = ensure_host_tool(
        "avbtool"
    )

    source_infos = {
        name: _info_image(
            avbtool,
            path,
        )
        for name, path
        in source_images.items()
    }

    #
    # Build the two TreeForge-owned boot-family outputs using the
    # backed-up init_boot/root-vbmeta as the source contract.
    #
    build_image(
        source_init_boot=(
            source_images["init_boot"]
        ),
        source_vbmeta=(
            source_images["vbmeta"]
        ),
        signing_key=avb_key,
    )

    verify_image(
        source_init_boot=(
            source_images["init_boot"]
        ),
        source_vbmeta=(
            source_images["vbmeta"]
        ),
        signing_key=avb_key,
    )

    #
    # The current tangorpro realization deliberately preserves the
    # existing signing identity. A changed identity is a separate
    # recursive trust-rewrite operation and must never happen
    # accidentally.
    #
    generated_infos = {
        "boot": _info_image(
            avbtool,
            OUTPUT_BOOT_IMAGE,
        ),
        "init_boot": _info_image(
            avbtool,
            OUTPUT_IMAGE,
        ),
    }

    for partition in (
        "boot",
        "init_boot",
    ):
        _verify_replaced_child_contract(
            partition=partition,
            source_info=(
                source_infos[partition]
            ),
            realized_info=(
                generated_infos[partition]
            ),
        )

    if realized_out.exists():
        raise TreeForgeBootstrapAvbGraphError(
            "realized family output already "
            f"exists: {realized_out}"
        )

    if REALIZED_WORK.exists():
        shutil.rmtree(
            REALIZED_WORK
        )

    if REALIZED_KEY_WORK.exists():
        shutil.rmtree(
            REALIZED_KEY_WORK
        )

    REALIZED_WORK.mkdir(
        parents=True,
        exist_ok=False,
    )

    REALIZED_KEY_WORK.mkdir(
        parents=True,
        exist_ok=False,
    )

    realized_images: dict[
        str,
        Path,
    ] = {}

    for name in REQUIRED_PARTITIONS:
        destination = (
            REALIZED_WORK
            / f"{name}.img"
        )

        if name == "boot":
            _copy_generated(
                OUTPUT_BOOT_IMAGE,
                destination,
            )

        elif name == "init_boot":
            _copy_generated(
                OUTPUT_IMAGE,
                destination,
            )

        else:
            _copy_passthrough(
                source_images[name],
                destination,
            )

        realized_images[name] = (
            destination
        )

    trust_realization = (
        _apply_explicit_boot_chain_policy(
            avbtool=avbtool,
            realized_images=realized_images,
            source_infos=source_infos,
            avb_key=avb_key,
            parent_vbmeta_key=(
                parent_vbmeta_key
            ),
        )
    )

    allowed_changed = {
        "boot",
        "init_boot",
    }

    if trust_realization[
        "root_vbmeta_rewritten"
    ]:
        allowed_changed.add(
            "vbmeta"
        )

    _verify_passthrough_identity(
        source_images,
        realized_images,
        allowed_changed=allowed_changed,
    )

    infos: dict[str, str] = {}

    #
    # Cryptographically verify each non-root AVB image first.
    #
    # Root vbmeta is special: its chain descriptors delegate trust to
    # boot, init_boot, vbmeta_system, and vbmeta_vendor. avbtool must
    # explicitly follow those chain partitions so the complete graph
    # is traversed and each child is checked against the exact public
    # key carried by its parent chain descriptor.
    #
    for name in REQUIRED_PARTITIONS:
        if name == "vbmeta":
            continue

        path = realized_images[name]

        _verify_avb_image(
            avbtool,
            path,
        )

        infos[name] = _info_image(
            avbtool,
            path,
        )

    _verify_avb_image(
        avbtool,
        realized_images["vbmeta"],
        follow_chain_partitions=True,
    )

    infos["vbmeta"] = _info_image(
        avbtool,
        realized_images["vbmeta"],
    )

    chain_edges = (
        _verify_chain_edges(
            infos
        )
    )

    _verify_descriptor_graph(
        infos
    )

    #
    # Root and child vbmeta are intentionally preserved byte-for-byte
    # in the compatible-trust path.
    #
    identity_required = {
        "vbmeta_system",
        "vbmeta_vendor",
    }

    if not trust_realization[
        "root_vbmeta_rewritten"
    ]:
        identity_required.add(
            "vbmeta"
        )

    for name in sorted(
        identity_required
    ):
        if (
            _sha256(
                source_images[name]
            )
            != _sha256(
                realized_images[name]
            )
        ):
            raise TreeForgeBootstrapAvbGraphError(
                f"{name} unexpectedly changed"
            )

    if trust_realization[
        "root_vbmeta_rewritten"
    ]:
        if (
            _sha256(
                source_images["vbmeta"]
            )
            == _sha256(
                realized_images["vbmeta"]
            )
        ):
            raise TreeForgeBootstrapAvbGraphError(
                "root vbmeta rewrite was required "
                "but root identity did not change"
            )

    source_identity = (
        source_manifest.get(
            "identity",
            {}
        )
        if source_manifest
        else {}
    )

    artifact_records = []

    for name in REQUIRED_PARTITIONS:
        source_path = source_images[name]
        realized_path = realized_images[name]

        if name == "boot":
            role = (
                "kernel-provider+avb-resigned"
                if trust_realization[
                    "root_vbmeta_rewritten"
                ]
                else "kernel-provider"
            )

        elif name == "init_boot":
            role = (
                "bootstrap-runtime+avb-resigned"
                if trust_realization[
                    "root_vbmeta_rewritten"
                ]
                else "bootstrap-runtime"
            )

        elif (
            name == "vbmeta"
            and trust_realization[
                "root_vbmeta_rewritten"
            ]
        ):
            role = "avb-root-rewrite"

        else:
            role = "device-backup-passthrough"

        artifact_records.append(
            {
                "partition": name,
                "role": role,
                "source_path":
                    str(source_path),

                "source_sha256":
                    _sha256(
                        source_path
                    ),

                "realized_file":
                    f"{name}.img",

                "realized_sha256":
                    _sha256(
                        realized_path
                    ),

                "size_bytes":
                    realized_path.stat().st_size,
            }
        )

    manifest = {
        "schema": 1,

        "family":
            "treeforge-bootstrap-realized-family",

        "device":
            source_identity.get(
                "product",
                "tangorpro",
            ),

        "android_release":
            source_identity.get(
                "android_release",
                "15",
            ),

        "build_id":
            source_identity.get(
                "build_id",
            ),

        "source_slot":
            source_identity.get(
                "source_slot",
            ),

        "input_family":
            str(input_root),

        "source_manifest":
            (
                str(source_manifest_path)
                if source_manifest_path
                else None
            ),

        "artifact_count":
            len(artifact_records),

        "artifacts":
            artifact_records,

        "avb": {
            "verified":
                True,

            "graph_policy":
                trust_realization[
                    "graph_policy"
                ],

            "root_vbmeta_rewritten":
                trust_realization[
                    "root_vbmeta_rewritten"
                ],

            "vbmeta_system_rewritten":
                False,

            "vbmeta_vendor_rewritten":
                False,

            "source_boot_chain_public_key_sha1":
                trust_realization[
                    "source_boot_chain_public_key_sha1"
                ],

            "realized_boot_chain_public_key_sha1":
                trust_realization[
                    "realized_boot_chain_public_key_sha1"
                ],

            "root_signing_identity_preserved":
                trust_realization[
                    "root_signing_identity_preserved"
                ],

            "bootloader_root_trust_update_required":
                trust_realization[
                    "bootloader_root_trust_update_required"
                ],


            "keyset_id":
                keyset_id,

            "keyset_manifest_sha256":
                keyset_manifest_sha256,

            "chain_edges":
                chain_edges,

            "root_public_key_sha1":
                _header_fields(
                    infos["vbmeta"]
                ).get(
                    "Public key (sha1)"
                ),

            "root_algorithm":
                _header_fields(
                    infos["vbmeta"]
                ).get(
                    "Algorithm"
                ),

            "root_rollback_index":
                _header_fields(
                    infos["vbmeta"]
                ).get(
                    "Rollback Index"
                ),

            "root_flags":
                _header_fields(
                    infos["vbmeta"]
                ).get(
                    "Flags"
                ),

            "root_descriptor_targets":
                list(
                    ROOT_DESCRIPTOR_TARGETS
                ),

            "system_descriptor_targets":
                list(
                    SYSTEM_DESCRIPTOR_TARGETS
                ),

            "vendor_descriptor_targets":
                list(
                    VENDOR_DESCRIPTOR_TARGETS
                ),
        },

        "verification": {
            "source_family_complete":
                True,

            "all_images_avb_verified":
                True,

            "all_chain_edges_verified":
                True,

            "all_descriptor_bindings_verified":
                True,

            "passthrough_identity_verified":
                True,

            "publishable":
                True,
        },
    }

    manifest_path = (
        REALIZED_WORK
        / "manifest.json"
    )

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    expected_publication = {
        f"{name}.img"
        for name in REQUIRED_PARTITIONS
    }

    expected_publication.add(
        "manifest.json"
    )

    actual_publication = {
        path.name
        for path in REALIZED_WORK.iterdir()
    }

    if (
        actual_publication
        != expected_publication
    ):
        unexpected = sorted(
            actual_publication
            - expected_publication
        )

        missing = sorted(
            expected_publication
            - actual_publication
        )

        raise TreeForgeBootstrapAvbGraphError(
            "realized publication contains "
            "unexpected or missing artifacts: "
            f"unexpected={unexpected}, "
            f"missing={missing}"
        )

    #
    # Public-key blobs are realization scratch, not family artifacts.
    #
    shutil.rmtree(
        REALIZED_KEY_WORK
    )

    realized_out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REALIZED_WORK.replace(
        realized_out
    )

    print(
        "TreeForge Bootstrap "
        "Realized Family"
    )
    print(
        "=============================="
    )
    print()

    print(
        f"Input family: {input_root}"
    )
    print(
        f"Output:       {realized_out}"
    )
    print(
        "Artifacts:    "
        f"{len(REQUIRED_PARTITIONS)}/"
        f"{len(REQUIRED_PARTITIONS)}"
    )
    print()

    for name in REQUIRED_PARTITIONS:
        path = (
            realized_out
            / f"{name}.img"
        )

        print(
            f"{name}: "
            f"{path.stat().st_size} "
            f"{_sha256(path)}"
        )

    print()
    print(
        "AVB_GRAPH_POLICY="
        + str(
            trust_realization[
                "graph_policy"
            ]
        ).upper().replace(
            "-",
            "_",
        )
    )
    print(
        "BOOT_AVB_VERIFIED=PASS"
    )
    print(
        "INIT_BOOT_AVB_VERIFIED=PASS"
    )
    print(
        "ROOT_CHAIN_BOOT_2=PASS"
    )
    print(
        "ROOT_CHAIN_INIT_BOOT_4=PASS"
    )
    print(
        "ROOT_CHAIN_VBMETA_SYSTEM_1=PASS"
    )
    print(
        "ROOT_CHAIN_VBMETA_VENDOR_3=PASS"
    )
    print(
        "ROOT_DESCRIPTOR_BINDINGS=PASS"
    )
    print(
        "VBMETA_SYSTEM_BINDINGS=PASS"
    )
    print(
        "VBMETA_VENDOR_BINDINGS=PASS"
    )
    print(
        "VBMETA_REWRITE_REQUIRED="
        + (
            "YES"
            if trust_realization[
                "root_vbmeta_rewritten"
            ]
            else "NO"
        )
    )

    print(
        "BOOTLOADER_ROOT_TRUST_UPDATE_REQUIRED="
        + (
            "YES"
            if trust_realization[
                "bootloader_root_trust_update_required"
            ]
            else "NO"
        )
    )
    print(
        "REALIZED_ARTIFACT_COUNT=15"
    )
    print(
        "TREEFORGE_BOOTSTRAP_AVB_GRAPH_VERIFY=PASS"
    )
    print(
        "TREEFORGE_BOOTSTRAP_REALIZE_FAMILY=PASS"
    )

    return realized_out
