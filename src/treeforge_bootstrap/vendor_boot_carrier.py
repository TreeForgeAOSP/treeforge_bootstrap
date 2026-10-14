from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from .host_providers import ensure_host_tool
from .newc import build_newc


class TreeForgeVendorBootCarrierError(
    RuntimeError
):
    pass


TREEFORGE_FRAGMENT_NAME = (
    "treeforge_bootstrap"
)

TREEFORGE_FRAGMENT_TYPE = 1

TREEFORGE_MARKER = (
    b"TREEFORGE_BOOTSTRAP_VENDOR_BOOT_CARRIER_V1\n"
)

TREEFORGE_TRANSACTION_REQUEST_ENTRY = (
    "transaction/request-v1"
)

TREEFORGE_TRANSACTION_REQUEST_PREFIX = (
    b"TREEFORGE_BOOTSTRAP_TRANSACTION_V1\nid="
)

TREEFORGE_TRANSACTION_REQUEST_SUFFIX = (
    b"\noperation=proof\n"
)

TREEFORGE_TRANSACTION_REQUEST_BYTES = (
    len(TREEFORGE_TRANSACTION_REQUEST_PREFIX)
    + 64
    + len(TREEFORGE_TRANSACTION_REQUEST_SUFFIX)
)


#
# TreeForge Bootstrap retained carrier ABI v1.
#
# The carrier itself is a single regular file in the appended
# TreeForge vendor-ramdisk stream:
#
#     /treeforge/bootstrap-carrier
#
# Initial Bootstrap PID1 opens that file and retains its open file
# description across Android FirstStageMain / FreeRamdisk.
#
# Keep the binary format deliberately simple so the freestanding
# dispatcher can validate and consume it without libc, JSON, tar,
# CPIO, or another parser.
#
# Header, records, and integer fields are little-endian.
#
BOOTSTRAP_CARRIER_MAGIC = (
    b"TFBCAR01"
)

BOOTSTRAP_CARRIER_SCHEMA = 1

BOOTSTRAP_CARRIER_HEADER_BYTES = 96

BOOTSTRAP_CARRIER_RECORD_BYTES = 128

BOOTSTRAP_CARRIER_ENTRY_FILE = 1

_BOOTSTRAP_CARRIER_HEADER = (
    struct.Struct(
        "<8sIIIIQQQ32s16s"
    )
)

_BOOTSTRAP_CARRIER_RECORD = (
    struct.Struct(
        "<64sIIQQ32s8s"
    )
)


if (
    _BOOTSTRAP_CARRIER_HEADER.size
    != BOOTSTRAP_CARRIER_HEADER_BYTES
):
    raise RuntimeError(
        "Bootstrap carrier header ABI size changed"
    )


if (
    _BOOTSTRAP_CARRIER_RECORD.size
    != BOOTSTRAP_CARRIER_RECORD_BYTES
):
    raise RuntimeError(
        "Bootstrap carrier record ABI size changed"
    )


@dataclass(
    frozen=True,
    slots=True,
)
class BootstrapCarrierEntry:
    name: str
    mode: int
    payload: bytes


def _validate_carrier_entry_name(
    name: str,
) -> bytes:
    try:
        encoded = name.encode(
            "ascii"
        )
    except UnicodeEncodeError as error:
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier entry name "
            "must be ASCII"
        ) from error

    if (
        not encoded
        or len(encoded) > 63
        or name.startswith("/")
        or name.endswith("/")
        or "//" in name
        or re.fullmatch(
            r"[a-z0-9][a-z0-9._/-]*",
            name,
        )
        is None
    ):
        raise TreeForgeVendorBootCarrierError(
            "invalid Bootstrap carrier entry "
            f"name: {name!r}"
        )

    components = name.split(
        "/"
    )

    if any(
        component in {
            "",
            ".",
            "..",
        }
        for component in components
    ):
        raise TreeForgeVendorBootCarrierError(
            "unsafe Bootstrap carrier entry "
            f"name: {name!r}"
        )

    return encoded


def _validate_carrier_mode(
    mode: int,
) -> None:
    if (
        not isinstance(
            mode,
            int,
        )
        or mode < 0
        or mode > 0o7777
    ):
        raise TreeForgeVendorBootCarrierError(
            "invalid Bootstrap carrier "
            f"mode: {mode!r}"
        )


def _validate_transaction_request(
    request: bytes,
) -> bytes:
    if not isinstance(
        request,
        bytes,
    ):
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap transaction request "
            "must be bytes"
        )

    if (
        len(request)
        != TREEFORGE_TRANSACTION_REQUEST_BYTES
        or not request.startswith(
            TREEFORGE_TRANSACTION_REQUEST_PREFIX
        )
        or not request.endswith(
            TREEFORGE_TRANSACTION_REQUEST_SUFFIX
        )
    ):
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap transaction request "
            "has invalid canonical form"
        )

    id_start = len(
        TREEFORGE_TRANSACTION_REQUEST_PREFIX
    )

    transaction_id = request[
        id_start:
        id_start + 64
    ]

    if any(
        value not in b"0123456789abcdef"
        for value in transaction_id
    ):
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap transaction request "
            "has invalid transaction ID"
        )

    return request


def build_bootstrap_carrier_blob(
    entries: tuple[
        BootstrapCarrierEntry,
        ...,
    ],
) -> bytes:
    ordered = tuple(
        sorted(
            entries,
            key=lambda entry:
                entry.name,
        )
    )

    names = [
        entry.name
        for entry in ordered
    ]

    if len(names) != len(
        set(names)
    ):
        raise TreeForgeVendorBootCarrierError(
            "duplicate Bootstrap carrier "
            "entry name"
        )

    payload_offset = (
        BOOTSTRAP_CARRIER_HEADER_BYTES
        + (
            len(ordered)
            * BOOTSTRAP_CARRIER_RECORD_BYTES
        )
    )

    payload_chunks: list[
        bytes
    ] = []

    records: list[
        bytes
    ] = []

    cursor = payload_offset

    for entry in ordered:
        name = (
            _validate_carrier_entry_name(
                entry.name
            )
        )

        _validate_carrier_mode(
            entry.mode
        )

        if not isinstance(
            entry.payload,
            bytes,
        ):
            raise TreeForgeVendorBootCarrierError(
                "Bootstrap carrier payload "
                f"is not bytes: {entry.name}"
            )

        padded_name = (
            name
            + (
                b"\0"
                * (
                    64
                    - len(name)
                )
            )
        )

        digest = hashlib.sha256(
            entry.payload
        ).digest()

        record = (
            _BOOTSTRAP_CARRIER_RECORD.pack(
                padded_name,
                BOOTSTRAP_CARRIER_ENTRY_FILE,
                entry.mode,
                cursor,
                len(
                    entry.payload
                ),
                digest,
                b"\0" * 8,
            )
        )

        records.append(
            record
        )

        payload_chunks.append(
            entry.payload
        )

        cursor += len(
            entry.payload
        )

    table = b"".join(
        records
    )

    payload = b"".join(
        payload_chunks
    )

    table_digest = hashlib.sha256(
        table
    ).digest()

    total_bytes = (
        payload_offset
        + len(payload)
    )

    header = (
        _BOOTSTRAP_CARRIER_HEADER.pack(
            BOOTSTRAP_CARRIER_MAGIC,
            BOOTSTRAP_CARRIER_SCHEMA,
            BOOTSTRAP_CARRIER_HEADER_BYTES,
            BOOTSTRAP_CARRIER_RECORD_BYTES,
            len(ordered),
            BOOTSTRAP_CARRIER_HEADER_BYTES,
            payload_offset,
            total_bytes,
            table_digest,
            b"\0" * 16,
        )
    )

    blob = (
        header
        + table
        + payload
    )

    if len(blob) != total_bytes:
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier total size "
            "does not match encoded header"
        )

    return blob


def parse_bootstrap_carrier_blob(
    blob: bytes,
) -> tuple[
    BootstrapCarrierEntry,
    ...,
]:
    if not isinstance(
        blob,
        bytes,
    ):
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier blob "
            "is not bytes"
        )

    if len(blob) < (
        BOOTSTRAP_CARRIER_HEADER_BYTES
    ):
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier is "
            "shorter than its header"
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
    ) = (
        _BOOTSTRAP_CARRIER_HEADER.unpack_from(
            blob,
            0,
        )
    )

    if magic != BOOTSTRAP_CARRIER_MAGIC:
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier magic changed"
        )

    if schema != BOOTSTRAP_CARRIER_SCHEMA:
        raise TreeForgeVendorBootCarrierError(
            "unsupported Bootstrap carrier "
            f"schema: {schema}"
        )

    if (
        header_bytes
        != BOOTSTRAP_CARRIER_HEADER_BYTES
        or record_bytes
        != BOOTSTRAP_CARRIER_RECORD_BYTES
    ):
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier ABI sizes changed"
        )

    if table_offset != header_bytes:
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier table offset "
            "is not canonical"
        )

    expected_payload_offset = (
        table_offset
        + (
            entry_count
            * record_bytes
        )
    )

    if (
        payload_offset
        != expected_payload_offset
    ):
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier payload offset "
            "is not canonical"
        )

    if (
        total_bytes != len(blob)
        or total_bytes < payload_offset
    ):
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier total size "
            "is invalid"
        )

    if reserved != b"\0" * 16:
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier header "
            "reserved bytes are nonzero"
        )

    table = blob[
        table_offset:
        payload_offset
    ]

    if (
        hashlib.sha256(
            table
        ).digest()
        != table_digest
    ):
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier table "
            "digest mismatch"
        )

    result: list[
        BootstrapCarrierEntry
    ] = []

    previous_name: str | None = None

    cursor = payload_offset

    for index in range(
        entry_count
    ):
        offset = (
            index
            * record_bytes
        )

        (
            raw_name,
            kind,
            mode,
            payload_entry_offset,
            payload_size,
            payload_digest,
            record_reserved,
        ) = (
            _BOOTSTRAP_CARRIER_RECORD.unpack_from(
                table,
                offset,
            )
        )

        if (
            b"\0"
            not in raw_name
        ):
            raise TreeForgeVendorBootCarrierError(
                "Bootstrap carrier entry name "
                "is not NUL terminated"
            )

        name_bytes, padding = (
            raw_name.split(
                b"\0",
                1,
            )
        )

        if any(
            value != 0
            for value in padding
        ):
            raise TreeForgeVendorBootCarrierError(
                "Bootstrap carrier entry name "
                "padding is nonzero"
            )

        try:
            name = name_bytes.decode(
                "ascii"
            )
        except UnicodeDecodeError as error:
            raise TreeForgeVendorBootCarrierError(
                "Bootstrap carrier entry name "
                "is not ASCII"
            ) from error

        _validate_carrier_entry_name(
            name
        )

        _validate_carrier_mode(
            mode
        )

        if (
            kind
            != BOOTSTRAP_CARRIER_ENTRY_FILE
        ):
            raise TreeForgeVendorBootCarrierError(
                "unsupported Bootstrap carrier "
                f"entry type: {kind}"
            )

        if record_reserved != b"\0" * 8:
            raise TreeForgeVendorBootCarrierError(
                "Bootstrap carrier record "
                "reserved bytes are nonzero"
            )

        if (
            previous_name is not None
            and name <= previous_name
        ):
            raise TreeForgeVendorBootCarrierError(
                "Bootstrap carrier entries "
                "are not strictly sorted"
            )

        if payload_entry_offset != cursor:
            raise TreeForgeVendorBootCarrierError(
                "Bootstrap carrier payload "
                "layout is not canonical"
            )

        end = (
            payload_entry_offset
            + payload_size
        )

        if end > total_bytes:
            raise TreeForgeVendorBootCarrierError(
                "Bootstrap carrier payload "
                "extends past container"
            )

        payload = blob[
            payload_entry_offset:
            end
        ]

        if (
            hashlib.sha256(
                payload
            ).digest()
            != payload_digest
        ):
            raise TreeForgeVendorBootCarrierError(
                "Bootstrap carrier payload "
                f"digest mismatch: {name}"
            )

        result.append(
            BootstrapCarrierEntry(
                name=name,
                mode=mode,
                payload=payload,
            )
        )

        previous_name = name
        cursor = end

    if cursor != total_bytes:
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap carrier has "
            "unreferenced trailing bytes"
        )

    return tuple(
        result
    )


@dataclass(
    frozen=True,
    slots=True,
)
class VendorRamdiskFragment:
    ordinal: int
    path: Path
    ramdisk_type: int
    ramdisk_name: str
    board_id: tuple[int, ...]


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
    argv: list[str | Path],
    *,
    cwd: Path | None = None,
    data: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    command = [
        str(value)
        for value in argv
    ]

    completed = subprocess.run(
        command,
        cwd=cwd,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if completed.returncode != 0:
        raise TreeForgeVendorBootCarrierError(
            "command failed:\n"
            + " ".join(command)
            + "\n"
            + completed.stdout.decode(
                errors="replace"
            )[-4000:]
            + completed.stderr.decode(
                errors="replace"
            )[-4000:]
        )

    return completed


def _resolve_argument_path(
    value: str,
    unpack_root: Path,
) -> Path:
    path = Path(
        value
    )

    if path.is_file():
        return path.resolve()

    candidate = (
        unpack_root
        / path.name
    )

    if candidate.is_file():
        return candidate.resolve()

    raise TreeForgeVendorBootCarrierError(
        "unpack_bootimg argument does not "
        f"identify a materialized file: {value}"
    )


def _unpack_arguments(
    unpack_bootimg: Path,
    image: Path,
    destination: Path,
) -> list[str]:
    if destination.exists():
        shutil.rmtree(
            destination
        )

    destination.mkdir(
        parents=True
    )

    completed = _run(
        [
            unpack_bootimg,
            "--boot_img",
            image,
            "--out",
            destination,
            "--format=mkbootimg",
            "-0",
        ]
    )

    raw = completed.stdout

    if b"\0" not in raw:
        raise TreeForgeVendorBootCarrierError(
            "unpack_bootimg did not return "
            "the required NUL-delimited "
            "mkbootimg argument stream"
        )

    values = raw.split(
        b"\0"
    )

    while (
        values
        and values[-1] in {
            b"",
            b"\n",
        }
    ):
        values.pop()

    arguments = [
        value.decode(
            "utf-8",
            errors="surrogateescape",
        )
        for value in values
    ]

    if (
        "--header_version"
        not in arguments
    ):
        raise TreeForgeVendorBootCarrierError(
            "canonical mkbootimg argument "
            "stream has no header version"
        )

    return arguments


def _flag_values(
    arguments: list[str],
    *,
    start: int,
    end: int,
    flag: str,
) -> list[str]:
    values: list[str] = []

    index = start

    while index < end:
        if arguments[index] != flag:
            index += 1
            continue

        if index + 1 >= end:
            raise TreeForgeVendorBootCarrierError(
                f"argument has no value: {flag}"
            )

        values.append(
            arguments[index + 1]
        )

        index += 2

    return values


def _fragments(
    arguments: list[str],
    unpack_root: Path,
) -> tuple[
    VendorRamdiskFragment,
    ...,
]:
    indexes = [
        index
        for index, value
        in enumerate(arguments)
        if (
            value
            == "--vendor_ramdisk_fragment"
        )
    ]

    if not indexes:
        raise TreeForgeVendorBootCarrierError(
            "vendor_boot contains no "
            "vendor ramdisk fragments"
        )

    result: list[
        VendorRamdiskFragment
    ] = []

    group_start = 0

    for ordinal, index in enumerate(
        indexes
    ):
        if index + 1 >= len(arguments):
            raise TreeForgeVendorBootCarrierError(
                "vendor ramdisk fragment "
                "argument has no path"
            )

        group_end = index + 2

        type_values = _flag_values(
            arguments,
            start=group_start,
            end=group_end,
            flag="--ramdisk_type",
        )

        name_values = _flag_values(
            arguments,
            start=group_start,
            end=group_end,
            flag="--ramdisk_name",
        )

        if len(type_values) != 1:
            raise TreeForgeVendorBootCarrierError(
                "vendor ramdisk group must "
                "contain exactly one "
                "--ramdisk_type"
            )

        if len(name_values) != 1:
            raise TreeForgeVendorBootCarrierError(
                "vendor ramdisk group must "
                "contain exactly one "
                "--ramdisk_name"
            )

        try:
            ramdisk_type = int(
                type_values[0],
                0,
            )
        except ValueError as error:
            raise TreeForgeVendorBootCarrierError(
                "invalid vendor ramdisk type"
            ) from error

        board: list[int] = []

        for board_index in range(
            16
        ):
            values = _flag_values(
                arguments,
                start=group_start,
                end=group_end,
                flag=(
                    f"--board_id"
                    f"{board_index}"
                ),
            )

            if len(values) > 1:
                raise TreeForgeVendorBootCarrierError(
                    "duplicate vendor ramdisk "
                    f"board_id{board_index}"
                )

            if not values:
                board.append(
                    0
                )
                continue

            try:
                board.append(
                    int(
                        values[0],
                        0,
                    )
                )
            except ValueError as error:
                raise TreeForgeVendorBootCarrierError(
                    "invalid vendor ramdisk "
                    f"board_id{board_index}"
                ) from error

        result.append(
            VendorRamdiskFragment(
                ordinal=ordinal,
                path=(
                    _resolve_argument_path(
                        arguments[
                            index + 1
                        ],
                        unpack_root,
                    )
                ),
                ramdisk_type=(
                    ramdisk_type
                ),
                ramdisk_name=(
                    name_values[0]
                ),
                board_id=tuple(
                    board
                ),
            )
        )

        group_start = (
            group_end
        )

    return tuple(
        result
    )


def _global_signature(
    arguments: list[str],
    unpack_root: Path,
) -> tuple[
    tuple[str, ...],
    ...,
]:
    fragment_flags = {
        "--ramdisk_type",
        "--ramdisk_name",
        "--vendor_ramdisk_fragment",
    }

    fragment_flags.update(
        f"--board_id{index}"
        for index in range(16)
    )

    file_flags = {
        "--vendor_bootconfig",
        "--dtb",
    }

    result: list[
        tuple[str, ...]
    ] = []

    index = 0

    while index < len(
        arguments
    ):
        value = arguments[
            index
        ]

        if value in fragment_flags:
            if index + 1 >= len(
                arguments
            ):
                raise TreeForgeVendorBootCarrierError(
                    f"argument has no value: {value}"
                )

            index += 2
            continue

        if value == "--vendor_boot":
            if index + 1 >= len(
                arguments
            ):
                raise TreeForgeVendorBootCarrierError(
                    "--vendor_boot has no value"
                )

            index += 2
            continue

        if value in file_flags:
            if index + 1 >= len(
                arguments
            ):
                raise TreeForgeVendorBootCarrierError(
                    f"argument has no value: {value}"
                )

            path = _resolve_argument_path(
                arguments[index + 1],
                unpack_root,
            )

            result.append(
                (
                    value,
                    str(
                        path.stat().st_size
                    ),
                    _sha256(
                        path
                    ),
                )
            )

            index += 2
            continue

        result.append(
            (
                value,
            )
        )

        index += 1

    return tuple(
        result
    )


def _build_proof_fragment(
    root: Path,
    *,
    transaction_request: bytes | None = None,
) -> Path:
    stage = (
        root
        / "fragment-root"
    )

    payload_directory = (
        stage
        / "treeforge"
    )

    payload_directory.mkdir(
        parents=True
    )

    stage.chmod(
        0o755
    )

    payload_directory.chmod(
        0o755
    )

    marker = (
        payload_directory
        / "bootstrap-carrier"
    )

    entries = [
        BootstrapCarrierEntry(
            name="proof/retained-fd",
            mode=0o444,
            payload=TREEFORGE_MARKER,
        ),
    ]

    if transaction_request is not None:
        entries.append(
            BootstrapCarrierEntry(
                name=(
                    TREEFORGE_TRANSACTION_REQUEST_ENTRY
                ),
                mode=0o644,
                payload=(
                    _validate_transaction_request(
                        transaction_request
                    )
                ),
            )
        )

    carrier_blob = (
        build_bootstrap_carrier_blob(
            tuple(entries)
        )
    )

    marker.write_bytes(
        carrier_blob
    )

    marker.chmod(
        0o644
    )

    cpio = (
        root
        / "treeforge-bootstrap.cpio"
    )

    build_newc(
        stage,
        cpio,
    )

    lz4 = shutil.which(
        "lz4"
    )

    if lz4 is None:
        raise TreeForgeVendorBootCarrierError(
            "lz4 is unavailable"
        )

    compressed = (
        root
        / "treeforge-bootstrap.lz4"
    )

    result = _run(
        [
            lz4,
            "-l",
            "-12",
            "-c",
        ],
        data=cpio.read_bytes(),
    )

    compressed.write_bytes(
        result.stdout
    )

    if (
        compressed.read_bytes()[:4]
        != b"\x02\x21\x4c\x18"
    ):
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap vendor ramdisk "
            "fragment is not legacy LZ4"
        )

    if compressed.stat().st_size == 0:
        raise TreeForgeVendorBootCarrierError(
            "Bootstrap vendor ramdisk "
            "fragment is empty"
        )

    return compressed

def _build_combined_fragment(
    *,
    factory_fragment: Path,
    proof_fragment: Path,
    root: Path,
) -> Path:
    """
    Build the tangorpro vendor ramdisk carrier.

    Hardware proved that introducing a second vendor ramdisk table
    entry is not sufficient on this device.  Preserve the complete
    canonical factory fragment byte-for-byte as the prefix of the
    existing table entry and append TreeForge's independent legacy-LZ4
    initramfs stream to that same payload.

    The source archive is never unpacked or rewritten.
    """
    output = (
        root
        / "treeforge-bootstrap-combined-vendor-ramdisk"
    )

    factory_bytes = (
        factory_fragment.read_bytes()
    )

    proof_bytes = (
        proof_fragment.read_bytes()
    )

    if not factory_bytes:
        raise TreeForgeVendorBootCarrierError(
            "canonical factory vendor ramdisk "
            "fragment is empty"
        )

    if not proof_bytes:
        raise TreeForgeVendorBootCarrierError(
            "TreeForge vendor ramdisk stream "
            "is empty"
        )

    output.write_bytes(
        factory_bytes
        + proof_bytes
    )

    if (
        output.stat().st_size
        != (
            len(factory_bytes)
            + len(proof_bytes)
        )
    ):
        raise TreeForgeVendorBootCarrierError(
            "combined vendor ramdisk size "
            "is incorrect"
        )

    combined = output.read_bytes()

    if (
        combined[
            :len(factory_bytes)
        ]
        != factory_bytes
    ):
        raise TreeForgeVendorBootCarrierError(
            "canonical factory vendor ramdisk "
            "prefix identity changed"
        )

    if (
        combined[
            len(factory_bytes):
        ]
        != proof_bytes
    ):
        raise TreeForgeVendorBootCarrierError(
            "TreeForge appended vendor ramdisk "
            "stream identity changed"
        )

    return output



def _avb_info(
    avbtool: Path,
    image: Path,
) -> str:
    return _run(
        [
            avbtool,
            "info_image",
            "--image",
            image,
        ]
    ).stdout.decode(
        errors="replace"
    )


def _header_value(
    info: str,
    label: str,
) -> str:
    match = re.search(
        rf"^{re.escape(label)}:\s*(.*?)\s*$",
        info,
        flags=re.MULTILINE,
    )

    if match is None:
        raise TreeForgeVendorBootCarrierError(
            f"AVB field missing: {label}"
        )

    return match.group(
        1
    )


def _indented_values(
    info: str,
    label: str,
) -> list[str]:
    return re.findall(
        rf"^\s+{re.escape(label)}:\s*(.*?)\s*$",
        info,
        flags=re.MULTILINE,
    )


def _avb_properties(
    info: str,
) -> tuple[
    tuple[str, str],
    ...,
]:
    return tuple(
        re.findall(
            r"^\s+Prop: (.*?) -> '(.*)'$",
            info,
            flags=re.MULTILINE,
        )
    )


def _hash_footer_contract(
    avbtool: Path,
    source: Path,
) -> dict[
    str,
    object,
]:
    info = _avb_info(
        avbtool,
        source,
    )

    partition_names = (
        _indented_values(
            info,
            "Partition Name",
        )
    )

    hash_algorithms = (
        _indented_values(
            info,
            "Hash Algorithm",
        )
    )

    salts = (
        _indented_values(
            info,
            "Salt",
        )
    )

    if partition_names != [
        "vendor_boot"
    ]:
        raise TreeForgeVendorBootCarrierError(
            "source vendor_boot must contain "
            "exactly one vendor_boot hash descriptor"
        )

    if len(hash_algorithms) != 1:
        raise TreeForgeVendorBootCarrierError(
            "source vendor_boot hash algorithm "
            "is ambiguous"
        )

    if len(salts) != 1:
        raise TreeForgeVendorBootCarrierError(
            "source vendor_boot AVB salt "
            "is ambiguous"
        )

    descriptor_flags = (
        _indented_values(
            info,
            "Flags",
        )
    )

    if any(
        value != "0"
        for value in descriptor_flags
    ):
        raise TreeForgeVendorBootCarrierError(
            "source vendor_boot contains "
            "unsupported AVB descriptor flags"
        )

    return {
        "partition_name":
            "vendor_boot",

        "hash_algorithm":
            hash_algorithms[0],

        "salt":
            salts[0],

        "properties":
            _avb_properties(
                info
            ),
    }


def _add_hash_footer(
    avbtool: Path,
    *,
    output: Path,
    partition_size: int,
    contract: dict[
        str,
        object,
    ],
) -> None:
    command: list[
        str | Path
    ] = [
        avbtool,
        "add_hash_footer",

        "--image",
        output,

        "--partition_name",
        str(
            contract[
                "partition_name"
            ]
        ),

        "--partition_size",
        str(
            partition_size
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

    for key, value in (
        contract[
            "properties"
        ]
    ):
        command.extend(
            [
                "--prop",
                f"{key}:{value}",
            ]
        )

    _run(
        command
    )


def _without_output_argument(
    arguments: list[str],
) -> list[str]:
    result: list[str] = []

    index = 0

    while index < len(
        arguments
    ):
        if (
            arguments[index]
            == "--vendor_boot"
        ):
            if index + 1 >= len(
                arguments
            ):
                raise TreeForgeVendorBootCarrierError(
                    "--vendor_boot has no value"
                )

            index += 2
            continue

        result.append(
            arguments[
                index
            ]
        )

        index += 1

    return result



def _verify_final(
    *,
    source: Path,
    output: Path,
    proof_fragment: Path,
    unpack_bootimg: Path,
    avbtool: Path,
    source_sha256: str,
    source_contract: dict[
        str,
        object,
    ],
    root: Path,
) -> None:
    source_unpack = (
        root
        / "verify-source"
    )

    final_unpack = (
        root
        / "verify-final"
    )

    source_arguments = (
        _unpack_arguments(
            unpack_bootimg,
            source,
            source_unpack,
        )
    )

    final_arguments = (
        _unpack_arguments(
            unpack_bootimg,
            output,
            final_unpack,
        )
    )

    source_fragments = (
        _fragments(
            source_arguments,
            source_unpack,
        )
    )

    final_fragments = (
        _fragments(
            final_arguments,
            final_unpack,
        )
    )

    if len(source_fragments) != 1:
        raise TreeForgeVendorBootCarrierError(
            "tangorpro vendor_boot carrier "
            "requires exactly one canonical "
            "factory vendor ramdisk fragment"
        )

    if len(final_fragments) != 1:
        raise TreeForgeVendorBootCarrierError(
            "final tangorpro vendor_boot must "
            "retain exactly one vendor ramdisk "
            "table entry"
        )

    if (
        _global_signature(
            source_arguments,
            source_unpack,
        )
        !=
        _global_signature(
            final_arguments,
            final_unpack,
        )
    ):
        raise TreeForgeVendorBootCarrierError(
            "vendor_boot global mkbootimg "
            "semantics changed"
        )

    source_fragment = (
        source_fragments[0]
    )

    final_fragment = (
        final_fragments[0]
    )

    if (
        source_fragment.ramdisk_type
        != final_fragment.ramdisk_type
        or source_fragment.ramdisk_name
        != final_fragment.ramdisk_name
        or source_fragment.board_id
        != final_fragment.board_id
    ):
        raise TreeForgeVendorBootCarrierError(
            "canonical factory vendor ramdisk "
            "metadata changed"
        )

    factory_bytes = (
        source_fragment.path.read_bytes()
    )

    proof_bytes = (
        proof_fragment.read_bytes()
    )

    final_bytes = (
        final_fragment.path.read_bytes()
    )

    expected_size = (
        len(factory_bytes)
        + len(proof_bytes)
    )

    if len(final_bytes) != expected_size:
        raise TreeForgeVendorBootCarrierError(
            "combined vendor ramdisk payload "
            "size is incorrect"
        )

    if (
        final_bytes[
            :len(factory_bytes)
        ]
        != factory_bytes
    ):
        raise TreeForgeVendorBootCarrierError(
            "canonical factory vendor ramdisk "
            "prefix identity changed"
        )

    if (
        final_bytes[
            len(factory_bytes):
        ]
        != proof_bytes
    ):
        raise TreeForgeVendorBootCarrierError(
            "TreeForge vendor ramdisk stream "
            "was not appended exactly"
        )

    if (
        _sha256(
            source
        )
        != source_sha256
    ):
        raise TreeForgeVendorBootCarrierError(
            "source vendor_boot changed "
            "during reconstruction"
        )

    final_info = _avb_info(
        avbtool,
        output,
    )

    _run(
        [
            avbtool,
            "verify_image",
            "--image",
            output,
        ]
    )

    if (
        _header_value(
            final_info,
            "Algorithm",
        )
        != "NONE"
    ):
        raise TreeForgeVendorBootCarrierError(
            "reconstructed vendor_boot must "
            "use descriptor-authenticated "
            "Algorithm NONE"
        )

    final_contract = (
        _hash_footer_contract(
            avbtool,
            output,
        )
    )

    for field in (
        "partition_name",
        "hash_algorithm",
        "salt",
        "properties",
    ):
        if (
            final_contract[field]
            != source_contract[field]
        ):
            raise TreeForgeVendorBootCarrierError(
                "vendor_boot AVB hash contract "
                f"changed: {field}"
            )




def realize_vendor_boot_carrier(
    *,
    source: Path,
    output: Path,
    transaction_request: bytes | None = None,
) -> Path:
    source = (
        source
        .expanduser()
        .resolve()
    )

    output = (
        output
        .expanduser()
        .absolute()
    )

    if not source.is_file():
        raise FileNotFoundError(
            source
        )

    if output.resolve() == source:
        raise TreeForgeVendorBootCarrierError(
            "vendor_boot reconstruction "
            "may not overwrite its source"
        )

    if output.exists():
        output.unlink()

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    unpack_bootimg = (
        ensure_host_tool(
            "unpack_bootimg"
        )
    )

    mkbootimg = (
        ensure_host_tool(
            "mkbootimg"
        )
    )

    avbtool = (
        ensure_host_tool(
            "avbtool"
        )
    )

    source_sha256 = (
        _sha256(
            source
        )
    )

    source_size = (
        source.stat().st_size
    )

    source_contract = (
        _hash_footer_contract(
            avbtool,
            source,
        )
    )

    with tempfile.TemporaryDirectory(
        prefix=".treeforge-vendor-boot-",
        dir=output.parent,
    ) as raw:
        temporary = Path(
            raw
        )

        source_unpack = (
            temporary
            / "source"
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
                source_arguments,
                source_unpack,
            )
        )

        #
        # Tangorpro hardware acceptance established that a newly added
        # second vendor ramdisk table entry is not exposed to the live
        # Bootstrap initramfs.  The supported carrier therefore has one
        # canonical source entry and one final entry.
        #
        if len(source_fragments) != 1:
            raise TreeForgeVendorBootCarrierError(
                "tangorpro vendor_boot carrier "
                "requires exactly one canonical "
                "factory vendor ramdisk fragment"
            )

        source_fragment = (
            source_fragments[0]
        )

        proof_fragment = (
            _build_proof_fragment(
                temporary,
                transaction_request=(
                    transaction_request
                ),
            )
        )

        proof_bytes = (
            proof_fragment.read_bytes()
        )

        factory_bytes = (
            source_fragment.path.read_bytes()
        )

        if factory_bytes.endswith(
            proof_bytes
        ):
            raise TreeForgeVendorBootCarrierError(
                "source vendor ramdisk already "
                "contains the TreeForge carrier "
                "stream"
            )

        combined_fragment = (
            _build_combined_fragment(
                factory_fragment=(
                    source_fragment.path
                ),
                proof_fragment=proof_fragment,
                root=temporary,
            )
        )

        arguments = (
            _without_output_argument(
                source_arguments
            )
        )

        fragment_indexes = [
            index
            for index, value
            in enumerate(arguments)
            if (
                value
                == "--vendor_ramdisk_fragment"
            )
        ]

        if len(fragment_indexes) != 1:
            raise TreeForgeVendorBootCarrierError(
                "canonical mkbootimg argument "
                "stream must contain exactly one "
                "vendor ramdisk fragment"
            )

        fragment_index = (
            fragment_indexes[0]
        )

        if (
            fragment_index + 1
            >= len(arguments)
        ):
            raise TreeForgeVendorBootCarrierError(
                "canonical vendor ramdisk "
                "fragment argument has no path"
            )

        #
        # Preserve every existing metadata argument exactly.  Replace
        # only the payload path for the existing table entry.
        #
        arguments[
            fragment_index + 1
        ] = str(
            combined_fragment
        )

        arguments.extend(
            [
                "--vendor_boot",
                str(
                    output
                ),
            ]
        )

        _run(
            [
                mkbootimg,
                *arguments,
            ]
        )

        if (
            not output.is_file()
            or output.stat().st_size == 0
        ):
            raise TreeForgeVendorBootCarrierError(
                "mkbootimg produced no "
                "vendor_boot image"
            )

        _add_hash_footer(
            avbtool,
            output=output,
            partition_size=source_size,
            contract=source_contract,
        )

        if (
            output.stat().st_size
            != source_size
        ):
            raise TreeForgeVendorBootCarrierError(
                "reconstructed vendor_boot "
                "partition size changed"
            )

        _verify_final(
            source=source,
            output=output,
            proof_fragment=proof_fragment,
            unpack_bootimg=unpack_bootimg,
            avbtool=avbtool,
            source_sha256=source_sha256,
            source_contract=source_contract,
            root=temporary,
        )

        print(
            "VENDOR_BOOT_SOURCE_SHA256="
            + source_sha256
        )

        print(
            "VENDOR_BOOT_SOURCE_FRAGMENT_COUNT=1"
        )

        print(
            "VENDOR_BOOT_FINAL_FRAGMENT_COUNT=1"
        )

        print(
            "FACTORY_FRAGMENT_BYTES="
            + str(
                len(factory_bytes)
            )
        )

        print(
            "FACTORY_FRAGMENT_SHA256="
            + _sha256(
                source_fragment.path
            )
        )

        print(
            "TREEFORGE_STREAM_BYTES="
            + str(
                len(proof_bytes)
            )
        )

        print(
            "TREEFORGE_STREAM_SHA256="
            + _sha256(
                proof_fragment
            )
        )

        print(
            "COMBINED_FRAGMENT_BYTES="
            + str(
                combined_fragment.stat().st_size
            )
        )

    print(
        "VENDOR_BOOT_OUTPUT="
        + str(
            output
        )
    )

    print(
        "VENDOR_BOOT_OUTPUT_SHA256="
        + _sha256(
            output
        )
    )

    print(
        "VENDOR_BOOT_OUTPUT_BYTES="
        + str(
            output.stat().st_size
        )
    )

    print(
        "VENDOR_BOOT_FACTORY_FRAGMENT_PREFIX_PRESERVED=PASS"
    )

    print(
        "VENDOR_BOOT_TREEFORGE_STREAM_APPENDED=PASS"
    )

    print(
        "VENDOR_BOOT_SINGLE_FRAGMENT_TABLE=PASS"
    )

    print(
        "VENDOR_BOOT_AVB_DESCRIPTOR_CONTRACT=PASS"
    )

    print(
        "TREEFORGE_VENDOR_BOOT_CARRIER=PASS"
    )

    return output



__all__ = [
    "BOOTSTRAP_CARRIER_ENTRY_FILE",
    "BOOTSTRAP_CARRIER_HEADER_BYTES",
    "BOOTSTRAP_CARRIER_MAGIC",
    "BOOTSTRAP_CARRIER_RECORD_BYTES",
    "BOOTSTRAP_CARRIER_SCHEMA",
    "BootstrapCarrierEntry",
    "TREEFORGE_FRAGMENT_NAME",
    "TREEFORGE_FRAGMENT_TYPE",
    "TreeForgeVendorBootCarrierError",
    "build_bootstrap_carrier_blob",
    "parse_bootstrap_carrier_blob",
    "realize_vendor_boot_carrier",
]
