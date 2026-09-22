from __future__ import annotations

import hashlib
import os

from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path
from pathlib import PurePosixPath

from .dispatcher import (
    TreeForgeDispatcherBuilder,
)

from .newc import (
    NewcArchive,
    build_newc,
    read_newc_archive,
    write_newc_archive,
)

from .paths import (
    PROJECT_ROOT,
    WORK,
)


CANONICAL_PROVIDER = (
    PROJECT_ROOT
    / "providers"
    / "google"
    / "tangorpro"
    / "android-15"
    / "init_boot.ramdisk.cpio"
)

CANONICAL_SHA256 = (
    "d9a027e3c06dc096cfb92e15251329c96f1d69e38954c2d0758da520b1f3078f"
)

ORIGINAL_INIT_NAME = (
    "init.treeforge-bootstrap-original"
)

FIRST_STAGE_INIT_NAME = (
    "init.treeforge-bootstrap-first-stage"
)

RETAINED_SOURCE_ROOT = (
    "treeforge-bootstrap-retained"
)

RUNTIME_DESTINATION_ROOT = (
    "/dev/treeforge-bootstrap-runtime"
)

TRANSITION_SOURCE = (
    b"/system/bin/init\x00"
)

TRANSITION_TARGET = (
    b"/proc/self/fd/99\x00"
)


class CanonicalInitramfsError(
    RuntimeError
):
    pass


@dataclass(frozen=True)
class CanonicalInitramfsBuild:
    output: Path
    dispatcher: Path
    dispatcher_sha256: str
    retained_file_count: int
    entry_count: int


def _sha256_bytes(
    data: bytes,
) -> str:
    return hashlib.sha256(
        data
    ).hexdigest()


def _sha256_path(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(
            lambda: stream.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def _canonical_archive() -> NewcArchive:
    if not CANONICAL_PROVIDER.is_file():
        raise CanonicalInitramfsError(
            "canonical Google init_boot CPIO "
            f"is missing: {CANONICAL_PROVIDER}"
        )

    identity = _sha256_path(
        CANONICAL_PROVIDER
    )

    if identity != CANONICAL_SHA256:
        raise CanonicalInitramfsError(
            "canonical Google init_boot CPIO "
            "identity changed: "
            f"{identity}"
        )

    return read_newc_archive(
        CANONICAL_PROVIDER
    )


def _canonical_init(
    archive: NewcArchive,
):
    matches = [
        entry
        for entry in archive.entries
        if entry.name.lstrip("/") == "init"
    ]

    if len(matches) != 1:
        raise CanonicalInitramfsError(
            "canonical Google archive must contain "
            "exactly one /init"
        )

    return matches[0]


def _patched_first_stage(
    canonical_init: bytes,
) -> bytes:
    if len(TRANSITION_SOURCE) != len(
        TRANSITION_TARGET
    ):
        raise CanonicalInitramfsError(
            "first-stage transition replacement "
            "changed literal length"
        )

    count = canonical_init.count(
        TRANSITION_SOURCE
    )

    if count != 1:
        raise CanonicalInitramfsError(
            "canonical init must contain exactly "
            "one /system/bin/init transition literal; "
            f"found {count}"
        )

    patched = canonical_init.replace(
        TRANSITION_SOURCE,
        TRANSITION_TARGET,
        1,
    )

    if len(patched) != len(
        canonical_init
    ):
        raise CanonicalInitramfsError(
            "first-stage init mutation changed "
            "binary size"
        )

    return patched


def _retained_files(
    stage: Path,
) -> tuple[
    tuple[str, str, int],
    ...
]:
    result: list[
        tuple[str, str, int]
    ] = []

    for name in (
        "treeforge-bootstrap-adb-service",
        "etc/treeforge-bootstrap-release",
    ):
        source = stage / name

        if not source.is_file():
            raise CanonicalInitramfsError(
                f"missing staged runtime: {source}"
            )

        result.append(
            (
                (
                    "/"
                    + RETAINED_SOURCE_ROOT
                    + "/"
                    + name
                ),
                (
                    RUNTIME_DESTINATION_ROOT
                    + "/"
                    + name
                ),
                source.stat().st_mode
                & 0o777,
            )
        )

    system = stage / "system"

    if not system.is_dir():
        raise CanonicalInitramfsError(
            f"staged adbd runtime missing: {system}"
        )

    for source in sorted(
        system.rglob("*")
    ):
        if not (
            source.is_file()
            or source.is_symlink()
        ):
            continue

        relative = source.relative_to(
            stage
        ).as_posix()

        result.append(
            (
                (
                    "/"
                    + RETAINED_SOURCE_ROOT
                    + "/"
                    + relative
                ),
                (
                    RUNTIME_DESTINATION_ROOT
                    + "/"
                    + relative
                ),
                source.stat().st_mode
                & 0o777,
            )
        )

    retained = tuple(result)

    if len(retained) > 256:
        raise CanonicalInitramfsError(
            "TreeForge Bootstrap retained runtime exceeds "
            f"bundle entry capacity: {len(retained)} > 256"
        )

    return retained


def _runtime_bundle(
    stage: Path,
    retained: tuple[
        tuple[str, str, int],
        ...,
    ],
) -> bytes:
    """
    Build the complete TreeForge Bootstrap retained runtime as one
    deterministic trailer carried inside the dispatcher /init ELF.

    Layout:

      TFRTB001
      u32 entry_count
      u32 reserved

      repeated:
        u32 destination_path_length
        u32 mode
        u64 payload_length
        destination_path bytes
        payload bytes

      Entry type:
        mode != 0: regular file; payload is file contents
        mode == 0: symbolic link; payload is NUL-terminated target

      TFRTEND1
      u64 body_length
    """

    source_prefix = (
        "/"
        + RETAINED_SOURCE_ROOT
        + "/"
    )

    destination_prefix = (
        RUNTIME_DESTINATION_ROOT
        + "/"
    )

    body = bytearray(
        b"TFRTB001"
    )

    body.extend(
        len(retained).to_bytes(
            4,
            "little",
        )
    )

    body.extend(
        (0).to_bytes(
            4,
            "little",
        )
    )

    for (
        source_path,
        destination_path,
        mode,
    ) in retained:
        if not source_path.startswith(
            source_prefix
        ):
            raise CanonicalInitramfsError(
                "retained runtime source is outside "
                "TreeForge Bootstrap retained root: "
                f"{source_path}"
            )

        if not destination_path.startswith(
            destination_prefix
        ):
            raise CanonicalInitramfsError(
                "retained runtime destination is outside "
                "TreeForge Bootstrap runtime root: "
                f"{destination_path}"
            )

        relative = destination_path[
            len(destination_prefix):
        ]

        host_source = (
            stage
            / relative
        )

        if not (
            host_source.is_file()
            or host_source.is_symlink()
        ):
            raise CanonicalInitramfsError(
                "retained runtime bundle host source missing: "
                f"{host_source}"
            )

        destination = (
            destination_path.encode(
                "ascii"
            )
        )

        if (
            len(destination) == 0
            or len(destination) >= 512
        ):
            raise CanonicalInitramfsError(
                "retained runtime destination exceeds "
                "FD99 bundle path capacity: "
                f"{destination_path}"
            )

        entry_mode = mode

        if host_source.is_symlink():
            target = str(
                host_source.readlink()
            )

            if (
                not target
                or "\x00" in target
            ):
                raise CanonicalInitramfsError(
                    "invalid retained runtime symlink target: "
                    f"{host_source}"
                )

            payload = (
                target.encode("utf-8")
                + b"\x00"
            )

            entry_mode = 0

        else:
            payload = (
                host_source.read_bytes()
            )

        body.extend(
            len(destination).to_bytes(
                4,
                "little",
            )
        )

        body.extend(
            int(entry_mode).to_bytes(
                4,
                "little",
            )
        )

        body.extend(
            len(payload).to_bytes(
                8,
                "little",
            )
        )

        body.extend(
            destination
        )

        body.extend(
            payload
        )

    trailer = (
        b"TFRTEND1"
        + len(body).to_bytes(
            8,
            "little",
        )
    )

    return (
        bytes(body)
        + trailer
    )


def _payload_entries(
    stage: Path,
    *,
    first_inode: int,
):
    work = (
        WORK
        / "canonical-initramfs"
    )

    work.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload_cpio = (
        work
        / "payload.cpio"
    )

    build_newc(
        stage,
        payload_cpio,
    )

    payload = read_newc_archive(
        payload_cpio
    )

    wanted_files = {
        "treeforge-bootstrap-adb-service",
        "etc/treeforge-bootstrap-release",
    }

    system = stage / "system"

    for source in sorted(
        system.rglob("*")
    ):
        if (
            source.is_file()
            or source.is_symlink()
        ):
            wanted_files.add(
                source.relative_to(
                    stage
                ).as_posix()
            )

    wanted = set(
        wanted_files
    )

    for name in tuple(
        wanted_files
    ):
        pure = PurePosixPath(
            name
        )

        for parent in pure.parents:
            value = parent.as_posix()

            if value == ".":
                continue

            wanted.add(
                value
            )

    selected = []

    for entry in payload.entries:
        name = entry.name.lstrip("/")

        if name not in wanted:
            continue

        new_name = (
            RETAINED_SOURCE_ROOT
            + "/"
            + name
        )

        selected.append(
            replace(
                entry,
                name=new_name,
                ino=(
                    first_inode
                    + len(selected)
                ),
            )
        )

    realized_files = {
        entry.name[
            len(RETAINED_SOURCE_ROOT) + 1:
        ]
        for entry in selected
        if (
            entry.name[
                len(RETAINED_SOURCE_ROOT) + 1:
            ]
            in wanted_files
        )
    }

    if realized_files != wanted_files:
        missing = sorted(
            wanted_files
            - realized_files
        )

        raise CanonicalInitramfsError(
            "payload CPIO did not contain required "
            "retained sources: "
            + ", ".join(missing)
        )

    return tuple(selected)


def compose_canonical_initramfs(
    *,
    stage: Path,
    clang: Path,
    output: Path,
) -> CanonicalInitramfsBuild:
    canonical = _canonical_archive()
    canonical_init_entry = (
        _canonical_init(
            canonical
        )
    )

    canonical_init = (
        canonical_init_entry.data
    )

    first_stage_init = (
        _patched_first_stage(
            canonical_init
        )
    )

    retained = _retained_files(
        stage
    )

    runtime_bundle = _runtime_bundle(
        stage,
        retained,
    )

    previous_clang = os.environ.get(
        "TREEFORGE_BOOTSTRAP_CLANG"
    )

    os.environ[
        "TREEFORGE_BOOTSTRAP_CLANG"
    ] = str(clang)

    try:
        dispatcher_build = (
            TreeForgeDispatcherBuilder.build(
                canonical_init=canonical_init,
                runtime_bundle=runtime_bundle,
                output_root=(
                    WORK
                    / "canonical-initramfs"
                    / "dispatcher"
                ),
            )
        )
    finally:
        if previous_clang is None:
            os.environ.pop(
                "TREEFORGE_BOOTSTRAP_CLANG",
                None,
            )
        else:
            os.environ[
                "TREEFORGE_BOOTSTRAP_CLANG"
            ] = previous_clang

    dispatcher = (
        dispatcher_build.executable_path
        .read_bytes()
    )

    maximum_inode = max(
        entry.ino
        for entry in canonical.entries
    )

    dispatcher_entry = replace(
        canonical_init_entry,
        data=dispatcher,
    )

    # TreeForge Bootstrap currently stops at its standalone
    # maintenance runtime and does not package an Android second-stage
    # continuation. The patched Google first-stage copy remains
    # mandatory for the current FD99 interception contract.
    first_stage_entry = replace(
        canonical_init_entry,
        name=FIRST_STAGE_INIT_NAME,
        ino=maximum_inode + 1,
        data=first_stage_init,
    )

    # Retained TreeForge Bootstrap runtime files are now carried inside
    # the dispatcher ELF itself and survive first-stage teardown
    # through the already-proven FD99 transition descriptor.
    #
    # Do not duplicate those files as CPIO entries.
    payload_entries = ()

    additions = (
        first_stage_entry,
    )

    canonical_names = {
        entry.name
        for entry in canonical.entries
    }

    for addition in additions:
        if addition.name in canonical_names:
            raise CanonicalInitramfsError(
                "TreeForge Bootstrap CPIO addition collides "
                "with canonical Google entry: "
                f"{addition.name}"
            )

    modified = []

    for entry in canonical.entries:
        if entry is canonical_init_entry:
            modified.append(
                dispatcher_entry
            )

            modified.extend(
                additions
            )

            continue

        modified.append(
            entry
        )

    addition_names = [
        entry.name
        for entry in additions
    ]

    if len(addition_names) != len(
        set(addition_names)
    ):
        raise CanonicalInitramfsError(
            "TreeForge Bootstrap-generated CPIO additions "
            "contain duplicate entry names"
        )

    result = NewcArchive(
        entries=tuple(modified),
        trailing_data=canonical.trailing_data,
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    write_newc_archive(
        result,
        output,
    )

    validate_canonical_initramfs(
        output
    )

    return CanonicalInitramfsBuild(
        output=output,
        dispatcher=(
            dispatcher_build.executable_path
        ),
        dispatcher_sha256=(
            _sha256_bytes(
                dispatcher
            )
        ),
        retained_file_count=len(
            retained
        ),
        entry_count=len(
            result.entries
        ),
    )


def validate_canonical_initramfs(
    path: Path,
) -> None:
    canonical = _canonical_archive()
    candidate = read_newc_archive(
        path
    )

    canonical_init_entry = (
        _canonical_init(
            canonical
        )
    )

    candidate_init_matches = [
        entry
        for entry in candidate.entries
        if entry.name.lstrip("/") == "init"
    ]

    if len(candidate_init_matches) != 1:
        raise CanonicalInitramfsError(
            "candidate CPIO does not contain "
            "exactly one /init"
        )

    candidate_init = (
        candidate_init_matches[0]
    )

    if (
        not candidate_init.data.startswith(
            b"\x7fELF"
        )
        or len(candidate_init.data) < 20
        or int.from_bytes(
            candidate_init.data[18:20],
            "little",
        ) != 183
    ):
        raise CanonicalInitramfsError(
            "candidate /init is not AArch64 ELF"
        )

    for required in (
        b"TREEFORGE_MENU_PROFILE_V1",
        (
            b"/dev/treeforge-bootstrap-runtime/"
            b"treeforge-bootstrap-adb-service"
        ),
        b"/dev/treeforge_bootstrap_fb",
    ):
        if required not in candidate_init.data:
            raise CanonicalInitramfsError(
                "dispatcher policy marker missing: "
                + required.decode(
                    "ascii"
                )
            )

    first_stage = [
        entry
        for entry in candidate.entries
        if entry.name
        == FIRST_STAGE_INIT_NAME
    ]

    expected_first_stage = (
        _patched_first_stage(
            canonical_init_entry.data
        )
    )

    if (
        len(first_stage) != 1
        or first_stage[0].data
        != expected_first_stage
    ):
        raise CanonicalInitramfsError(
            "TreeForge Bootstrap first-stage init mismatch"
        )

    retained_prefix = (
        RETAINED_SOURCE_ROOT
        + "/"
    )

    candidate_canonical_entries = tuple(
        entry
        for entry in candidate.entries
        if not (
            entry.name.lstrip("/") == "init"
            or entry.name
            == ORIGINAL_INIT_NAME
            or entry.name
            == FIRST_STAGE_INIT_NAME
            or entry.name.startswith(
                retained_prefix
            )
        )
    )

    expected_canonical_entries = tuple(
        entry
        for entry in canonical.entries
        if entry is not canonical_init_entry
    )

    if (
        candidate_canonical_entries
        != expected_canonical_entries
    ):
        raise CanonicalInitramfsError(
            "canonical Google CPIO population, "
            "ordering, metadata, or duplicate-name "
            "multiplicity changed"
        )

    candidate_names = {
        entry.name
        for entry in candidate.entries
    }

    normalized_dispatcher = replace(
        candidate_init,
        data=(
            canonical_init_entry.data
        ),
    )

    if normalized_dispatcher != canonical_init_entry:
        raise CanonicalInitramfsError(
            "dispatcher replacement changed "
            "canonical /init metadata"
        )

    if (
        candidate.trailing_data
        != canonical.trailing_data
    ):
        raise CanonicalInitramfsError(
            "canonical archive trailing padding changed"
        )

    # Retained runtime files are not duplicated as CPIO entries.
    # The complete TreeForge Bootstrap runtime is carried by the FD99
    # dispatcher bundle.
    legacy_retained = sorted(
        name
        for name in candidate_names
        if name.startswith(
            RETAINED_SOURCE_ROOT + "/"
        )
    )

    if legacy_retained:
        raise CanonicalInitramfsError(
            "legacy retained-runtime CPIO entries remain: "
            + ", ".join(
                legacy_retained
            )
        )

    embedded = candidate_init.data

    if len(embedded) < 32:
        raise CanonicalInitramfsError(
            "dispatcher is too small for FD99 runtime bundle"
        )

    trailer = embedded[-16:]

    if trailer[:8] != b"TFRTEND1":
        raise CanonicalInitramfsError(
            "FD99 runtime bundle trailer magic missing"
        )

    bundle_size = int.from_bytes(
        trailer[8:16],
        "little",
    )

    bundle_start = (
        len(embedded)
        - 16
        - bundle_size
    )

    if (
        bundle_size < 16
        or bundle_start < 0
    ):
        raise CanonicalInitramfsError(
            "FD99 runtime bundle size is invalid"
        )

    if (
        embedded[
            bundle_start:
            bundle_start + 8
        ]
        != b"TFRTB001"
    ):
        raise CanonicalInitramfsError(
            "FD99 runtime bundle header magic missing"
        )

    file_count = int.from_bytes(
        embedded[
            bundle_start + 8:
            bundle_start + 12
        ],
        "little",
    )

    if (
        file_count == 0
        or file_count > 256
    ):
        raise CanonicalInitramfsError(
            "FD99 runtime bundle file count is invalid: "
            f"{file_count}"
        )

    cursor = bundle_start + 16
    bundle_end = len(embedded) - 16

    destinations = set()

    for index in range(file_count):
        if cursor + 16 > bundle_end:
            raise CanonicalInitramfsError(
                "FD99 runtime bundle entry header exceeds "
                f"bundle boundary at index {index}"
            )

        path_length = int.from_bytes(
            embedded[
                cursor:
                cursor + 4
            ],
            "little",
        )

        mode = int.from_bytes(
            embedded[
                cursor + 4:
                cursor + 8
            ],
            "little",
        )

        payload_length = int.from_bytes(
            embedded[
                cursor + 8:
                cursor + 16
            ],
            "little",
        )

        cursor += 16

        if (
            path_length == 0
            or path_length >= 512
        ):
            raise CanonicalInitramfsError(
                "FD99 runtime bundle path length is invalid "
                f"at index {index}: {path_length}"
            )

        if mode > 0o777:
            raise CanonicalInitramfsError(
                "FD99 runtime bundle mode is invalid "
                f"at index {index}: {mode:o}"
            )

        if cursor + path_length > bundle_end:
            raise CanonicalInitramfsError(
                "FD99 runtime bundle path exceeds boundary "
                f"at index {index}"
            )

        path_bytes = embedded[
            cursor:
            cursor + path_length
        ]

        cursor += path_length

        try:
            destination = path_bytes.decode(
                "ascii"
            )
        except UnicodeDecodeError as error:
            raise CanonicalInitramfsError(
                "FD99 runtime bundle path is not ASCII "
                f"at index {index}"
            ) from error

        if not destination.startswith(
            RUNTIME_DESTINATION_ROOT + "/"
        ):
            raise CanonicalInitramfsError(
                "FD99 runtime destination is outside "
                "TreeForge Bootstrap runtime root: "
                f"{destination}"
            )

        if destination in destinations:
            raise CanonicalInitramfsError(
                "FD99 runtime bundle contains duplicate "
                f"destination: {destination}"
            )

        destinations.add(
            destination
        )

        if cursor + payload_length > bundle_end:
            raise CanonicalInitramfsError(
                "FD99 runtime payload exceeds bundle boundary "
                f"at index {index}: {destination}"
            )

        payload = embedded[
            cursor:
            cursor + payload_length
        ]

        if mode == 0:
            if (
                payload_length < 2
                or not payload.endswith(b"\x00")
            ):
                raise CanonicalInitramfsError(
                    "FD99 runtime symlink payload is invalid "
                    f"at index {index}: {destination}"
                )

            if b"\x00" in payload[:-1]:
                raise CanonicalInitramfsError(
                    "FD99 runtime symlink target contains "
                    "embedded NUL "
                    f"at index {index}: {destination}"
                )

            try:
                symlink_target = payload[:-1].decode(
                    "utf-8"
                )
            except UnicodeDecodeError as error:
                raise CanonicalInitramfsError(
                    "FD99 runtime symlink target is not UTF-8 "
                    f"at index {index}: {destination}"
                ) from error

            if not symlink_target:
                raise CanonicalInitramfsError(
                    "FD99 runtime symlink target is empty "
                    f"at index {index}: {destination}"
                )

        cursor += payload_length

    if cursor != bundle_end:
        raise CanonicalInitramfsError(
            "FD99 runtime bundle contains unexpected "
            "trailing body data"
        )

    required_runtime_destinations = (
        (
            RUNTIME_DESTINATION_ROOT
            + "/treeforge-bootstrap-adb-service"
        ),
        (
            RUNTIME_DESTINATION_ROOT
            + "/etc/treeforge-bootstrap-release"
        ),
        (
            RUNTIME_DESTINATION_ROOT
            + "/system/bin/linker64"
        ),
        (
            RUNTIME_DESTINATION_ROOT
            + "/system/bin/"
            "treeforge-bootstrap-adbd"
        ),
    )

    for required in required_runtime_destinations:
        if required not in destinations:
            raise CanonicalInitramfsError(
                "FD99 runtime bundle destination missing: "
                f"{required}"
            )
