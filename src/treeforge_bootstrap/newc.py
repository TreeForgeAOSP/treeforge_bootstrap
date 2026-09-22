from __future__ import annotations

from dataclasses import dataclass

import os
import stat

from pathlib import Path


def _pad4(
    data: bytearray,
) -> None:
    while len(data) % 4:
        data.append(0)


def _field(
    value: int,
) -> bytes:
    return (
        f"{value & 0xFFFFFFFF:08x}"
        .encode("ascii")
    )


def _entry(
    archive: bytearray,
    *,
    ino: int,
    name: str,
    mode: int,
    nlink: int,
    data: bytes,
) -> None:
    encoded_name = (
        name.encode("utf-8")
        + b"\0"
    )

    header = b"".join(
        (
            b"070701",
            _field(ino),
            _field(mode),
            _field(0),
            _field(0),
            _field(nlink),
            _field(0),
            _field(len(data)),
            _field(0),
            _field(0),
            _field(0),
            _field(0),
            _field(
                len(encoded_name)
            ),
            _field(0),
        )
    )

    archive.extend(header)
    archive.extend(encoded_name)

    _pad4(archive)

    archive.extend(data)

    _pad4(archive)


def build_newc(
    root: Path,
    output: Path,
) -> int:
    archive = bytearray()

    ino = 1

    paths = [root]

    paths.extend(
        sorted(
            root.rglob("*"),
            key=lambda path: str(
                path.relative_to(root)
            ),
        )
    )

    for path in paths:
        if path == root:
            name = "."
        else:
            name = str(
                path.relative_to(root)
            )

        info = path.lstat()

        mode = stat.S_IMODE(
            info.st_mode
        )

        if path.is_symlink():
            payload = (
                os.readlink(path)
                .encode("utf-8")
            )

            full_mode = (
                stat.S_IFLNK
                | mode
            )

            nlink = 1

        elif path.is_dir():
            payload = b""

            full_mode = (
                stat.S_IFDIR
                | mode
            )

            nlink = 2

        elif path.is_file():
            payload = (
                path.read_bytes()
            )

            full_mode = (
                stat.S_IFREG
                | mode
            )

            nlink = 1

        else:
            continue

        _entry(
            archive,
            ino=ino,
            name=name,
            mode=full_mode,
            nlink=nlink,
            data=payload,
        )

        ino += 1

    _entry(
        archive,
        ino=ino,
        name="TRAILER!!!",
        mode=0,
        nlink=1,
        data=b"",
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_bytes(
        archive
    )

    return len(archive)

# TREEFORGE_BOOTSTRAP_PRESERVING_NEWC_V1
#
# The ordinary build_newc() helper above intentionally constructs a
# deterministic archive from a filesystem tree.  That is appropriate for the
# old isolated bring-up initramfs, but it is not appropriate for the
# canonical Android init_boot ramdisk because it would discard caller-owned
# uid/gid/mtime/inode/device/check fields and canonical entry ordering.
#
# These helpers parse and reserialize an existing newc archive while retaining
# every metadata field and payload byte represented by the archive.

@dataclass(frozen=True)
class NewcEntry:
    magic: bytes
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    mtime: int
    devmajor: int
    devminor: int
    rdevmajor: int
    rdevminor: int
    check: int
    name: str
    data: bytes

    @property
    def namesize(self) -> int:
        return (
            len(
                self.name.encode(
                    "utf-8",
                    errors="surrogateescape",
                )
            )
            + 1
        )

    @property
    def filesize(self) -> int:
        return len(self.data)

    @property
    def is_trailer(self) -> bool:
        return self.name == "TRAILER!!!"


def _newc_align4(
    offset: int,
) -> int:
    return (
        offset
        + 3
    ) & ~3


def _newc_hex(
    field: bytes,
    *,
    label: str,
) -> int:
    if len(field) != 8:
        raise ValueError(
            f"invalid newc {label} width: "
            f"{len(field)}"
        )

    try:
        return int(
            field.decode("ascii"),
            16,
        )
    except ValueError as error:
        raise ValueError(
            f"invalid hexadecimal newc {label}: "
            f"{field!r}"
        ) from error


def parse_newc(
    data: bytes,
) -> tuple[NewcEntry, ...]:
    entries: list[NewcEntry] = []
    offset = 0
    total = len(data)

    while offset < total:
        entry_start = offset

        if total - offset < 110:
            trailing = data[offset:]

            if trailing and any(trailing):
                raise ValueError(
                    "non-zero bytes follow final newc entry"
                )

            break

        header = data[
            offset:
            offset + 110
        ]

        magic = header[:6]

        if magic not in (
            b"070701",
            b"070702",
        ):
            raise ValueError(
                "invalid newc magic at offset "
                f"{entry_start}: {magic!r}"
            )

        fields = [
            header[
                6 + index * 8:
                14 + index * 8
            ]
            for index in range(13)
        ]

        (
            ino,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            filesize,
            devmajor,
            devminor,
            rdevmajor,
            rdevminor,
            namesize,
            check,
        ) = (
            _newc_hex(
                value,
                label=f"field-{index}",
            )
            for index, value
            in enumerate(fields)
        )

        if namesize < 1:
            raise ValueError(
                "newc entry has invalid zero namesize "
                f"at offset {entry_start}"
            )

        offset += 110

        name_end = offset + namesize

        if name_end > total:
            raise ValueError(
                "newc entry name exceeds archive"
            )

        raw_name = data[
            offset:
            name_end
        ]

        if raw_name[-1:] != b"\0":
            raise ValueError(
                "newc entry name is not NUL terminated"
            )

        name = raw_name[:-1].decode(
            "utf-8",
            errors="surrogateescape",
        )

        offset = _newc_align4(
            name_end
        )

        data_end = offset + filesize

        if data_end > total:
            raise ValueError(
                "newc entry payload exceeds archive "
                f"for {name!r}"
            )

        payload = data[
            offset:
            data_end
        ]

        offset = _newc_align4(
            data_end
        )

        entries.append(
            NewcEntry(
                magic=magic,
                ino=ino,
                mode=mode,
                uid=uid,
                gid=gid,
                nlink=nlink,
                mtime=mtime,
                devmajor=devmajor,
                devminor=devminor,
                rdevmajor=rdevmajor,
                rdevminor=rdevminor,
                check=check,
                name=name,
                data=payload,
            )
        )

        if name == "TRAILER!!!":
            trailing = data[offset:]

            if trailing and any(trailing):
                raise ValueError(
                    "non-zero bytes follow newc TRAILER!!!"
                )

            break

    if not entries:
        raise ValueError(
            "newc archive contains no entries"
        )

    trailer_count = sum(
        entry.is_trailer
        for entry in entries
    )

    if trailer_count != 1:
        raise ValueError(
            "newc archive requires exactly one "
            f"TRAILER!!! entry; found {trailer_count}"
        )

    if not entries[-1].is_trailer:
        raise ValueError(
            "newc TRAILER!!! is not the final entry"
        )

    return tuple(entries)



# TREEFORGE_BOOTSTRAP_NEWC_ARCHIVE_PADDING_V1
#
# Android init_boot CPIO archives may carry deterministic zero padding after
# the aligned TRAILER!!! entry.  The padding is outside the logical newc entry
# population, but preserving it is required for byte-identical conservation.

@dataclass(frozen=True)
class NewcArchive:
    entries: tuple[NewcEntry, ...]
    trailing_data: bytes = b""

    def validate(self) -> None:
        if not self.entries:
            raise ValueError(
                "newc archive contains no entries"
            )

        if not self.entries[-1].is_trailer:
            raise ValueError(
                "newc archive does not end with TRAILER!!!"
            )

        trailer_count = sum(
            entry.is_trailer
            for entry in self.entries
        )

        if trailer_count != 1:
            raise ValueError(
                "newc archive requires exactly one "
                f"TRAILER!!! entry; found {trailer_count}"
            )

        if self.trailing_data and any(
            self.trailing_data
        ):
            raise ValueError(
                "newc archive trailing data is not zero padding"
            )


def parse_newc_archive(
    data: bytes,
) -> NewcArchive:
    entries: list[NewcEntry] = []
    offset = 0
    total = len(data)

    while offset < total:
        entry_start = offset

        if total - offset < 110:
            raise ValueError(
                "newc archive ended before TRAILER!!!"
            )

        header = data[
            offset:
            offset + 110
        ]

        magic = header[:6]

        if magic not in (
            b"070701",
            b"070702",
        ):
            raise ValueError(
                "invalid newc magic at offset "
                f"{entry_start}: {magic!r}"
            )

        fields = [
            header[
                6 + index * 8:
                14 + index * 8
            ]
            for index in range(13)
        ]

        (
            ino,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            filesize,
            devmajor,
            devminor,
            rdevmajor,
            rdevminor,
            namesize,
            check,
        ) = (
            _newc_hex(
                value,
                label=f"field-{index}",
            )
            for index, value
            in enumerate(fields)
        )

        if namesize < 1:
            raise ValueError(
                "newc entry has invalid zero namesize "
                f"at offset {entry_start}"
            )

        offset += 110

        name_end = offset + namesize

        if name_end > total:
            raise ValueError(
                "newc entry name exceeds archive"
            )

        raw_name = data[
            offset:
            name_end
        ]

        if raw_name[-1:] != b"\0":
            raise ValueError(
                "newc entry name is not NUL terminated"
            )

        name = raw_name[:-1].decode(
            "utf-8",
            errors="surrogateescape",
        )

        offset = _newc_align4(
            name_end
        )

        data_end = offset + filesize

        if data_end > total:
            raise ValueError(
                "newc entry payload exceeds archive "
                f"for {name!r}"
            )

        payload = data[
            offset:
            data_end
        ]

        offset = _newc_align4(
            data_end
        )

        entries.append(
            NewcEntry(
                magic=magic,
                ino=ino,
                mode=mode,
                uid=uid,
                gid=gid,
                nlink=nlink,
                mtime=mtime,
                devmajor=devmajor,
                devminor=devminor,
                rdevmajor=rdevmajor,
                rdevminor=rdevminor,
                check=check,
                name=name,
                data=payload,
            )
        )

        if name == "TRAILER!!!":
            trailing = data[offset:]

            archive = NewcArchive(
                entries=tuple(entries),
                trailing_data=trailing,
            )

            archive.validate()

            return archive

    raise ValueError(
        "newc archive has no TRAILER!!! entry"
    )


def read_newc_archive(
    path: Path,
) -> NewcArchive:
    return parse_newc_archive(
        path.read_bytes()
    )


def serialize_newc_archive(
    archive: NewcArchive,
) -> bytes:
    archive.validate()

    return (
        serialize_newc(
            archive.entries
        )
        + archive.trailing_data
    )


def write_newc_archive(
    archive: NewcArchive,
    output: Path,
) -> int:
    data = serialize_newc_archive(
        archive
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_bytes(
        data
    )

    return len(data)

def read_newc(
    path: Path,
) -> tuple[NewcEntry, ...]:
    return parse_newc(
        path.read_bytes()
    )


def _newc_emit_preserved(
    archive: bytearray,
    entry: NewcEntry,
) -> None:
    if entry.magic not in (
        b"070701",
        b"070702",
    ):
        raise ValueError(
            f"unsupported newc magic: {entry.magic!r}"
        )

    encoded_name = (
        entry.name.encode(
            "utf-8",
            errors="surrogateescape",
        )
        + b"\0"
    )

    values = (
        entry.ino,
        entry.mode,
        entry.uid,
        entry.gid,
        entry.nlink,
        entry.mtime,
        len(entry.data),
        entry.devmajor,
        entry.devminor,
        entry.rdevmajor,
        entry.rdevminor,
        len(encoded_name),
        entry.check,
    )

    archive.extend(
        entry.magic
    )

    for value in values:
        archive.extend(
            _field(value)
        )

    archive.extend(
        encoded_name
    )

    _pad4(
        archive
    )

    archive.extend(
        entry.data
    )

    _pad4(
        archive
    )


def serialize_newc(
    entries: tuple[NewcEntry, ...]
    | list[NewcEntry],
) -> bytes:
    population = tuple(entries)

    if not population:
        raise ValueError(
            "cannot serialize empty newc population"
        )

    trailer_indexes = tuple(
        index
        for index, entry
        in enumerate(population)
        if entry.is_trailer
    )

    if trailer_indexes != (
        len(population) - 1,
    ):
        raise ValueError(
            "newc population requires one final "
            "TRAILER!!! entry"
        )

    archive = bytearray()

    for entry in population:
        _newc_emit_preserved(
            archive,
            entry,
        )

    return bytes(archive)


def write_newc(
    entries: tuple[NewcEntry, ...]
    | list[NewcEntry],
    output: Path,
) -> int:
    data = serialize_newc(
        entries
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_bytes(
        data
    )

    return len(data)


def insert_before_newc_trailer(
    entries: tuple[NewcEntry, ...],
    additions: tuple[NewcEntry, ...],
) -> tuple[NewcEntry, ...]:
    if (
        not entries
        or not entries[-1].is_trailer
    ):
        raise ValueError(
            "canonical newc population has no final trailer"
        )

    if any(
        entry.is_trailer
        for entry in additions
    ):
        raise ValueError(
            "generated newc additions may not contain trailer"
        )

    return (
        entries[:-1]
        + additions
        + (entries[-1],)
    )
