from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from .canonical_initramfs import (
    compose_canonical_initramfs,
    validate_canonical_initramfs,
)
from .newc import read_newc_archive
from .paths import (
    INITRAMFS_ROOT,
    OUT,
    PROVIDERS,
    WORK,
)


class TreeForgeBootstrapRuntimeError(
    RuntimeError
):
    pass


ADBD_PROVIDER_ROOT = (
    PROVIDERS
    / "external"
    / "pixel-partitioner-adbd"
    / "android-15.0.0_r36-arm64"
    / "rootfs"
)

EXPECTED_ADBD_SHA256 = (
    "938587531b1a4f6ee74d591ffd5be8445"
    "9d43402e0ed54cadfa17283b680bef8"
)

EXPECTED_ADB_SERVICE_SHA256 = (
    "03ab7f2dbbb252d409076d65890381045"
    "78f6f3ea28aa61a838b557c84edd988"
)

RUNTIME_OUT = (
    OUT
    / "runtime"
)

RAW_INITRAMFS = (
    RUNTIME_OUT
    / "initramfs.cpio"
)

COMPRESSED_INITRAMFS = (
    RUNTIME_OUT
    / "initramfs.lz4"
)

MENU_BINARY = (
    RUNTIME_OUT
    / "treeforge-menu"
)

RUNTIME_METADATA = (
    RUNTIME_OUT
    / "runtime.json"
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


def _clang() -> Path:
    override = os.environ.get(
        "TREEFORGE_BOOTSTRAP_CLANG"
    )

    if not override:
        raise TreeForgeBootstrapRuntimeError(
            "TREEFORGE_BOOTSTRAP_CLANG "
            "must select the pinned clang provider"
        )

    path = Path(
        override
    ).expanduser().resolve()

    if not path.is_file():
        raise TreeForgeBootstrapRuntimeError(
            "TREEFORGE_BOOTSTRAP_CLANG "
            f"is missing: {path}"
        )

    return path


def _lz4() -> Path:
    discovered = shutil.which(
        "lz4"
    )

    if discovered is None:
        raise TreeForgeBootstrapRuntimeError(
            "lz4 is unavailable"
        )

    return Path(
        discovered
    ).resolve()


def _elf_machine(
    path: Path,
) -> int | None:
    with path.open("rb") as stream:
        header = stream.read(20)

    if (
        len(header) < 20
        or header[:4] != b"\x7fELF"
    ):
        return None

    byteorder = (
        "little"
        if header[5] == 1
        else "big"
    )

    return int.from_bytes(
        header[18:20],
        byteorder,
    )


def _compile_adb_service(
    clang: Path,
    stage: Path,
) -> Path:
    source = (
        INITRAMFS_ROOT.parent
        / "src"
        / "adb_service.c"
    )

    output = (
        stage
        / "pixel-partitioner-adb-service"
    )

    if not source.is_file():
        raise TreeForgeBootstrapRuntimeError(
            "ADB service source missing: "
            f"{source}"
        )

    command = [
        str(clang),
        "--target=aarch64-linux-gnu",
        "-fuse-ld=lld",
        "-Os",
        "-ffreestanding",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fno-pic",
        "-fno-pie",
        "-nostdlib",
        "-static",
        "-Wl,-e,_start",
        "-Wl,--build-id=none",
        "-Wl,-z,max-page-size=4096",
        str(source),
        "-o",
        str(output),
    ]

    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    if completed.returncode != 0:
        raise TreeForgeBootstrapRuntimeError(
            "ADB service compile failed:\n"
            + completed.stdout
        )

    output.chmod(
        0o755
    )

    if _elf_machine(output) != 183:
        raise TreeForgeBootstrapRuntimeError(
            "compiled ADB service is not "
            "AArch64 ELF"
        )

    actual = _sha256(
        output
    )

    if (
        actual
        != EXPECTED_ADB_SERVICE_SHA256
    ):
        raise TreeForgeBootstrapRuntimeError(
            "compiled ADB service identity "
            "changed: "
            f"{actual}"
        )

    return output


def _copy_external_provider(
    stage: Path,
) -> None:
    if not ADBD_PROVIDER_ROOT.is_dir():
        raise TreeForgeBootstrapRuntimeError(
            "pixel-partitioner-adbd provider "
            "rootfs missing: "
            f"{ADBD_PROVIDER_ROOT}"
        )

    adbd = (
        ADBD_PROVIDER_ROOT
        / "system"
        / "bin"
        / "pixel-partitioner-adbd"
    )

    if (
        not adbd.is_file()
        or _sha256(adbd)
        != EXPECTED_ADBD_SHA256
    ):
        raise TreeForgeBootstrapRuntimeError(
            "pixel-partitioner-adbd provider "
            "identity changed"
        )

    shutil.copytree(
        ADBD_PROVIDER_ROOT,
        stage,
        dirs_exist_ok=True,
        symlinks=True,
    )


def _install_root_busybox(
    stage: Path,
) -> None:
    source = (
        stage
        / "system"
        / "bin"
        / "busybox"
    )

    if not source.is_file():
        raise TreeForgeBootstrapRuntimeError(
            "provider BusyBox is missing: "
            f"{source}"
        )

    root_bin = (
        stage
        / "bin"
    )

    root_bin.mkdir(
        parents=True,
        exist_ok=True,
    )

    target = (
        root_bin
        / "busybox"
    )

    shutil.copy2(
        source,
        target,
    )

    target.chmod(
        0o755
    )

    for name in (
        "cat",
        "dmesg",
        "ls",
        "mount",
        "sh",
        "sleep",
    ):
        link = (
            root_bin
            / name
        )

        if (
            link.exists()
            or link.is_symlink()
        ):
            link.unlink()

        link.symlink_to(
            "busybox"
        )


def _stage_runtime() -> Path:
    clang = _clang()

    stage = (
        WORK
        / "runtime"
        / "root"
    )

    if stage.exists():
        shutil.rmtree(
            stage
        )

    stage.mkdir(
        parents=True,
        exist_ok=True,
    )

    _copy_external_provider(
        stage
    )

    _install_root_busybox(
        stage
    )

    if INITRAMFS_ROOT.is_dir():
        shutil.copytree(
            INITRAMFS_ROOT,
            stage,
            dirs_exist_ok=True,
            symlinks=True,
        )

    _compile_adb_service(
        clang,
        stage,
    )

    return stage


def _compress(
    raw: Path,
    compressed: Path,
) -> None:
    lz4 = _lz4()

    if compressed.exists():
        compressed.unlink()

    completed = subprocess.run(
        [
            str(lz4),
            "-l",
            "-12",
            "-f",
            str(raw),
            str(compressed),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    if completed.returncode != 0:
        raise TreeForgeBootstrapRuntimeError(
            "legacy LZ4 compression failed:\n"
            + completed.stdout
        )

    if not compressed.is_file():
        raise TreeForgeBootstrapRuntimeError(
            "LZ4 produced no initramfs"
        )

    magic = compressed.read_bytes()[:4]

    if magic != b"\x02\x21\x4c\x18":
        raise TreeForgeBootstrapRuntimeError(
            "initramfs does not use "
            "legacy Android LZ4 framing: "
            f"{magic.hex()}"
        )

    verification = (
        compressed.parent
        / ".roundtrip.cpio"
    )

    if verification.exists():
        verification.unlink()

    decoded = subprocess.run(
        [
            str(lz4),
            "-d",
            "-f",
            str(compressed),
            str(verification),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    if decoded.returncode != 0:
        raise TreeForgeBootstrapRuntimeError(
            "LZ4 round-trip failed:\n"
            + decoded.stdout
        )

    if _sha256(verification) != _sha256(raw):
        raise TreeForgeBootstrapRuntimeError(
            "LZ4 round-trip changed "
            "the raw initramfs"
        )

    verification.unlink()


def _validate_menu(
    raw: Path,
) -> tuple[str, int]:
    validate_canonical_initramfs(
        raw
    )

    archive = read_newc_archive(
        raw
    )

    init_entries = [
        entry
        for entry in archive.entries
        if entry.name.lstrip("/")
        == "init"
    ]

    if len(init_entries) != 1:
        raise TreeForgeBootstrapRuntimeError(
            "runtime must contain exactly "
            "one /init"
        )

    init = init_entries[0].data

    if (
        len(init) < 20
        or init[:4] != b"\x7fELF"
        or int.from_bytes(
            init[18:20],
            "little",
        ) != 183
    ):
        raise TreeForgeBootstrapRuntimeError(
            "runtime /init is not "
            "AArch64 ELF"
        )

    required = (
        b"TREEFORGE MENU",
        b"REBOOT BOOTLOADER",
        b"/dev/pixel_partitioner_fb",
        b"pixel-partitioner-adb-service",
    )

    for marker in required:
        if marker not in init:
            raise TreeForgeBootstrapRuntimeError(
                "runtime marker missing: "
                + marker.decode(
                    "ascii"
                )
            )

    return (
        hashlib.sha256(
            init
        ).hexdigest(),
        len(init),
    )


def build_runtime() -> Path:
    clang = _clang()

    stage = _stage_runtime()

    if RUNTIME_OUT.exists():
        shutil.rmtree(
            RUNTIME_OUT
        )

    RUNTIME_OUT.mkdir(
        parents=True,
        exist_ok=True,
    )

    os.environ[
        "TREEFORGE_BOOTSTRAP_CLANG"
    ] = str(clang)

    result = compose_canonical_initramfs(
        stage=stage,
        clang=clang,
        output=RAW_INITRAMFS,
    )

    validate_canonical_initramfs(
        RAW_INITRAMFS
    )

    _compress(
        RAW_INITRAMFS,
        COMPRESSED_INITRAMFS,
    )

    shutil.copy2(
        result.dispatcher,
        MENU_BINARY,
    )

    MENU_BINARY.chmod(
        0o755
    )

    init_sha256, init_bytes = (
        _validate_menu(
            RAW_INITRAMFS
        )
    )

    metadata = {
        "schema": 1,
        "project":
            "TreeForge Bootstrap",
        "role":
            "persistent-installed-bootstrap",
        "device":
            "tangorpro",
        "platform":
            "android-15",
        "menu_identity":
            "TreeForge Menu",
        "signed_image":
            False,
        "signing_owner":
            "pixel_partitioner",
        "runtime": {
            "initramfs_cpio_bytes":
                RAW_INITRAMFS.stat().st_size,
            "initramfs_cpio_sha256":
                _sha256(
                    RAW_INITRAMFS
                ),
            "initramfs_lz4_bytes":
                COMPRESSED_INITRAMFS.stat().st_size,
            "initramfs_lz4_sha256":
                _sha256(
                    COMPRESSED_INITRAMFS
                ),
            "treeforge_menu_bytes":
                MENU_BINARY.stat().st_size,
            "treeforge_menu_sha256":
                _sha256(
                    MENU_BINARY
                ),
            "init_elf_bytes":
                init_bytes,
            "init_elf_sha256":
                init_sha256,
            "retained_file_count":
                result.retained_file_count,
            "cpio_entry_count":
                result.entry_count,
        },
        "build": {
            "clang":
                str(clang),
        },
    }

    RUNTIME_METADATA.write_text(
        json.dumps(
            metadata,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print("TreeForge Bootstrap Runtime")
    print("===========================")
    print()
    print(f"CPIO:       {RAW_INITRAMFS}")
    print(
        f"CPIO SHA:   "
        f"{_sha256(RAW_INITRAMFS)}"
    )
    print(f"LZ4:        {COMPRESSED_INITRAMFS}")
    print(
        f"LZ4 SHA:    "
        f"{_sha256(COMPRESSED_INITRAMFS)}"
    )
    print(f"Menu:       {MENU_BINARY}")
    print(
        f"Menu SHA:   "
        f"{_sha256(MENU_BINARY)}"
    )
    print(f"Metadata:   {RUNTIME_METADATA}")
    print()
    print("VISIBLE_MENU_IDENTITY=TreeForge Menu")
    print("SIGNED_IMAGE=NO")
    print("SIGNING_OWNER=Pixel Partitioner")
    print("TREEFORGE_BOOTSTRAP_RUNTIME_BUILD=PASS")

    return RAW_INITRAMFS


def verify_runtime() -> Path:
    for path in (
        RAW_INITRAMFS,
        COMPRESSED_INITRAMFS,
        MENU_BINARY,
        RUNTIME_METADATA,
    ):
        if not path.is_file():
            raise TreeForgeBootstrapRuntimeError(
                f"runtime output missing: {path}"
            )

    metadata = json.loads(
        RUNTIME_METADATA.read_text(
            encoding="utf-8"
        )
    )

    runtime = metadata[
        "runtime"
    ]

    actual = {
        "initramfs_cpio_sha256":
            _sha256(
                RAW_INITRAMFS
            ),
        "initramfs_lz4_sha256":
            _sha256(
                COMPRESSED_INITRAMFS
            ),
        "treeforge_menu_sha256":
            _sha256(
                MENU_BINARY
            ),
    }

    for key, value in actual.items():
        if runtime.get(key) != value:
            raise TreeForgeBootstrapRuntimeError(
                "runtime metadata mismatch: "
                f"{key}"
            )

    if metadata.get(
        "signed_image"
    ) is not False:
        raise TreeForgeBootstrapRuntimeError(
            "runtime unexpectedly owns signing"
        )

    if metadata.get(
        "signing_owner"
    ) != "pixel_partitioner":
        raise TreeForgeBootstrapRuntimeError(
            "signing ownership changed"
        )

    _validate_menu(
        RAW_INITRAMFS
    )

    if (
        COMPRESSED_INITRAMFS
        .read_bytes()[:4]
        != b"\x02\x21\x4c\x18"
    ):
        raise TreeForgeBootstrapRuntimeError(
            "legacy LZ4 framing changed"
        )

    print("VISIBLE_MENU_IDENTITY=TreeForge Menu")
    print("LOW_LEVEL_PIXEL_PARTITIONER_ABI=PRESERVED")
    print("SIGNED_IMAGE=NO")
    print("SIGNING_OWNER=Pixel Partitioner")
    print("TREEFORGE_BOOTSTRAP_RUNTIME_VERIFY=PASS")

    return RAW_INITRAMFS
