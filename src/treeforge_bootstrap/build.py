from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil

from .paths import (
    OUT,
    PROVIDERS,
    REPOSITORY_ROOT,
    WORK,
)

from .runtime import (
    build_runtime,
    verify_runtime,
)

from .provider import (
    package_provider,
    verify_provider,
)

from .image import (
    build_image,
    verify_image,
)

from .hardware import hardware_preflight
from .interactive import interactive


class TreeForgeBootstrapBuildError(
    RuntimeError
):
    pass


CANONICAL_PROVIDER = (
    PROVIDERS
    / "google"
    / "tangorpro"
    / "android-15"
    / "init_boot.ramdisk.cpio"
)

ADBD_PROVIDER_ROOT = (
    PROVIDERS
    / "external"
    / "treeforge-bootstrap-adbd"
    / "android-15.0.0_r36-arm64"
    / "rootfs"
)

EXPECTED_CANONICAL_SHA256 = (
    "d9a027e3c06dc096cfb92e15251329c9"
    "6f1d69e38954c2d0758da520b1f3078f"
)


def _sha256(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for block in iter(
            lambda: stream.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def _clang() -> Path:
    from .host_providers import ensure_clang

    return ensure_clang()

def doctor() -> None:
    if not CANONICAL_PROVIDER.is_file():
        raise TreeForgeBootstrapBuildError(
            "canonical Google provider missing: "
            f"{CANONICAL_PROVIDER}"
        )

    actual = _sha256(
        CANONICAL_PROVIDER
    )

    if actual != EXPECTED_CANONICAL_SHA256:
        raise TreeForgeBootstrapBuildError(
            "canonical provider identity changed: "
            f"{actual}"
        )

    if not ADBD_PROVIDER_ROOT.is_dir():
        raise TreeForgeBootstrapBuildError(
            "treeforge-bootstrap-adbd provider "
            "rootfs missing: "
            f"{ADBD_PROVIDER_ROOT}"
        )

    adbd = (
        ADBD_PROVIDER_ROOT
        / "system"
        / "bin"
        / "treeforge-bootstrap-adbd"
    )

    if not adbd.is_file():
        raise TreeForgeBootstrapBuildError(
            "treeforge-bootstrap-adbd binary "
            f"missing: {adbd}"
        )

    if (
        _sha256(adbd)
        != "46ab32860fc78a7556c47b71e8f4a2089f43492fd78bc30727f94a3b466e4109"
    ):
        raise TreeForgeBootstrapBuildError(
            "treeforge-bootstrap-adbd "
            "provider identity changed"
        )

    clang = _clang()

    from .host_providers import ensure_host_tool

    mkbootimg = ensure_host_tool("mkbootimg")
    unpack_bootimg = ensure_host_tool("unpack_bootimg")
    avbtool = ensure_host_tool("avbtool")

    lz4 = shutil.which(
        "lz4"
    )

    if lz4 is None:
        raise TreeForgeBootstrapBuildError(
            "lz4 is unavailable"
        )

    print("TreeForge Bootstrap Doctor")
    print("==========================")
    print()
    print(f"Repository:         {REPOSITORY_ROOT}")
    print(f"Canonical provider: {CANONICAL_PROVIDER}")
    print(f"Canonical SHA256:   {actual}")
    print(f"ADB provider:       {ADBD_PROVIDER_ROOT}")
    print(f"Clang:              {clang}")
    print(f"Mkbootimg:          {mkbootimg}")
    print(f"Unpack bootimg:     {unpack_bootimg}")
    print(f"AVBTool:            {avbtool}")
    print(f"LZ4:                {Path(lz4).resolve()}")
    print(f"Work:               {WORK}")
    print(f"Output:             {OUT}")
    print()
    print("SIGNED_IMAGE=NO")
    print("DEVICE_ACCESS_REQUIRED=NO")
    print("TREEFORGE_BOOTSTRAP_DOCTOR=PASS")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="treeforge-bootstrap"
    )

    parser.add_argument(
        "command",
        nargs="?",
        choices=(
            "doctor",
            "build",
            "verify",
            "package",
            "verify-provider",
            "image",
            "verify-image",
            "hardware-preflight",
        ),
    )

    args = parser.parse_args()

    if args.command is None:
        interactive()
        return

    if args.command == "doctor":
        doctor()
    elif args.command == "build":
        build_runtime()
    elif args.command == "verify":
        verify_runtime()
    elif args.command == "package":
        package_provider()
    elif args.command == "verify-provider":
        verify_provider()
    elif args.command == "image":
        build_image()
    elif args.command == "verify-image":
        verify_image()
    else:
        hardware_preflight()


if __name__ == "__main__":
    main()
