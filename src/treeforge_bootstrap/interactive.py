from __future__ import annotations

import subprocess
import time

from .hardware import (
    TreeForgeBootstrapHardwareError,
    _devices,
    _getvar,
    _run,
    hardware_preflight,
)
from .host_providers import ensure_host_tool
from .image import (
    OUTPUT_BOOT_IMAGE,
    OUTPUT_IMAGE,
    build_image,
    verify_image,
)
from .paths import REPOSITORY_ROOT


IDENTITY_FILE = (
    REPOSITORY_ROOT
    / "runtime/initramfs/root/etc/"
      "treeforge-bootstrap-release"
)

DEVICE_IDENTITY_PATH = (
    "/dev/treeforge-bootstrap-runtime/etc/"
    "treeforge-bootstrap-release"
)


def _adb(
    adb,
    serial: str,
    *args: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(adb),
            "-s",
            serial,
            *args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


def interactive() -> None:
    print("TreeForge Bootstrap")
    print("===================")
    print()

    print("[1/4] Build and verify image family")
    build_image()
    verify_image()

    print()
    print("[2/4] Hardware preflight")
    hardware_preflight()

    fastboot = ensure_host_tool("fastboot")
    devices = _devices(fastboot)

    if len(devices) != 1:
        raise TreeForgeBootstrapHardwareError(
            "exactly one fastboot device is required"
        )

    serial = devices[0]

    if _getvar(
        fastboot,
        serial,
        "current-slot",
    ).lower() != "a":
        raise TreeForgeBootstrapHardwareError(
            "first Bootstrap installation requires slot A"
        )

    print()
    print("[3/4] Install TreeForge Boot Manager")
    print()
    print("Will write:")
    print(f"  boot_a      <- {OUTPUT_BOOT_IMAGE}")
    print(f"  init_boot_a <- {OUTPUT_IMAGE}")
    print()
    print("Will NOT write vbmeta or slot B.")
    print()

    answer = input(
        "Install to Slot A and reboot? [y/N]: "
    ).strip().lower()

    if answer not in ("y", "yes"):
        print("Installation cancelled.")
        return

    print()
    print("Flashing boot_a...")
    print(
        _run(
            [
                str(fastboot),
                "-s",
                serial,
                "flash",
                "boot_a",
                str(OUTPUT_BOOT_IMAGE),
            ]
        ).rstrip()
    )

    print()
    print("Flashing init_boot_a...")
    print(
        _run(
            [
                str(fastboot),
                "-s",
                serial,
                "flash",
                "init_boot_a",
                str(OUTPUT_IMAGE),
            ]
        ).rstrip()
    )

    print()
    print("Rebooting...")
    _run(
        [
            str(fastboot),
            "-s",
            serial,
            "reboot",
        ]
    )

    print()
    print("[4/4] Waiting for TreeForge Bootstrap ADB")

    adb = ensure_host_tool("adb")

    expected_identity = (
        IDENTITY_FILE
        .read_text(encoding="utf-8")
        .strip()
    )

    deadline = (
        time.monotonic()
        + 120.0
    )

    while time.monotonic() < deadline:
        devices_result = subprocess.run(
            [
                str(adb),
                "devices",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

        if devices_result.returncode == 0:
            adb_serials = []

            for line in devices_result.stdout.splitlines():
                fields = line.split()

                if (
                    len(fields) >= 2
                    and fields[1] == "device"
                ):
                    adb_serials.append(
                        fields[0]
                    )

            for adb_serial in adb_serials:
                identity = _adb(
                    adb,
                    adb_serial,
                    "shell",
                    "cat",
                    DEVICE_IDENTITY_PATH,
                )

                if identity.returncode != 0:
                    continue

                actual_identity = (
                    identity.stdout.strip()
                )

                if actual_identity != expected_identity:
                    continue

                print()
                print(
                    "ADB device detected: "
                    + adb_serial
                )
                print(
                    "Runtime identity: "
                    + actual_identity
                )
                print()
                print(
                    "TREEFORGE_BOOTSTRAP_"
                    "HARDWARE_BOOT=PASS"
                )
                return

        time.sleep(1.0)

    raise TreeForgeBootstrapHardwareError(
        "TreeForge Bootstrap ADB identity "
        "was not observed"
    )
