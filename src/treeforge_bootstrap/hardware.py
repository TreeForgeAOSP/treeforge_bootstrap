from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess

from .host_providers import ensure_host_tool
from .image import (
    OUTPUT_IMAGE,
    verify_image,
)


class TreeForgeBootstrapHardwareError(
    RuntimeError
):
    pass


EXPECTED_FASTBOOT_SHA256 = (
    "340c23293ee6f3fb60d689e8c2042d23"
    "ef969d511981c2df3c423973d6ff4898"
)

EXPECTED_PRODUCT = "tangorpro"

EXPECTED_SLOT_COUNT = "2"


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
        raise TreeForgeBootstrapHardwareError(
            "fastboot command failed:\n"
            + " ".join(command)
            + "\n\n"
            + result.stdout
        )

    return result.stdout


def _devices(
    fastboot: Path,
) -> list[str]:
    output = _run(
        [
            str(fastboot),
            "devices",
        ]
    )

    devices: list[str] = []

    for raw in output.splitlines():
        line = raw.strip()

        if not line:
            continue

        fields = line.split()

        if not fields:
            continue

        serial = fields[0].strip()

        if serial:
            devices.append(
                serial
            )

    return devices


def _getvar(
    fastboot: Path,
    serial: str,
    name: str,
) -> str:
    output = _run(
        [
            str(fastboot),
            "-s",
            serial,
            "getvar",
            name,
        ]
    )

    prefix = name + ":"

    for raw in output.splitlines():
        line = raw.strip()

        if line.startswith(
            "(bootloader) "
        ):
            line = line[
                len("(bootloader) "):
            ].strip()

        if line.startswith(prefix):
            return line[
                len(prefix):
            ].strip()

    raise TreeForgeBootstrapHardwareError(
        "fastboot did not report "
        f"{name!r}:\n{output}"
    )


def hardware_preflight() -> None:
    # This operation is intentionally read-only.
    #
    # No flash, erase, reboot, set_active, snapshot,
    # OEM/flashing command, or userspace-fastboot
    # transition is permitted here.
    verify_image()

    if not OUTPUT_IMAGE.is_file():
        raise TreeForgeBootstrapHardwareError(
            "accepted init_boot image missing"
        )

    fastboot = ensure_host_tool(
        "fastboot"
    )

    actual_fastboot_sha = _sha256(
        fastboot
    )

    if (
        actual_fastboot_sha
        != EXPECTED_FASTBOOT_SHA256
    ):
        raise TreeForgeBootstrapHardwareError(
            "TreeForge fastboot identity "
            "changed: "
            f"{actual_fastboot_sha}"
        )

    version = _run(
        [
            str(fastboot),
            "--version",
        ]
    ).strip()

    devices = _devices(
        fastboot
    )

    if len(devices) == 0:
        raise TreeForgeBootstrapHardwareError(
            "no bootloader-fastboot device "
            "detected"
        )

    if len(devices) != 1:
        raise TreeForgeBootstrapHardwareError(
            "hardware preflight requires "
            "exactly one fastboot device; "
            f"found {len(devices)}"
        )

    serial = devices[0]

    product = _getvar(
        fastboot,
        serial,
        "product",
    )

    current_slot = _getvar(
        fastboot,
        serial,
        "current-slot",
    ).lower()

    slot_count = _getvar(
        fastboot,
        serial,
        "slot-count",
    )

    unlocked = _getvar(
        fastboot,
        serial,
        "unlocked",
    ).lower()

    is_userspace = _getvar(
        fastboot,
        serial,
        "is-userspace",
    ).lower()

    has_init_boot = _getvar(
        fastboot,
        serial,
        "has-slot:init_boot",
    ).lower()

    if product != EXPECTED_PRODUCT:
        raise TreeForgeBootstrapHardwareError(
            "unsupported product: "
            f"{product}"
        )

    if current_slot not in (
        "a",
        "b",
    ):
        raise TreeForgeBootstrapHardwareError(
            "invalid current slot: "
            f"{current_slot}"
        )

    if slot_count != EXPECTED_SLOT_COUNT:
        raise TreeForgeBootstrapHardwareError(
            "unexpected slot count: "
            f"{slot_count}"
        )

    if unlocked not in (
        "yes",
        "true",
        "1",
    ):
        raise TreeForgeBootstrapHardwareError(
            "bootloader is not unlocked: "
            f"{unlocked}"
        )

    if is_userspace not in (
        "no",
        "false",
        "0",
    ):
        raise TreeForgeBootstrapHardwareError(
            "device is in userspace fastboot; "
            "bootloader fastboot is required"
        )

    if has_init_boot not in (
        "yes",
        "true",
        "1",
    ):
        raise TreeForgeBootstrapHardwareError(
            "init_boot is not slotted"
        )

    first_test_ready = (
        current_slot == "a"
    )

    print(
        "TreeForge Bootstrap Hardware Preflight"
    )
    print(
        "======================================"
    )
    print()

    print(
        f"Fastboot:       {fastboot}"
    )
    print(
        "Fastboot SHA:   "
        + actual_fastboot_sha
    )
    print(
        "Fastboot ver:   "
        + version.replace(
            "\n",
            " | ",
        )
    )

    print()
    print(
        f"Device serial:  {serial}"
    )
    print(
        f"Product:        {product}"
    )
    print(
        f"Current slot:   {current_slot}"
    )
    print(
        f"Slot count:     {slot_count}"
    )
    print(
        f"Unlocked:       {unlocked}"
    )
    print(
        f"Userspace FB:   {is_userspace}"
    )
    print(
        f"init_boot A/B:  {has_init_boot}"
    )

    print()
    print(
        f"Image:          {OUTPUT_IMAGE}"
    )
    print(
        f"Image bytes:    "
        f"{OUTPUT_IMAGE.stat().st_size}"
    )
    print(
        f"Image SHA:      "
        f"{_sha256(OUTPUT_IMAGE)}"
    )

    print()
    print(
        "FIRST_TEST_SLOT=A"
    )
    print(
        "FIRST_TEST_SLOT_READY="
        + (
            "YES"
            if first_test_ready
            else "NO"
        )
    )

    print(
        "DEVICE_WRITE_PERFORMED=NO"
    )
    print(
        "DEVICE_REBOOT_PERFORMED=NO"
    )
    print(
        "DEVICE_SLOT_CHANGE_PERFORMED=NO"
    )
    print(
        "TREEFORGE_BOOTSTRAP_"
        "HARDWARE_PREFLIGHT=PASS"
    )
