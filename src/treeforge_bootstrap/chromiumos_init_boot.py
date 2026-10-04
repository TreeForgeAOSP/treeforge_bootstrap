from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

from .host_providers import ensure_host_tool
from .image import (
    SOURCE_INIT_BOOT,
    SOURCE_VBMETA,
    SIGNING_KEY,
    EXPECTED_SOURCE_SHA256,
    EXPECTED_SOURCE_VBMETA_SHA256,
    EXPECTED_KEY_SHA256,
)
from .paths import BUILD_PROFILE, OUT, WORK
from .runtime import (
    COMPRESSED_INITRAMFS,
    RAW_INITRAMFS,
    MENU_BINARY,
    RUNTIME_METADATA,
    verify_runtime,
)


class ChromiumOSImageError(RuntimeError):
    pass


PROFILE = "treeforge-chromiumos"
IMAGE_OUT = OUT / "image"
IMAGE_WORK = WORK / "image"
OUTPUT_IMAGE = IMAGE_OUT / "init_boot.img"
OUTPUT_METADATA = IMAGE_OUT / "image.json"
PARTITION_SIZE = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ChromiumOSImageError(message)


def sha(path):
    require(path.is_file(), f"Missing input: {path}")
    h = hashlib.sha256()

    with path.open("rb") as stream:
        for block in iter(
            lambda: stream.read(1024 * 1024),
            b"",
        ):
            h.update(block)

    return h.hexdigest()


def command(*args):
    result = subprocess.run(
        [str(x) for x in args],
        capture_output=True,
    )

    if result.returncode:
        raise ChromiumOSImageError(
            "Command failed: "
            + " ".join(str(x) for x in args[:3])
            + "\n"
            + result.stdout.decode(errors="replace")
            + "\n"
            + result.stderr.decode(errors="replace")
        )

    return result.stdout


def require_profile():
    require(
        BUILD_PROFILE == PROFILE,
        "ChromiumOS init_boot builder selected outside its profile",
    )


def tools():
    return {
        name: ensure_host_tool(name)
        for name in ("unpack_bootimg", "mkbootimg", "avbtool")
    }


def runtime_contract():
    require_profile()
    verify_runtime()

    metadata = json.loads(RUNTIME_METADATA.read_text())

    require(
        metadata.get("profile_id") == PROFILE,
        "Runtime was not built by the ChromiumOS profile",
    )

    actual = {
        "treeforge-menu": sha(MENU_BINARY),
        "initramfs.cpio": sha(RAW_INITRAMFS),
        "initramfs.lz4": sha(COMPRESSED_INITRAMFS),
    }

    require(
        COMPRESSED_INITRAMFS.read_bytes()[:4]
        == b"\x02\x21\x4c\x18",
        "ChromiumOS ramdisk is not legacy LZ4",
    )

    return actual


def avb_value(info, label, required=True):
    match = re.search(
        r"(?m)^\s*" + re.escape(label) + r":\s*(.*?)\s*$",
        info,
    )

    if required:
        require(match is not None, f"Missing AVB field: {label}")

    return match.group(1) if match else None


def avb_properties(info):
    result = {}

    for line in info.splitlines():
        match = re.match(
            r"^\s*Prop:\s+(\S+)\s+->\s+(.+?)\s*$",
            line,
        )

        if not match:
            continue

        key, value = match.groups()

        if value.startswith(("'", '"')):
            try:
                value = ast.literal_eval(value)
            except (SyntaxError, ValueError):
                raise ChromiumOSImageError(
                    "Cannot safely decode AVB property: " + key
                )

        require(
            isinstance(value, str),
            "Invalid AVB property value: " + key,
        )

        require(key not in result, "Duplicate AVB property")

        result[key] = value

    return result


def source_contract(avbtool):
    require(
        sha(SOURCE_INIT_BOOT) == EXPECTED_SOURCE_SHA256,
        "Canonical AOSP init_boot identity changed",
    )

    require(
        sha(SOURCE_VBMETA) == EXPECTED_SOURCE_VBMETA_SHA256,
        "Canonical AOSP root vbmeta identity changed",
    )

    require(
        sha(SIGNING_KEY) == EXPECTED_KEY_SHA256,
        "Existing Bootstrap AOSP signing-key identity changed",
    )

    command(
        avbtool, "verify_image",
        "--image", SOURCE_INIT_BOOT,
        "--key", SIGNING_KEY,
    )

    source_info = command(
        avbtool, "info_image",
        "--image", SOURCE_INIT_BOOT,
    ).decode(errors="replace")

    root_info = command(
        avbtool, "info_image",
        "--image", SOURCE_VBMETA,
    ).decode(errors="replace")

    require(
        "init_boot" in root_info,
        "Canonical root vbmeta has no init_boot chain reference",
    )

    require(
        source_info.count("Hash descriptor:") == 1,
        "Expected exactly one source init_boot hash descriptor",
    )

    algorithm = avb_value(source_info, "Algorithm")
    rollback = avb_value(source_info, "Rollback Index")
    location = avb_value(
        source_info, "Rollback Index Location", False
    )
    partition = avb_value(source_info, "Partition Name")
    salt = avb_value(source_info, "Salt")
    hash_algorithm = avb_value(source_info, "Hash Algorithm")
    properties = avb_properties(source_info)

    require(
        algorithm == "SHA256_RSA2048",
        "Unexpected source init_boot AVB signing algorithm",
    )

    require(
        partition == "init_boot"
        and hash_algorithm == "sha256",
        "Unexpected source init_boot AVB hash descriptor",
    )

    require(
        re.fullmatch(r"[0-9a-fA-F]+", salt) is not None,
        "Invalid source AVB salt",
    )

    require(
        len(properties) >= 1,
        "Source init_boot properties could not be recovered",
    )

    return {
        "algorithm": algorithm,
        "rollback_index": int(rollback, 0),
        "rollback_index_location": (
            int(location, 0) if location is not None else 0
        ),
        "partition_name": partition,
        "hash_algorithm": hash_algorithm,
        "salt": salt.lower(),
        "properties": properties,
    }


def unpack_arguments(unpack_bootimg, image, destination):
    destination.mkdir(parents=True, exist_ok=True)

    args = [
        unpack_bootimg,
        "--boot_img", image,
        "--out", destination,
        "--format=mkbootimg",
    ]

    # AOSP's null-delimited output avoids ambiguities in
    # command lines and paths. Older tool builds can use
    # the shell-quoted mkbootimg format instead.
    attempt = subprocess.run(
        [str(x) for x in args] + ["-0"],
        capture_output=True,
    )

    if attempt.returncode == 0 and b"\0" in attempt.stdout:
        require(
            attempt.stdout.endswith(b"\0"),
            "Unterminated mkbootimg argument stream",
        )
        values = [
            x.decode("utf-8")
            for x in attempt.stdout[:-1].split(b"\0")
        ]
    else:
        if attempt.returncode:
            output = command(*args)
        else:
            output = attempt.stdout

        values = shlex.split(output.decode("utf-8"))

    require(
        len(values) >= 2 and len(values) % 2 == 0,
        "Cannot interpret canonical mkbootimg arguments",
    )

    result = {}

    for i in range(0, len(values), 2):
        key, value = values[i:i + 2]

        require(
            key.startswith("--"),
            "Invalid unpacked mkbootimg option",
        )

        require(
            key not in result,
            "Duplicate unpacked mkbootimg option: " + key,
        )

        result[key] = value

    require(
        result.get("--header_version") == "4",
        "Expected canonical Android boot-header version 4",
    )

    require(
        "--ramdisk" in result,
        "Canonical init_boot ramdisk was not extracted",
    )

    # init_boot contains no kernel. Never silently copy
    # a kernel into a Bootstrap-owned image.
    kernel = destination / "kernel"

    require(
        not kernel.exists() or kernel.stat().st_size == 0,
        "Unexpected kernel payload in init_boot template",
    )

    signature = destination / "boot_signature"

    require(
        not signature.exists() or signature.stat().st_size == 0,
        "Unexpected embedded boot signature",
    )

    return result


def repack_arguments(original, ramdisk, output):
    result = []

    for key, value in original.items():
        if key in (
            "--kernel",
            "--ramdisk",
            "--boot_signature",
            "--output",
        ):
            continue

        result.extend((key, value))

    result.extend((
        "--ramdisk", str(ramdisk),
        "--output", str(output),
    ))

    return result


def verify_payload(
    unpack_bootimg,
    image,
    original_args,
    expected_ramdisk_sha,
    destination,
):
    rebuilt_args = unpack_arguments(
        unpack_bootimg, image, destination
    )

    unchanged = (
        set(original_args)
        | set(rebuilt_args)
    ) - {
        "--kernel",
        "--ramdisk",
        "--boot_signature",
        "--output",
    }

    for key in unchanged:
        require(
            original_args.get(key) == rebuilt_args.get(key),
            "Canonical init_boot header changed: " + key,
        )

    ramdisk = destination / "ramdisk"

    require(
        sha(ramdisk) == expected_ramdisk_sha,
        "Repacked init_boot ramdisk differs from ChromiumOS runtime",
    )


def verify_signed(
    toolset,
    image,
    source_args,
    avb_contract,
    runtime_sha,
    unpack_to,
):
    require(
        image.stat().st_size == PARTITION_SIZE,
        "Signed init_boot partition size changed",
    )

    command(
        toolset["avbtool"], "verify_image",
        "--image", image,
        "--key", SIGNING_KEY,
    )

    signed_info = command(
        toolset["avbtool"], "info_image",
        "--image", image,
    ).decode(errors="replace")

    require(
        avb_value(signed_info, "Algorithm")
        == avb_contract["algorithm"],
        "Signed init_boot AVB algorithm changed",
    )

    require(
        int(avb_value(signed_info, "Rollback Index"), 0)
        == avb_contract["rollback_index"],
        "Signed init_boot rollback index changed",
    )

    require(
        avb_value(signed_info, "Partition Name")
        == "init_boot",
        "Signed init_boot partition identity changed",
    )

    require(
        avb_value(signed_info, "Salt").lower()
        == avb_contract["salt"],
        "Signed init_boot salt changed",
    )

    require(
        avb_properties(signed_info)
        == avb_contract["properties"],
        "Signed init_boot properties differ from canonical AOSP",
    )

    verify_payload(
        toolset["unpack_bootimg"],
        image,
        source_args,
        runtime_sha,
        unpack_to,
    )


def build():
    require_profile()
    runtime = runtime_contract()
    toolset = tools()
    contract = source_contract(toolset["avbtool"])

    require(
        not OUTPUT_IMAGE.exists()
        and not OUTPUT_METADATA.exists(),
        "ChromiumOS image already exists; verify it "
        "instead of overwriting an accepted candidate",
    )

    IMAGE_WORK.mkdir(parents=True, exist_ok=True)
    IMAGE_OUT.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="chromiumos-init-boot-",
        dir=IMAGE_WORK,
    ) as temporary:
        temp = Path(temporary)

        source_args = unpack_arguments(
            toolset["unpack_bootimg"],
            SOURCE_INIT_BOOT,
            temp / "canonical",
        )

        raw = temp / "init_boot.raw.img"

        command(
            toolset["mkbootimg"],
            *repack_arguments(
                source_args,
                COMPRESSED_INITRAMFS,
                raw,
            ),
        )

        verify_payload(
            toolset["unpack_bootimg"],
            raw,
            source_args,
            runtime["initramfs.lz4"],
            temp / "raw-check",
        )

        signed = temp / "init_boot.img"
        shutil.copyfile(raw, signed)

        avb_args = [
            toolset["avbtool"],
            "add_hash_footer",
            "--image", signed,
            "--partition_name", "init_boot",
            "--partition_size", str(PARTITION_SIZE),
            "--key", SIGNING_KEY,
            "--algorithm", contract["algorithm"],
            "--rollback_index",
            str(contract["rollback_index"]),
            "--rollback_index_location",
            str(contract["rollback_index_location"]),
            "--hash_algorithm", contract["hash_algorithm"],
            "--salt", contract["salt"],
        ]

        for key, value in contract["properties"].items():
            avb_args.extend((
                "--prop",
                key + ":" + value,
            ))

        command(*avb_args)

        verify_signed(
            toolset,
            signed,
            source_args,
            contract,
            runtime["initramfs.lz4"],
            temp / "signed-check",
        )

        metadata = {
            "schema": 1,
            "profile_id": PROFILE,
            "state": "development-candidate",
            "device": "tangorpro",
            "source_init_boot_sha256": sha(SOURCE_INIT_BOOT),
            "source_vbmeta_sha256": sha(SOURCE_VBMETA),
            "signing_key_sha256": sha(SIGNING_KEY),
            "runtime_sha256": runtime,
            "image_sha256": sha(signed),
            "image_bytes": signed.stat().st_size,
            "avb": contract,
            "kernel_dependency": None,
            "hardware_validated": False,
        }

        metadata_path = temp / "image.json"
        metadata_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True)
            + "\n"
        )

        # Publish only after all payload and AVB checks pass.
        shutil.copy2(signed, OUTPUT_IMAGE)
        shutil.copy2(metadata_path, OUTPUT_METADATA)

    print("CHROMIUMOS_INIT_BOOT_IMAGE=" + str(OUTPUT_IMAGE))
    print("CHROMIUMOS_INIT_BOOT_SHA256=" + sha(OUTPUT_IMAGE))
    print("CHROMIUMOS_INIT_BOOT_BUILD=PASS")

    return OUTPUT_IMAGE


def verify():
    require_profile()
    runtime = runtime_contract()
    toolset = tools()
    contract = source_contract(toolset["avbtool"])

    require(
        OUTPUT_IMAGE.is_file() and OUTPUT_METADATA.is_file(),
        "ChromiumOS init_boot candidate has not been built",
    )

    metadata = json.loads(OUTPUT_METADATA.read_text())

    require(
        metadata.get("profile_id") == PROFILE,
        "Image metadata has the wrong build profile",
    )

    require(
        metadata.get("runtime_sha256") == runtime,
        "Image was built using a different runtime",
    )

    require(
        metadata.get("image_sha256") == sha(OUTPUT_IMAGE),
        "Signed image identity differs from metadata",
    )

    require(
        metadata.get("source_init_boot_sha256")
        == sha(SOURCE_INIT_BOOT),
        "Canonical template identity differs from metadata",
    )

    require(
        metadata.get("avb") == contract,
        "AVB signing contract differs from metadata",
    )

    IMAGE_WORK.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="chromiumos-init-verify-",
        dir=IMAGE_WORK,
    ) as temporary:
        temp = Path(temporary)

        original_args = unpack_arguments(
            toolset["unpack_bootimg"],
            SOURCE_INIT_BOOT,
            temp / "canonical",
        )

        verify_signed(
            toolset,
            OUTPUT_IMAGE,
            original_args,
            contract,
            runtime["initramfs.lz4"],
            temp / "candidate",
        )

    print("CHROMIUMOS_INIT_BOOT_SHA256=" + sha(OUTPUT_IMAGE))
    print("CHROMIUMOS_INIT_BOOT_VERIFY=PASS")

    return OUTPUT_IMAGE
