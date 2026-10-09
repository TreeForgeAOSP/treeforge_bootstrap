from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

from .host_providers import (
    ensure_fec,
    ensure_host_tool,
    ensure_kernel_avbtool,
)
from .kernel_family import (
    CARRIERS,
    ensure_kernel_family_payload,
)


class TreeForgeKernelCarrierError(RuntimeError):
    pass


#
# r0.94-v1.0b2 accepted build geometry.
#
# These are reconstruction parameters, not distributed
# partition-image identities.
#
DLKM_GEOMETRY = {
    "vendor_dlkm": {
        "filesystem_bytes": 42422272,
        "partition_bytes": 43110400,
        "blocks": 10357,
        "inodes": 544,
        "uuid":
            "7fc39a1d-6b52-5279-be04-368598326b8c",
        "selinux":
            "u:object_r:vendor_file:s0",
        "module_selinux":
            "u:object_r:vendor_kernel_modules:s0",
        "salt":
            "641d11b81bba030518ef823fb1d9f14c"
            "2523bf86207dbc430de92c8b2b17ed6d",
    },
    "system_dlkm": {
        "filesystem_bytes": 12013568,
        "partition_bytes": 12218368,
        "blocks": 2933,
        "inodes": 144,
        "uuid":
            "b9a769a7-2107-5447-b4df-5b05124dcdd0",
        "selinux":
            "u:object_r:system_dlkm_file:s0",
        "salt":
            "53f40afa0653eaacfb41c4bc2363d6c9"
            "708662dfffb6aa8621f5a6df03a436a7",
    },
}


def _run(
    args: list[str | Path],
    *,
    cwd: Path | None = None,
    data: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    environment = os.environ.copy()

    #
    # avbtool invokes `fec` by basename. Supply the exact pinned
    # AOSP FEC binary and the verified libc++ runtime already
    # carried by the android-image-tools host provider.
    #
    if (
        args
        and Path(
            str(args[0])
        ).name == "avbtool"
    ):
        fec = ensure_fec()

        image_tool = ensure_host_tool(
            "mkbootimg"
        )

        provider_payload = (
            image_tool
            .parent
            .parent
        )

        provider_lib64 = (
            provider_payload
            / "lib64"
        )

        libcxx = (
            provider_lib64
            / "libc++.so"
        )

        if not libcxx.is_file():
            raise TreeForgeKernelCarrierError(
                "android-image-tools libc++.so missing"
            )

        environment["PATH"] = (
            str(fec.parent)
            + os.pathsep
            + environment.get(
                "PATH",
                "",
            )
        )

        old_ld = environment.get(
            "LD_LIBRARY_PATH",
            "",
        )

        environment[
            "LD_LIBRARY_PATH"
        ] = (
            str(provider_lib64)
            if not old_ld
            else (
                str(provider_lib64)
                + os.pathsep
                + old_ld
            )
        )

    result = subprocess.run(
        [str(v) for v in args],
        cwd=cwd,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )

    if check and result.returncode:
        raise TreeForgeKernelCarrierError(
            f"{Path(str(args[0])).name} failed:\n"
            + result.stderr.decode(
                errors="replace"
            )[-4000:]
        )

    return result


def _source_image(
    root: Path,
    name: str,
) -> Path:
    for filename in (
        f"{name}.img",
        f"{name}_a.img",
    ):
        path = root / filename

        if path.is_file():
            return path

    raise TreeForgeKernelCarrierError(
        f"source image missing: {name}"
    )


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


def _avb_salt(
    info: str,
) -> str:
    match = re.search(
        r"^\s+Salt:\s+([0-9a-fA-F]+)\s*$",
        info,
        flags=re.MULTILINE,
    )

    if match is None:
        raise TreeForgeKernelCarrierError(
            "AVB salt missing"
        )

    return match.group(1)


def _avb_properties(
    info: str,
) -> list[tuple[str, str]]:
    return re.findall(
        r"^\s+Prop: (.*?) -> '(.*)'$",
        info,
        flags=re.MULTILINE,
    )


def _apply_ext4_metadata(
    image: Path,
    root: Path,
    context: str,
    module_context: str | None = None,
) -> None:
    debugfs = shutil.which(
        "debugfs"
    )

    if debugfs is None:
        raise TreeForgeKernelCarrierError(
            "debugfs is required"
        )

    with tempfile.TemporaryDirectory(
        prefix=".treeforge-ext4-meta-"
    ) as raw:
        temporary = Path(raw)

        context_file = (
            temporary
            / "context.bin"
        )

        context_file.write_bytes(
            context.encode("utf-8")
            + b"\0"
        )

        module_context_file = None

        if module_context is not None:
            module_context_file = (
                temporary
                / "module-context.bin"
            )

            module_context_file.write_bytes(
                module_context.encode("utf-8")
                + b"\0"
            )

        paths = [
            Path("/"),
            Path("/lost+found"),
        ]

        for item in sorted(
            root.rglob("*")
        ):
            paths.append(
                Path("/")
                / item.relative_to(root)
            )

        commands = (
            temporary
            / "debugfs.commands"
        )

        with commands.open(
            "w",
            encoding="utf-8",
        ) as stream:
            for path in paths:
                value = str(path)

                stream.write(
                    f"set_inode_field {value} uid 0\n"
                )
                stream.write(
                    f"set_inode_field {value} gid 0\n"
                )

                #
                # Kleaf/mkuserimg_mke2fs realizes the DLKM
                # top-level /lib directory as 0755. The
                # provider extraction tree can inherit a
                # 0775 host mode, so normalize this inode
                # explicitly without mutating the provider
                # cache itself.
                #
                if value == "/lib":
                    stream.write(
                        "set_inode_field /lib mode 040755\n"
                    )

                selected_context_file = (
                    context_file
                )

                if (
                    module_context_file is not None
                    and value.endswith(".ko")
                ):
                    selected_context_file = (
                        module_context_file
                    )

                stream.write(
                    "ea_set "
                    f"{value} "
                    "security.selinux "
                    f"-f {selected_context_file}\n"
                )

        result = _run(
            [
                debugfs,
                "-w",
                "-f",
                commands,
                image,
            ],
            check=False,
        )

        stderr = result.stderr.decode(
            errors="replace"
        )

        if (
            result.returncode != 0
            or "Command not found" in stderr
            or "File not found" in stderr
        ):
            raise TreeForgeKernelCarrierError(
                "debugfs metadata realization failed:\n"
                + stderr[-4000:]
            )

    root_ea = _run(
        [
            debugfs,
            "-R",
            "ea_list /",
            image,
        ]
    ).stdout.decode(
        errors="replace"
    )

    if context not in root_ea:
        raise TreeForgeKernelCarrierError(
            "ext4 SELinux root context missing"
        )


def _realize_dlkm(
    *,
    name: str,
    payload_root: Path,
    output: Path,
) -> None:
    geometry = DLKM_GEOMETRY[
        name
    ]

    mke2fs = shutil.which(
        "mke2fs"
    )

    if mke2fs is None:
        raise TreeForgeKernelCarrierError(
            "mke2fs is required"
        )

    #
    # DLKM images produced by the accepted r0.94 kernel
    # build use the kernel build-tools avbtool 1.2.0.
    #
    avbtool = ensure_kernel_avbtool()

    source_root = (
        payload_root
        / name
    )

    source_modules = (
        source_root
        / "lib"
        / "modules"
    )

    if not source_modules.is_dir():
        raise TreeForgeKernelCarrierError(
            f"{name} module tree missing"
        )

    #
    # Published provider payloads retain the conventional
    # host-side lib/modules/<kernel-release>/ hierarchy.
    #
    # Pixel Android DLKM images do not. Their on-device ABI is
    # basename-flat:
    #
    #   /lib/modules/foo.ko
    #
    # with text metadata referring to those basenames.
    #
    release_roots = [
        entry
        for entry in source_modules.iterdir()
        if (
            entry.is_dir()
            and (
                entry
                / "modules.load"
            ).is_file()
        )
    ]

    if (
        source_modules
        / "modules.load"
    ).is_file():
        module_source = source_modules

    elif len(release_roots) == 1:
        module_source = release_roots[0]

    else:
        raise TreeForgeKernelCarrierError(
            f"{name} must contain one coherent "
            "module metadata root"
        )

    staging_root = (
        output.parent
        / f".{name}.stock-flat-root"
    )

    if staging_root.exists():
        shutil.rmtree(
            staging_root
        )

    flat_modules = (
        staging_root
        / "lib"
        / "modules"
    )

    flat_modules.mkdir(
        parents=True
    )

    modules = sorted(
        module_source.rglob("*.ko")
    )

    if not modules:
        raise TreeForgeKernelCarrierError(
            f"{name} contains no kernel modules"
        )

    basename_sources: dict[str, Path] = {}

    for module in modules:
        basename = module.name

        previous = basename_sources.get(
            basename
        )

        if previous is not None:
            raise TreeForgeKernelCarrierError(
                f"{name} duplicate module basename: "
                f"{basename}: {previous} and {module}"
            )

        basename_sources[
            basename
        ] = module

        shutil.copy2(
            module,
            flat_modules
            / basename,
        )

    #
    # Stock DLKM images retain only the text libmodprobe
    # metadata needed by Android.
    #
    for metadata_name in (
        "modules.alias",
        "modules.blocklist",
        "modules.softdep",
    ):
        source = (
            module_source
            / metadata_name
        )

        if source.is_file():
            shutil.copy2(
                source,
                flat_modules
                / metadata_name,
            )

    modules_load = (
        module_source
        / "modules.load"
    )

    if not modules_load.is_file():
        raise TreeForgeKernelCarrierError(
            f"{name} modules.load missing"
        )

    load_lines: list[str] = []

    for raw_line in modules_load.read_text(
        encoding="utf-8"
    ).splitlines():
        line = raw_line.strip()

        if not line:
            continue

        basename = Path(line).name

        if basename not in basename_sources:
            raise TreeForgeKernelCarrierError(
                f"{name} modules.load references "
                f"missing module: {line}"
            )

        load_lines.append(
            basename
        )

    (
        flat_modules
        / "modules.load"
    ).write_text(
        "\n".join(load_lines)
        + "\n",
        encoding="utf-8",
    )

    modules_dep = (
        module_source
        / "modules.dep"
    )

    if not modules_dep.is_file():
        raise TreeForgeKernelCarrierError(
            f"{name} modules.dep missing"
        )

    dep_lines: list[str] = []

    for raw_line in modules_dep.read_text(
        encoding="utf-8"
    ).splitlines():
        if ":" not in raw_line:
            if raw_line.strip():
                raise TreeForgeKernelCarrierError(
                    f"{name} malformed modules.dep line: "
                    f"{raw_line}"
                )
            continue

        module_path, dependency_text = (
            raw_line.split(
                ":",
                1,
            )
        )

        module_name = Path(
            module_path.strip()
        ).name

        dependencies = [
            Path(value).name
            for value in dependency_text.split()
        ]

        rendered = (
            module_name
            + ":"
        )

        if dependencies:
            rendered += (
                " "
                + " ".join(
                    dependencies
                )
            )

        dep_lines.append(
            rendered
        )

    (
        flat_modules
        / "modules.dep"
    ).write_text(
        "\n".join(dep_lines)
        + "\n",
        encoding="utf-8",
    )

    carrier_root = staging_root

    if output.exists():
        output.unlink()

    _run(
        [
            mke2fs,
            "-q",
            "-F",
            "-t",
            "ext4",
            "-b",
            "4096",
            "-N",
            str(geometry["inodes"]),
            "-L",
            name,
            "-U",
            geometry["uuid"],
            "-O",
            (
                "ext_attr,dir_index,filetype,"
                "extent,sparse_super,large_file,"
                "huge_file,uninit_bg,dir_nlink,"
                "extra_isize,^has_journal,"
                "^metadata_csum,^64bit,^flex_bg"
            ),
            "-E",
            (
                "lazy_itable_init=0,"
                "lazy_journal_init=0,"
                "root_owner=0:0"
            ),
            "-d",
            carrier_root,
            output,
            str(geometry["blocks"]),
        ]
    )

    expected_fs = int(
        geometry[
            "filesystem_bytes"
        ]
    )

    if output.stat().st_size != expected_fs:
        raise TreeForgeKernelCarrierError(
            f"{name} filesystem size changed: "
            f"{output.stat().st_size} != "
            f"{expected_fs}"
        )

    _apply_ext4_metadata(
        output,
        carrier_root,
        str(
            geometry["selinux"]
        ),
        module_context=(
            str(
                geometry[
                    "module_selinux"
                ]
            )
            if "module_selinux"
            in geometry
            else None
        ),
    )

    if staging_root.exists():
        shutil.rmtree(
            staging_root
        )

    _run(
        [
            avbtool,
            "add_hashtree_footer",
            "--image",
            output,
            "--partition_name",
            name,
            "--hash_algorithm",
            "sha256",
            "--salt",
            geometry["salt"],
        ]
    )

    expected_partition = int(
        geometry[
            "partition_bytes"
        ]
    )

    if (
        output.stat().st_size
        != expected_partition
    ):
        raise TreeForgeKernelCarrierError(
            f"{name} partition size changed: "
            f"{output.stat().st_size} != "
            f"{expected_partition}"
        )


def _extract_lz4_cpio(
    fragment: Path,
    root: Path,
) -> tuple[bytes, list[str]]:
    root.mkdir(
        parents=True,
        exist_ok=True,
    )

    source_magic = fragment.read_bytes()[:4]

    decompressed = _run(
        [
            "lz4",
            "-d",
            "-c",
            fragment,
        ]
    ).stdout

    listing = _run(
        [
            "cpio",
            "-it",
            "--quiet",
        ],
        cwd=root,
        data=decompressed,
    ).stdout.decode(
        errors="surrogateescape"
    )

    source_entries = [
        line
        for line in listing.splitlines()
        if line
    ]

    extract = _run(
        [
            "cpio",
            "-idm",
            "--no-absolute-filenames",
            "--quiet",
        ],
        cwd=root,
        data=decompressed,
        check=False,
    )

    if extract.returncode != 0:
        raise TreeForgeKernelCarrierError(
            "vendor_kernel_boot ramdisk "
            "extraction failed:\n"
            + extract.stderr.decode(
                errors="replace"
            )[-4000:]
        )

    return (
        source_magic,
        source_entries,
    )


def _repack_lz4_cpio(
    root: Path,
    output: Path,
    source_magic: bytes,
    source_entries: list[str],
) -> None:
    #
    # Keep every surviving entry in its original cpio order.
    # Provider-only entries are appended deterministically.
    #
    entries: list[str] = []
    seen: set[str] = set()

    for raw_entry in source_entries:
        entry = raw_entry

        if entry == "./":
            entry = "."
        elif entry.startswith("./"):
            entry = entry[2:]

        candidate = (
            root
            if entry == "."
            else root / entry
        )

        if not (
            candidate.exists()
            or candidate.is_symlink()
        ):
            continue

        if entry in seen:
            continue

        entries.append(entry)
        seen.add(entry)

    if "." not in seen:
        entries.insert(0, ".")
        seen.add(".")

    for candidate in sorted(
        root.rglob("*"),
        key=lambda item: str(
            item.relative_to(root)
        ),
    ):
        entry = str(
            candidate.relative_to(root)
        )

        if entry in seen:
            continue

        entries.append(entry)
        seen.add(entry)

    names = (
        b"\0".join(
            entry.encode(
                errors="surrogateescape"
            )
            for entry in entries
        )
        + b"\0"
    )

    cpio = _run(
        [
            "cpio",
            "--null",
            "-o",
            "-H",
            "newc",
            "--owner=0:0",
            "--quiet",
        ],
        cwd=root,
        data=names,
    ).stdout

    legacy = (
        source_magic
        == b"\x02\x21\x4c\x18"
    )

    command = [
        "lz4",
        "-12",
        "-c",
    ]

    if legacy:
        command.insert(
            1,
            "-l",
        )

    compressed = _run(
        command,
        data=cpio,
    ).stdout

    output.write_bytes(
        compressed
    )


def _realize_vendor_kernel_boot(
    *,
    source: Path,
    payload_root: Path,
    output: Path,
) -> None:
    unpack_bootimg = ensure_host_tool(
        "unpack_bootimg"
    )

    mkbootimg = ensure_host_tool(
        "mkbootimg"
    )

    avbtool = ensure_host_tool(
        "avbtool"
    )

    source_info = _avb_info(
        avbtool,
        source,
    )

    source_salt = _avb_salt(
        source_info
    )

    properties = _avb_properties(
        source_info
    )

    with tempfile.TemporaryDirectory(
        prefix=".treeforge-vkb-"
    ) as raw:
        temporary = Path(raw)

        unpack = (
            temporary
            / "unpack"
        )

        unpack.mkdir()

        result = _run(
            [
                unpack_bootimg,
                "--boot_img",
                source,
                "--out",
                unpack,
                "--format=mkbootimg",
            ]
        )

        argument_text = (
            result.stdout.decode(
                errors="replace"
            ).strip()
        )

        arguments = shlex.split(
            argument_text
        )

        fragment = (
            unpack
            / "vendor_ramdisk00"
        )

        if not fragment.is_file():
            raise TreeForgeKernelCarrierError(
                "vendor ramdisk fragment missing"
            )

        ramdisk_root = (
            temporary
            / "ramdisk"
        )

        (
            source_magic,
            source_entries,
        ) = _extract_lz4_cpio(
            fragment,
            ramdisk_root,
        )

        modules = (
            ramdisk_root
            / "lib"
            / "modules"
        )

        if modules.exists():
            shutil.rmtree(
                modules
            )

        modules.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        shutil.copytree(
            (
                payload_root
                / "vendor_kernel_boot"
                / "lib"
                / "modules"
            ),
            modules,
        )

        rebuilt_fragment = (
            temporary
            / "vendor_ramdisk.rebuilt"
        )

        _repack_lz4_cpio(
            ramdisk_root,
            rebuilt_fragment,
            source_magic,
            source_entries,
        )

        fragment_indexes = [
            index
            for index, value
            in enumerate(arguments[:-1])
            if (
                value
                == "--vendor_ramdisk_fragment"
            )
        ]

        matching_indexes = [
            index
            for index in fragment_indexes
            if Path(
                arguments[index + 1]
            ).name == fragment.name
        ]

        if len(matching_indexes) == 1:
            fragment_index = (
                matching_indexes[0]
            )

        elif (
            len(matching_indexes) == 0
            and len(fragment_indexes) == 1
        ):
            fragment_index = (
                fragment_indexes[0]
            )

        else:
            raise TreeForgeKernelCarrierError(
                "unable to identify the unique "
                "vendor_kernel_boot module "
                "ramdisk fragment"
            )

        arguments[
            fragment_index + 1
        ] = str(
            rebuilt_fragment
        )

        if "--vendor_boot" in arguments:
            index = arguments.index(
                "--vendor_boot"
            )

            if (
                index + 1
                >= len(arguments)
            ):
                raise TreeForgeKernelCarrierError(
                    "invalid --vendor_boot argument"
                )

            arguments[
                index + 1
            ] = str(output)
        else:
            arguments.extend(
                [
                    "--vendor_boot",
                    str(output),
                ]
            )

        _run(
            [
                mkbootimg,
                *arguments,
            ]
        )

        if not output.is_file():
            raise TreeForgeKernelCarrierError(
                "mkbootimg produced no "
                "vendor_kernel_boot"
            )

    command = [
        avbtool,
        "add_hash_footer",
        "--image",
        output,
        "--partition_name",
        "vendor_kernel_boot",
        "--partition_size",
        str(source.stat().st_size),
        "--hash_algorithm",
        "sha256",
        "--salt",
        source_salt,
    ]

    for key, value in properties:
        command.extend(
            [
                "--prop",
                f"{key}:{value}",
            ]
        )

    _run(
        command
    )

    if (
        output.stat().st_size
        != source.stat().st_size
    ):
        raise TreeForgeKernelCarrierError(
            "vendor_kernel_boot partition "
            "size changed"
        )


def realize_kernel_carriers(
    *,
    input_root: Path,
    output_root: Path,
) -> dict[str, Path]:
    input_root = (
        input_root
        .expanduser()
        .resolve()
    )

    output_root = (
        output_root
        .expanduser()
        .resolve()
    )

    if output_root.exists():
        shutil.rmtree(
            output_root
        )

    output_root.mkdir(
        parents=True
    )

    provider = (
        ensure_kernel_family_payload()
    )

    payload_root = provider[
        "payload_root"
    ]

    source_vkb = _source_image(
        input_root,
        "vendor_kernel_boot",
    )

    _realize_vendor_kernel_boot(
        source=source_vkb,
        payload_root=payload_root,
        output=(
            output_root
            / "vendor_kernel_boot.img"
        ),
    )

    for name in (
        "vendor_dlkm",
        "system_dlkm",
    ):
        _realize_dlkm(
            name=name,
            payload_root=payload_root,
            output=(
                output_root
                / f"{name}.img"
            ),
        )

    return {
        name:
            output_root
            / f"{name}.img"
        for name in CARRIERS
    }
