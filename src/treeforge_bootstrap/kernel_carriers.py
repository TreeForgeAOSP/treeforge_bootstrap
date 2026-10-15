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
    include_root_metadata: bool = True,
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

        paths: list[Path] = []

        if include_root_metadata:
            paths.extend(
                [
                    Path("/"),
                    Path("/lost+found"),
                ]
            )

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
    source: Path,
    payload_root: Path,
    output: Path,
) -> None:
    geometry = DLKM_GEOMETRY[
        name
    ]

    avbtool = ensure_kernel_avbtool()

    debugfs_value = shutil.which(
        "debugfs"
    )

    if debugfs_value is None:
        raise TreeForgeKernelCarrierError(
            "debugfs is required"
        )

    debugfs = Path(
        debugfs_value
    )

    source_info = _avb_info(
        avbtool,
        source,
    )

    if "Hashtree descriptor:" not in source_info:
        raise TreeForgeKernelCarrierError(
            f"{name} source AVB hashtree missing"
        )

    source_partition_bytes = (
        source.stat().st_size
    )

    source_salt = _avb_salt(
        source_info
    )

    source_properties = (
        _avb_properties(
            source_info
        )
    )

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
    # Pixel Android DLKM images use a basename-flat on-device
    # module tree:
    #
    #   /lib/modules/foo.ko
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
        module_source = (
            source_modules
        )

    elif len(release_roots) == 1:
        module_source = (
            release_roots[0]
        )

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

    basename_sources: dict[
        str,
        Path,
    ] = {}

    for module in modules:
        basename = module.name

        if not re.fullmatch(
            r"[A-Za-z0-9._+-]+",
            basename,
        ):
            raise TreeForgeKernelCarrierError(
                f"{name} unsafe module basename: "
                f"{basename}"
            )

        previous = (
            basename_sources.get(
                basename
            )
        )

        if previous is not None:
            raise TreeForgeKernelCarrierError(
                f"{name} duplicate module basename: "
                f"{basename}: "
                f"{previous} and {module}"
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
    # Preserve the accepted Android text metadata surface.
    #
    for metadata_name in (
        "modules.alias",
        "modules.blocklist",
        "modules.softdep",
    ):
        metadata_source = (
            module_source
            / metadata_name
        )

        if metadata_source.is_file():
            shutil.copy2(
                metadata_source,
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

    for raw_line in (
        modules_load
        .read_text(
            encoding="utf-8"
        )
        .splitlines()
    ):
        line = raw_line.strip()

        if not line:
            continue

        basename = Path(
            line
        ).name

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
        "\n".join(
            load_lines
        )
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

    for raw_line in (
        modules_dep
        .read_text(
            encoding="utf-8"
        )
        .splitlines()
    ):
        if ":" not in raw_line:
            if raw_line.strip():
                raise TreeForgeKernelCarrierError(
                    f"{name} malformed "
                    f"modules.dep line: "
                    f"{raw_line}"
                )

            continue

        (
            module_path,
            dependency_text,
        ) = raw_line.split(
            ":",
            1,
        )

        module_name = Path(
            module_path.strip()
        ).name

        dependencies = [
            Path(value).name
            for value
            in dependency_text.split()
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
        "\n".join(
            dep_lines
        )
        + "\n",
        encoding="utf-8",
    )

    #
    # patch-current:
    #
    # Start from the complete installed carrier, not a new
    # modules-only filesystem. erase_footer removes the old AVB
    # hashtree/footer and returns the image to its original ext4
    # filesystem size while preserving every filesystem inode.
    #
    if output.exists():
        output.unlink()

    shutil.copy2(
        source,
        output,
    )

    _run(
        [
            avbtool,
            "erase_footer",
            "--image",
            output,
        ]
    )

    filesystem_bytes = (
        output.stat().st_size
    )

    if (
        filesystem_bytes <= 0
        or filesystem_bytes
        >= source_partition_bytes
    ):
        raise TreeForgeKernelCarrierError(
            f"{name} AVB footer erase "
            "did not expose filesystem"
        )

    #
    # Enumerate the existing flat module directory. Android's
    # tangorpro DLKM ABI is intentionally flat; nested content
    # here would require an explicit policy decision rather than
    # silently deleting it.
    #
    listing = _run(
        [
            debugfs,
            "-R",
            "ls -p /lib/modules",
            output,
        ]
    ).stdout.decode(
        errors="replace"
    )

    existing_entries: list[str] = []

    for raw_line in listing.splitlines():
        line = raw_line.strip()

        if not line.startswith("/"):
            continue

        fields = line.split("/")

        if len(fields) < 7:
            continue

        mode = fields[2]
        entry_name = fields[5]

        if entry_name in {
            ".",
            "..",
        }:
            continue

        if not re.fullmatch(
            r"[A-Za-z0-9._+-]+",
            entry_name,
        ):
            raise TreeForgeKernelCarrierError(
                f"{name} unsafe existing "
                f"module-tree entry: "
                f"{entry_name}"
            )

        if mode.startswith("04"):
            raise TreeForgeKernelCarrierError(
                f"{name} unexpected nested "
                f"module directory: "
                f"{entry_name}"
            )

        existing_entries.append(
            entry_name
        )

    if not existing_entries:
        raise TreeForgeKernelCarrierError(
            f"{name} source module tree empty"
        )

    with tempfile.TemporaryDirectory(
        prefix=f".treeforge-{name}-patch-"
    ) as raw:
        temporary = Path(raw)

        commands = (
            temporary
            / "debugfs.commands"
        )

        with commands.open(
            "w",
            encoding="utf-8",
        ) as stream:
            #
            # Replace-exact means no stale source modules or
            # metadata may survive.
            #
            for entry_name in sorted(
                set(existing_entries)
            ):
                stream.write(
                    "rm "
                    f"/lib/modules/"
                    f"{entry_name}\n"
                )

            for item in sorted(
                flat_modules.iterdir()
            ):
                if not item.is_file():
                    raise (
                        TreeForgeKernelCarrierError(
                            f"{name} generated module "
                            f"tree is not flat: {item}"
                        )
                    )

                entry_name = item.name

                if not re.fullmatch(
                    r"[A-Za-z0-9._+-]+",
                    entry_name,
                ):
                    raise (
                        TreeForgeKernelCarrierError(
                            f"{name} unsafe generated "
                            f"module-tree entry: "
                            f"{entry_name}"
                        )
                    )

                stream.write(
                    "write "
                    f"{shlex.quote(str(item))} "
                    f"/lib/modules/"
                    f"{entry_name}\n"
                )

        result = _run(
            [
                debugfs,
                "-w",
                "-f",
                commands,
                output,
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
            or "No space left" in stderr
        ):
            raise TreeForgeKernelCarrierError(
                f"{name} module-tree patch failed:\n"
                + stderr[-4000:]
            )

    #
    # Apply metadata only to /lib/modules and the newly written
    # module payload. Do not rewrite /etc or any other preserved
    # source inode.
    #
    _apply_ext4_metadata(
        output,
        staging_root,
        str(
            geometry[
                "selinux"
            ]
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
        include_root_metadata=False,
    )

    if (
        output.stat().st_size
        != filesystem_bytes
    ):
        raise TreeForgeKernelCarrierError(
            f"{name} filesystem size changed "
            "during module patch"
        )

    #
    # Hard preservation gates. A contaminated modules-only source
    # must fail here rather than becoming the next trusted backup.
    #
    required_non_module = [
        "/etc",
        "/etc/build.prop",
        "/etc/fs_config_dirs",
        "/etc/fs_config_files",
    ]

    if name == "vendor_dlkm":
        required_non_module.append(
            "/etc/init.insmod.tangorpro.cfg"
        )

    for required_path in required_non_module:
        probe = _run(
            [
                debugfs,
                "-R",
                f"stat {required_path}",
                output,
            ],
            check=False,
        )

        diagnostic = (
            probe.stdout
            + probe.stderr
        ).decode(
            errors="replace"
        )

        if (
            probe.returncode != 0
            or "File not found" in diagnostic
            or "not found by ext2_lookup"
            in diagnostic
        ):
            raise TreeForgeKernelCarrierError(
                f"{name} preserved payload "
                f"missing: {required_path}"
            )

    if staging_root.exists():
        shutil.rmtree(
            staging_root
        )

    #
    # Recreate the child hashtree/footer using the source
    # partition size and source salt. Parent Owner-AVB descriptors
    # are regenerated later by Pixel Partitioner.
    #
    command: list[str | Path] = [
        avbtool,
        "add_hashtree_footer",
        "--image",
        output,
        "--partition_name",
        name,
        "--partition_size",
        str(
            source_partition_bytes
        ),
        "--hash_algorithm",
        "sha256",
        "--salt",
        source_salt,
    ]

    for key, value in source_properties:
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
        != source_partition_bytes
    ):
        raise TreeForgeKernelCarrierError(
            f"{name} partition size changed: "
            f"{output.stat().st_size} != "
            f"{source_partition_bytes}"
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
        source_dlkm = _source_image(
            input_root,
            name,
        )

        _realize_dlkm(
            name=name,
            source=source_dlkm,
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
