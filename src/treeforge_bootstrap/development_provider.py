from __future__ import annotations

from datetime import datetime
import hashlib
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from .framebuffer_provider import (
    load_framebuffer_provider,
)

from .menu_provider import (
    load_menu_provider,
)

from .provider import (
    PROVIDER_ROOT_NAME,
    _add_directory,
    _add_file,
    _checksums,
    _manager_update_metadata,
    _provider_metadata,
)

from .runtime import (
    COMPRESSED_INITRAMFS,
    FROZEN_RUNTIME_CPIO_BYTES,
    FROZEN_RUNTIME_CPIO_SHA256,
    FROZEN_RUNTIME_LZ4_BYTES,
    FROZEN_RUNTIME_LZ4_SHA256,
    FROZEN_RUNTIME_MENU_BYTES,
    FROZEN_RUNTIME_MENU_SHA256,
    MENU_BINARY,
    RAW_INITRAMFS,
    verify_runtime,
)

from .realizer_provider import (
    MANAGER_ASSET,
    REALIZER_ASSET,
    REALIZER_METADATA,
    REALIZER_ROOT,
    RUNTIME_ASSET,
    _copy_payload,
    _git_commit,
    _git_dirty,
    _normalized_tar_bytes,
    _payload_paths,
    _realizer_metadata,
    _safe_extract,
    _sha256,
    _write_internal_sums,
    _write_json,
)


class TreeForgeBootstrapDevelopmentProviderError(
    RuntimeError
):
    pass


ROOT = Path(
    __file__
).resolve().parents[2]

VERSION_FILE = ROOT / "VERSION"

RUNTIME_DIR = (
    ROOT
    / "out"
    / "tangorpro"
    / "runtime"
)

DEVELOPMENT_ROOT = (
    ROOT
    / "out"
    / "development-provider"
)

DEVELOPMENT_RUNS = (
    DEVELOPMENT_ROOT
    / "runs"
)

DEVELOPMENT_INCOMING = (
    DEVELOPMENT_ROOT
    / ".incoming"
)

DEVELOPMENT_CURRENT = (
    DEVELOPMENT_ROOT
    / "current"
)

LEGACY_DEVELOPMENT_DIR = (
    ROOT
    / "out"
    / "tangorpro"
    / "development-provider"
)

RELEASE_ROOT = (
    ROOT
    / "out"
    / "releases"
)

DEVELOPMENT_RETENTION = 5

DEPENDENCY_DEVELOPMENT_SCHEMA = (
    "treeforge.development-provider.v1"
)

BOOTSTRAP_DEVELOPMENT_SCHEMA = 1

DEVELOPMENT_PROVIDER = "bootstrap"


def _run_id() -> str:
    return (
        datetime.now()
        .astimezone()
        .strftime(
            "%Y%m%d-%H%M%S-%f%z"
        )
    )


def _version_fields() -> dict[str, str]:
    values: dict[str, str] = {}

    for raw in VERSION_FILE.read_text(
        encoding="utf-8"
    ).splitlines():
        line = raw.strip()

        if (
            not line
            or line.startswith("#")
        ):
            continue

        if "=" not in line:
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    f"invalid VERSION record: {line}"
                )
            )

        key, value = line.split(
            "=",
            1,
        )

        values[
            key.strip()
        ] = value.strip()

    bootstrap = values.get(
        "TREEFORGE_BOOTSTRAP_VERSION"
    )

    runtime_abi = values.get(
        "TREEFORGE_RUNTIME_ABI_VERSION"
    )

    if not bootstrap or not runtime_abi:
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "VERSION contract is incomplete"
            )
        )

    return {
        "bootstrap": bootstrap,
        "runtime_abi": runtime_abi,
    }


def _git_remote() -> str:
    result = subprocess.run(
        [
            "git",
            "config",
            "--get",
            "remote.origin.url",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    if (
        result.returncode == 0
        and result.stdout.strip()
    ):
        return result.stdout.strip()

    return (
        "TreeForgeAOSP/"
        "treeforge_bootstrap"
    )


def _record(
    path: Path,
) -> dict[str, object]:
    if not path.is_file():
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                f"artifact missing: {path}"
            )
        )

    return {
        "bytes":
            path.stat().st_size,

        "sha256":
            _sha256(path),
    }


def _dependency_record(
    root: Path,
    version: str,
    *,
    boot_manager_version: str | None = None,
) -> dict[str, object]:
    resolved = root.resolve()

    record: dict[str, object] = {
        "root":
            str(resolved),

        "version":
            version,
    }

    if boot_manager_version is not None:
        record[
            "boot_manager_version"
        ] = boot_manager_version

    development = (
        resolved
        / "development-provider.json"
    )

    provider = (
        resolved
        / "provider.json"
    )

    if development.is_file():
        metadata = json.loads(
            development.read_text(
                encoding="utf-8"
            )
        )

        if (
            metadata.get("schema")
            != DEPENDENCY_DEVELOPMENT_SCHEMA
        ):
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "dependency development "
                    f"schema changed: {resolved}"
                )
            )

        record.update(
            {
                "channel":
                    "development",

                "source_commit":
                    metadata.get(
                        "source_commit"
                    ),

                "source_dirty":
                    metadata.get(
                        "source_dirty"
                    ),

                "development_manifest_sha256":
                    _sha256(
                        development
                    ),
            }
        )

    else:
        record[
            "channel"
        ] = "published"

    if provider.is_file():
        record[
            "provider_manifest_sha256"
        ] = _sha256(
            provider
        )

    return record


def _runtime_payloads(
) -> dict[str, bytes]:
    verify_runtime()

    paths = {
        "initramfs.cpio":
            RAW_INITRAMFS,

        "initramfs.lz4":
            COMPRESSED_INITRAMFS,

        "treeforge-menu":
            MENU_BINARY,
    }

    payloads: dict[str, bytes] = {}

    for name, path in paths.items():
        if not path.is_file():
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "runtime file missing: "
                    f"{path}"
                )
            )

        payloads[name] = (
            path.read_bytes()
        )

    return payloads


def _write_runtime_provider(
    root: Path,
) -> tuple[
    Path,
    dict[str, bytes],
]:
    payloads = _runtime_payloads()

    metadata = _provider_metadata(
        payloads
    )

    checksums = _checksums(
        {
            "payload/initramfs.cpio":
                payloads[
                    "initramfs.cpio"
                ],

            "payload/initramfs.lz4":
                payloads[
                    "initramfs.lz4"
                ],

            "payload/bin/treeforge-menu":
                payloads[
                    "treeforge-menu"
                ],

            "metadata/provider.json":
                metadata,
        }
    )

    runtime = (
        root
        / RUNTIME_ASSET
    )

    (
        root
        / "provider.json"
    ).write_bytes(
        metadata
    )

    (
        root
        / "SHA256SUMS"
    ).write_bytes(
        checksums
    )

    archive_root = PROVIDER_ROOT_NAME

    with tarfile.open(
        runtime,
        mode="w:xz",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        for directory in (
            archive_root,
            f"{archive_root}/payload",
            f"{archive_root}/payload/bin",
            f"{archive_root}/metadata",
        ):
            _add_directory(
                archive,
                directory,
            )

        _add_file(
            archive,
            (
                f"{archive_root}/"
                "payload/initramfs.cpio"
            ),
            payloads[
                "initramfs.cpio"
            ],
        )

        _add_file(
            archive,
            (
                f"{archive_root}/"
                "payload/initramfs.lz4"
            ),
            payloads[
                "initramfs.lz4"
            ],
        )

        _add_file(
            archive,
            (
                f"{archive_root}/"
                "payload/bin/treeforge-menu"
            ),
            payloads[
                "treeforge-menu"
            ],
            executable=True,
        )

        _add_file(
            archive,
            (
                f"{archive_root}/"
                "metadata/provider.json"
            ),
            metadata,
        )

        _add_file(
            archive,
            (
                f"{archive_root}/"
                "SHA256SUMS"
            ),
            checksums,
        )

    return runtime, payloads


def _package_realizer(
    output: Path,
    runtime_sha: str,
) -> tuple[
    Path,
    dict[str, object],
]:
    metadata = _realizer_metadata(
        runtime_sha
    )

    with tempfile.TemporaryDirectory(
        prefix=(
            "treeforge-bootstrap-"
            "development-realizer-"
        )
    ) as temporary:
        archive_root = (
            Path(temporary)
            / REALIZER_ROOT
        )

        payload_root = (
            archive_root
            / "payload"
        )

        archive_root.mkdir(
            parents=True
        )

        _copy_payload(
            payload_root
        )

        _write_json(
            archive_root
            / REALIZER_METADATA,
            metadata,
        )

        _write_internal_sums(
            archive_root
        )

        compressed = lzma.compress(
            _normalized_tar_bytes(
                archive_root
            ),
            format=lzma.FORMAT_XZ,
            preset=(
                9
                | lzma.PRESET_EXTREME
            ),
        )

        temporary_output = (
            output.with_suffix(
                output.suffix
                + ".tmp"
            )
        )

        temporary_output.write_bytes(
            compressed
        )

        temporary_output.replace(
            output
        )

    return output, metadata


def _materialize_direct(
    root: Path,
    metadata: dict[str, object],
) -> None:
    #
    # Canonical current is itself resolver-ready.
    # No current/provider or materialized layer.
    #
    _copy_payload(
        root
    )

    runtime_target = (
        root
        / "out"
        / "tangorpro"
        / "runtime"
    )

    runtime_target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copytree(
        RUNTIME_DIR,
        runtime_target,
    )

    _write_json(
        root
        / REALIZER_METADATA,
        metadata,
    )

    executable = (
        root
        / "treeforge-bootstrap"
    )

    if not executable.is_file():
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "development executable missing"
            )
        )

    executable.chmod(
        executable.stat().st_mode
        | 0o111
    )

    carrier = (
        root
        / "src"
        / "treeforge_bootstrap"
        / "vendor_boot_carrier.py"
    )

    if not carrier.is_file():
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "vendor_boot carrier missing"
            )
        )


def _read_manifest(
    root: Path,
) -> dict[str, object]:
    path = (
        root
        / "development-provider.json"
    )

    if not path.is_file():
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "development-provider.json missing"
            )
        )

    try:
        value = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "development-provider.json "
                "is unreadable"
            )
        ) from error

    if not isinstance(
        value,
        dict,
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "development provider "
                "manifest is not an object"
            )
        )

    return value


def _verify_runtime_archive(
    root: Path,
    runtime_files: dict[str, object],
) -> None:
    runtime = (
        root
        / RUNTIME_ASSET
    )

    expected = {
        (
            f"{PROVIDER_ROOT_NAME}/"
            "payload/initramfs.cpio"
        ):
            "initramfs.cpio",

        (
            f"{PROVIDER_ROOT_NAME}/"
            "payload/initramfs.lz4"
        ):
            "initramfs.lz4",

        (
            f"{PROVIDER_ROOT_NAME}/"
            "payload/bin/treeforge-menu"
        ):
            "treeforge-menu",
    }

    with tarfile.open(
        runtime,
        mode="r:xz",
    ) as archive:
        for member_name, runtime_name in (
            expected.items()
        ):
            member = archive.getmember(
                member_name
            )

            stream = archive.extractfile(
                member
            )

            if stream is None:
                raise (
                    TreeForgeBootstrapDevelopmentProviderError(
                        "runtime member unreadable: "
                        f"{member_name}"
                    )
                )

            payload = stream.read()

            record = runtime_files.get(
                runtime_name
            )

            if (
                not isinstance(
                    record,
                    dict,
                )
                or record.get("bytes")
                != len(payload)
                or record.get("sha256")
                != hashlib.sha256(
                    payload
                ).hexdigest()
            ):
                raise (
                    TreeForgeBootstrapDevelopmentProviderError(
                        "runtime member identity "
                        f"changed: {runtime_name}"
                    )
                )

        provider = archive.extractfile(
            archive.getmember(
                (
                    f"{PROVIDER_ROOT_NAME}/"
                    "metadata/provider.json"
                )
            )
        )

        sums = archive.extractfile(
            archive.getmember(
                (
                    f"{PROVIDER_ROOT_NAME}/"
                    "SHA256SUMS"
                )
            )
        )

        if (
            provider is None
            or sums is None
            or provider.read()
            != (
                root
                / "provider.json"
            ).read_bytes()
            or sums.read()
            != (
                root
                / "SHA256SUMS"
            ).read_bytes()
        ):
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "runtime provider metadata "
                    "does not match provider root"
                )
            )


def _verify_realizer(
    root: Path,
    runtime_sha: str,
) -> None:
    realizer = (
        root
        / REALIZER_ASSET
    )

    direct_metadata = (
        root
        / REALIZER_METADATA
    )

    if not direct_metadata.is_file():
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "direct realizer metadata missing"
            )
        )

    metadata = json.loads(
        direct_metadata.read_text(
            encoding="utf-8"
        )
    )

    dependency = metadata.get(
        "runtime_dependency"
    )

    if (
        not isinstance(
            dependency,
            dict,
        )
        or dependency.get("sha256")
        != runtime_sha
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "realizer runtime dependency "
                "does not match development runtime"
            )
        )

    with tempfile.TemporaryDirectory(
        prefix=(
            "treeforge-bootstrap-"
            "development-verify-"
        )
    ) as temporary:
        extracted = _safe_extract(
            realizer,
            Path(temporary),
        )

        _verify_internal_realizer_sums(
            extracted
        )

        archived_metadata = (
            extracted
            / REALIZER_METADATA
        )

        if (
            not archived_metadata.is_file()
            or archived_metadata.read_bytes()
            != direct_metadata.read_bytes()
        ):
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "direct/archived realizer "
                    "metadata mismatch"
                )
            )

        for relative in _payload_paths():
            direct = (
                root
                / relative
            )

            archived = (
                extracted
                / "payload"
                / relative
            )

            if (
                not direct.is_file()
                or not archived.is_file()
                or direct.read_bytes()
                != archived.read_bytes()
            ):
                raise (
                    TreeForgeBootstrapDevelopmentProviderError(
                        "direct/archived source "
                        f"mismatch: {relative}"
                    )
                )


def _verify_internal_realizer_sums(
    archive_root: Path,
) -> None:
    sums = (
        archive_root
        / "SHA256SUMS"
    )

    if not sums.is_file():
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "realizer SHA256SUMS missing"
            )
        )

    for raw in sums.read_text(
        encoding="utf-8"
    ).splitlines():
        raw = raw.strip()

        if not raw:
            continue

        try:
            digest, name = raw.split(
                None,
                1,
            )
        except ValueError as error:
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "invalid realizer "
                    "checksum line"
                )
            ) from error

        target = (
            archive_root
            / name.strip()
        )

        if (
            not target.is_file()
            or _sha256(target)
            != digest
        ):
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "realizer checksum mismatch: "
                    f"{name.strip()}"
                )
            )


def verify_development_provider(
    root: Path | None = None,
) -> Path:
    if root is None:
        if not DEVELOPMENT_CURRENT.exists():
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "development provider "
                    "current is missing"
                )
            )

        root = (
            DEVELOPMENT_CURRENT
            .resolve(
                strict=True
            )
        )

    else:
        root = (
            root
            .expanduser()
            .resolve(
                strict=True
            )
        )

    manifest = _read_manifest(
        root
    )

    if (
        manifest.get("schema")
        != BOOTSTRAP_DEVELOPMENT_SCHEMA
        or manifest.get("provider")
        != DEVELOPMENT_PROVIDER
        or manifest.get("kind")
        != "treeforge-bootstrap-development-provider"
        or manifest.get("channel")
        != "development"
        or manifest.get(
            "release_eligible"
        )
        is not False
        or manifest.get(
            "release_contract_enforced"
        )
        is not False
        or manifest.get(
            "retention_successful_runs"
        )
        != DEVELOPMENT_RETENTION
        or manifest.get(
            "run_id"
        )
        != root.name
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "development provider "
                "identity changed"
            )
        )

    artifacts = manifest.get(
        "artifacts"
    )

    if not isinstance(
        artifacts,
        dict,
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "development artifact "
                "metadata missing"
            )
        )

    artifact_names = {
        RUNTIME_ASSET,
        REALIZER_ASSET,
        "provider.json",
        "SHA256SUMS",
    }

    if set(artifacts) != artifact_names:
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "development artifact set changed"
            )
        )

    for name in sorted(
        artifact_names
    ):
        record = artifacts.get(
            name
        )

        path = root / name

        if (
            not isinstance(
                record,
                dict,
            )
            or not path.is_file()
            or record.get("bytes")
            != path.stat().st_size
            or record.get("sha256")
            != _sha256(path)
        ):
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "development artifact "
                    f"mismatch: {name}"
                )
            )

    runtime_record = manifest.get(
        "runtime"
    )

    realizer_record = manifest.get(
        "realizer"
    )

    if (
        not isinstance(
            runtime_record,
            dict,
        )
        or runtime_record.get("name")
        != RUNTIME_ASSET
        or runtime_record.get("bytes")
        != artifacts[
            RUNTIME_ASSET
        ]["bytes"]
        or runtime_record.get("sha256")
        != artifacts[
            RUNTIME_ASSET
        ]["sha256"]
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "runtime compatibility "
                "record mismatch"
            )
        )

    if (
        not isinstance(
            realizer_record,
            dict,
        )
        or realizer_record.get("name")
        != REALIZER_ASSET
        or realizer_record.get("bytes")
        != artifacts[
            REALIZER_ASSET
        ]["bytes"]
        or realizer_record.get("sha256")
        != artifacts[
            REALIZER_ASSET
        ]["sha256"]
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "realizer compatibility "
                "record mismatch"
            )
        )

    runtime_files = manifest.get(
        "runtime_files"
    )

    if not isinstance(
        runtime_files,
        dict,
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "runtime file identity missing"
            )
        )

    provider = json.loads(
        (
            root
            / "provider.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    payload = provider.get(
        "payload"
    )

    if not isinstance(
        payload,
        dict,
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "provider payload identity missing"
            )
        )

    for name in (
        "initramfs.cpio",
        "initramfs.lz4",
        "treeforge-menu",
    ):
        record = runtime_files.get(
            name
        )

        if (
            not isinstance(
                record,
                dict,
            )
            or payload.get(name)
            != record
        ):
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "provider/runtime identity "
                    f"mismatch: {name}"
                )
            )

        direct = (
            root
            / "out"
            / "tangorpro"
            / "runtime"
            / name
        )

        if (
            not direct.is_file()
            or direct.stat().st_size
            != record.get("bytes")
            or _sha256(direct)
            != record.get("sha256")
        ):
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "direct runtime mismatch: "
                    f"{name}"
                )
            )

    _verify_runtime_archive(
        root,
        runtime_files,
    )

    _verify_realizer(
        root,
        str(
            artifacts[
                RUNTIME_ASSET
            ]["sha256"]
        ),
    )

    executable = (
        root
        / str(
            manifest.get(
                "executable"
            )
        )
    )

    carrier = (
        root
        / "src"
        / "treeforge_bootstrap"
        / "vendor_boot_carrier.py"
    )

    if (
        not executable.is_file()
        or not os.access(
            executable,
            os.X_OK,
        )
        or not carrier.is_file()
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "resolver-ready source "
                "surface incomplete"
            )
        )

    print(
        f"RUN={root}"
    )

    print(
        "CHANNEL=development"
    )

    print(
        "RELEASE_ELIGIBLE=NO"
    )

    print(
        "TREEFORGE_BOOTSTRAP_"
        "DEVELOPMENT_VERIFY=PASS"
    )

    return root


def _promote_current(
    run: Path,
) -> None:
    if (
        DEVELOPMENT_CURRENT.exists()
        and not DEVELOPMENT_CURRENT.is_symlink()
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "development-provider/current "
                "is not a symlink"
            )
        )

    temporary = (
        DEVELOPMENT_ROOT
        / (
            ".current-"
            + str(
                os.getpid()
            )
        )
    )

    if (
        temporary.exists()
        or temporary.is_symlink()
    ):
        temporary.unlink()

    temporary.symlink_to(
        Path("runs")
        / run.name
    )

    os.replace(
        temporary,
        DEVELOPMENT_CURRENT,
    )


def _prune_runs() -> None:
    runs = sorted(
        path
        for path in (
            DEVELOPMENT_RUNS
            .iterdir()
        )
        if path.is_dir()
    )

    for path in runs[
        :-DEVELOPMENT_RETENTION
    ]:
        shutil.rmtree(
            path
        )


def package_development_provider() -> Path:
    verify_runtime()
    versions = _version_fields()

    menu = load_menu_provider()

    framebuffer = (
        load_framebuffer_provider()
    )

    run_id = _run_id()

    DEVELOPMENT_RUNS.mkdir(
        parents=True,
        exist_ok=True,
    )

    DEVELOPMENT_INCOMING.mkdir(
        parents=True,
        exist_ok=True,
    )

    staging = (
        DEVELOPMENT_INCOMING
        / run_id
    )

    final = (
        DEVELOPMENT_RUNS
        / run_id
    )

    if (
        staging.exists()
        or final.exists()
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                f"development run exists: {run_id}"
            )
        )

    staging.mkdir(
        parents=True
    )

    try:
        runtime, payloads = (
            _write_runtime_provider(
                staging
            )
        )

        realizer, realizer_metadata = (
            _package_realizer(
                staging
                / REALIZER_ASSET,
                _sha256(
                    runtime
                ),
            )
        )

        _materialize_direct(
            staging,
            realizer_metadata,
        )

        runtime_files = {
            name: {
                "bytes":
                    len(value),

                "sha256":
                    hashlib.sha256(
                        value
                    ).hexdigest(),
            }
            for name, value in sorted(
                payloads.items()
            )
        }

        artifacts = {
            name:
                _record(
                    staging
                    / name
                )
            for name in (
                RUNTIME_ASSET,
                REALIZER_ASSET,
                "provider.json",
                "SHA256SUMS",
            )
        }

        manifest = {
            "schema":
                BOOTSTRAP_DEVELOPMENT_SCHEMA,

            "development_schema":
                DEPENDENCY_DEVELOPMENT_SCHEMA,

            "provider":
                DEVELOPMENT_PROVIDER,

            "kind":
                "treeforge-bootstrap-development-provider",

            "repository":
                _git_remote(),

            "channel":
                "development",

            "release_eligible":
                False,

            "release_contract_enforced":
                False,

            "retention_successful_runs":
                DEVELOPMENT_RETENTION,

            "run_id":
                run_id,

            "version":
                versions[
                    "bootstrap"
                ],

            "runtime_abi":
                versions[
                    "runtime_abi"
                ],

            "source_commit":
                _git_commit(),

            "source_dirty":
                _git_dirty(),

            "dependencies": {
                "framebuffer":
                    _dependency_record(
                        framebuffer.root,
                        framebuffer.version,
                    ),

                "menu":
                    _dependency_record(
                        menu.root,
                        menu.version,
                        boot_manager_version=(
                            menu.boot_manager_version
                        ),
                    ),
            },

            "runtime_files":
                runtime_files,

            "artifacts":
                artifacts,

            "runtime": {
                "name":
                    RUNTIME_ASSET,

                **artifacts[
                    RUNTIME_ASSET
                ],
            },

            "realizer": {
                "name":
                    REALIZER_ASSET,

                **artifacts[
                    REALIZER_ASSET
                ],
            },

            "executable":
                "treeforge-bootstrap",

            "metadata":
                str(
                    REALIZER_METADATA
                ),
        }

        _write_json(
            staging
            / "development-provider.json",
            manifest,
        )

        verify_development_provider(
            staging
        )

        staging.replace(
            final
        )

        try:
            _promote_current(
                final
            )
        except Exception:
            shutil.rmtree(
                final
            )
            raise

        _prune_runs()

        if LEGACY_DEVELOPMENT_DIR.exists():
            shutil.rmtree(
                LEGACY_DEVELOPMENT_DIR
            )

    except Exception:
        if staging.exists():
            shutil.rmtree(
                staging
            )

        raise

    print(
        f"RUN={final}"
    )

    print(
        f"CURRENT={DEVELOPMENT_CURRENT}"
    )

    print(
        f"RETAINED={DEVELOPMENT_RETENTION}"
    )

    print(
        "TREEFORGE_BOOTSTRAP_"
        "DEVELOPMENT_PROVIDER=PASS"
    )

    return final


# Version-specific hardware-accepted historical release promotion.
# The v1.0b1 frozen values in runtime.py remain authoritative for the
# original release. No runtime binary is modified or reconstructed here.
ACCEPTANCE_ROOT = ROOT / "release-acceptance"


def _verify_historical_acceptance(
    root: Path,
    manifest: dict[str, object],
) -> None:
    version = manifest.get("version")
    if not isinstance(version, str) or not version.startswith("v"):
        raise TreeForgeBootstrapDevelopmentProviderError(
            "historical release version invalid"
        )

    acceptance_path = ACCEPTANCE_ROOT / (version + ".json")
    if not acceptance_path.is_file():
        raise TreeForgeBootstrapDevelopmentProviderError(
            f"release candidate requires explicit accepted-runtime contract: {version}"
        )

    try:
        accepted = json.loads(acceptance_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise TreeForgeBootstrapDevelopmentProviderError(
            "historical release acceptance unreadable"
        ) from error

    required_fields = {
        "schema", "repository", "release_version", "runtime_abi",
        "accepted_run", "accepted_source_commit", "development_metadata_sha256",
        "runtime_files", "artifacts", "provider_components",
    }
    if not isinstance(accepted, dict) or set(accepted) != required_fields:
        raise TreeForgeBootstrapDevelopmentProviderError(
            "historical release acceptance schema mismatch"
        )

    expected_source = accepted["accepted_source_commit"]
    metadata = root / "development-provider.json"
    if (
        accepted["schema"] != "treeforge.bootstrap.accepted-release.v1"
        or accepted["repository"] != "TreeForgeAOSP/treeforge_bootstrap"
        or accepted["release_version"] != version
        or accepted["runtime_abi"] != manifest.get("runtime_abi")
        or accepted["accepted_run"] != root.name
        or accepted["accepted_run"] != manifest.get("run_id")
        or not isinstance(expected_source, str)
        or len(expected_source) != 40
        or any(c not in "0123456789abcdef" for c in expected_source)
        or expected_source != manifest.get("source_commit")
        or manifest.get("source_dirty") is not False
        or accepted["development_metadata_sha256"] != _sha256(metadata)
        or accepted["runtime_files"] != manifest.get("runtime_files")
        or accepted["artifacts"] != manifest.get("artifacts")
    ):
        raise TreeForgeBootstrapDevelopmentProviderError(
            "historical release identity differs from accepted provider"
        )

    provider = json.loads((root / "provider.json").read_text(encoding="utf-8"))
    if (
        provider.get("components") != accepted["provider_components"]
        or provider.get("payload") != accepted["runtime_files"]
    ):
        raise TreeForgeBootstrapDevelopmentProviderError(
            "historical release provider payload/components changed"
        )

    # The original source commit must be part of this checkout's history;
    # release tooling changes made afterward never rewrite that identity.
    ancestry = subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor",
         expected_source, _git_commit()],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
    )
    if ancestry.returncode != 0:
        raise TreeForgeBootstrapDevelopmentProviderError(
            "accepted source commit not ancestral to release HEAD"
        )

    previous_version = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{expected_source}:VERSION"],
        text=True, capture_output=True, check=False,
    )
    if (
        previous_version.returncode != 0
        or f"TREEFORGE_BOOTSTRAP_VERSION={version}" not in previous_version.stdout.splitlines()
        or f"TREEFORGE_RUNTIME_ABI_VERSION={manifest.get('runtime_abi')}"
           not in previous_version.stdout.splitlines()
        or _git_dirty()
    ):
        raise TreeForgeBootstrapDevelopmentProviderError(
            "accepted source revision/version or release worktree invalid"
        )

    print(f"HISTORICAL_ACCEPTED_RUN={root.name}")
    print(f"HISTORICAL_ACCEPTED_SOURCE={expected_source}")
    print("HISTORICAL_ACCEPTED_BYTES=PASS")
    print("RUNTIME_REBUILT=NO")


def _release_candidate(
) -> tuple[
    Path,
    dict[str, object],
]:
    root = (
        verify_development_provider()
    )

    manifest = _read_manifest(
        root
    )

    versions = _version_fields()

    if (
        manifest.get("version")
        != versions["bootstrap"]
        or manifest.get(
            "runtime_abi"
        )
        != versions["runtime_abi"]
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "release candidate VERSION "
                "identity changed"
            )
        )

    candidate_is_current_head = (
        manifest.get("source_dirty") is False
        and manifest.get("source_commit") == _git_commit()
    )
    if manifest.get("source_dirty") is not False or _git_dirty():
        raise TreeForgeBootstrapDevelopmentProviderError(
            "release candidate source must be clean"
        )

    dependencies = manifest.get(
        "dependencies"
    )

    if not isinstance(
        dependencies,
        dict,
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "release dependencies missing"
            )
        )

    for name, record in (
        dependencies.items()
    ):
        if not isinstance(
            record,
            dict,
        ):
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    f"invalid dependency: {name}"
                )
            )

        if (
            record.get("channel")
            == "development"
            and record.get(
                "source_dirty"
            )
            is not False
        ):
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "release dependency was "
                    f"built dirty: {name}"
                )
            )

    runtime_files = manifest.get(
        "runtime_files"
    )

    frozen = {
        "initramfs.cpio": {
            "bytes":
                FROZEN_RUNTIME_CPIO_BYTES,

            "sha256":
                FROZEN_RUNTIME_CPIO_SHA256,
        },

        "initramfs.lz4": {
            "bytes":
                FROZEN_RUNTIME_LZ4_BYTES,

            "sha256":
                FROZEN_RUNTIME_LZ4_SHA256,
        },

        "treeforge-menu": {
            "bytes":
                FROZEN_RUNTIME_MENU_BYTES,

            "sha256":
                FROZEN_RUNTIME_MENU_SHA256,
        },
    }

    if not candidate_is_current_head or runtime_files != frozen:
        # Exact accepted version/run/source/metadata/artifact/payload pins
        # replace neither the v1.0b1 freeze nor any verification routine.
        _verify_historical_acceptance(root, manifest)

    provider = json.loads(
        (
            root
            / "provider.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    components = provider.get(
        "components"
    )

    framebuffer = dependencies.get(
        "framebuffer"
    )

    menu = dependencies.get(
        "menu"
    )

    if (
        not isinstance(
            components,
            dict,
        )
        or not isinstance(
            framebuffer,
            dict,
        )
        or not isinstance(
            menu,
            dict,
        )
        or components.get(
            "bootstrap"
        )
        != manifest.get("version")
        or components.get(
            "runtime_abi"
        )
        != manifest.get(
            "runtime_abi"
        )
        or components.get(
            "framebuffer"
        )
        != framebuffer.get(
            "version"
        )
        or components.get(
            "boot_menu"
        )
        != menu.get(
            "version"
        )
        or components.get(
            "boot_manager"
        )
        != menu.get(
            "boot_manager_version"
        )
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "release component "
                "provenance mismatch"
            )
        )

    realizer_metadata = json.loads(
        (
            root
            / REALIZER_METADATA
        ).read_text(
            encoding="utf-8"
        )
    )

    if (
        realizer_metadata.get(
            "source_commit"
        )
        != manifest.get(
            "source_commit"
        )
        or realizer_metadata.get(
            "source_dirty"
        )
        is not False
        or not isinstance(
            realizer_metadata.get(
                "runtime_dependency"
            ),
            dict,
        )
        or realizer_metadata[
            "runtime_dependency"
        ].get(
            "sha256"
        )
        != manifest[
            "artifacts"
        ][
            RUNTIME_ASSET
        ][
            "sha256"
        ]
    ):
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "release realizer "
                "provenance mismatch"
            )
        )

    return root, manifest


def verify_release_candidate() -> tuple[Path, dict[str, object]]:
    """Read-only verification of the exact source/provenance/bytes to release."""
    root, manifest = _release_candidate()
    print("TREEFORGE_BOOTSTRAP_RELEASE_CANDIDATE=PASS")
    return root, manifest


def prepare_release(
    *,
    force: bool = False,
) -> Path:
    #
    # Release preparation promotes the accepted runtime and
    # realizer bytes. It never rebuilds either artifact.
    #
    current, manifest = (
        _release_candidate()
    )

    version = str(
        manifest["version"]
    )

    final = (
        RELEASE_ROOT
        / version
    )

    assets = (
        final
        / "assets"
    )

    if final.exists() and not force:
        raise (
            TreeForgeBootstrapDevelopmentProviderError(
                "release output already exists: "
                f"{final}; use --force"
            )
        )

    RELEASE_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    staging = (
        RELEASE_ROOT
        / (
            ".incoming-"
            + version
            + "-"
            + str(
                os.getpid()
            )
        )
    )

    if staging.exists():
        shutil.rmtree(
            staging
        )

    staging_assets = (
        staging
        / "assets"
    )

    staging_assets.mkdir(
        parents=True
    )

    promoted = (
        RUNTIME_ASSET,
        REALIZER_ASSET,
        "provider.json",
        "SHA256SUMS",
    )

    try:
        for name in promoted:
            source = (
                current
                / name
            )

            target = (
                staging_assets
                / name
            )

            shutil.copy2(
                source,
                target,
            )

            if (
                _sha256(source)
                != _sha256(target)
            ):
                raise (
                    TreeForgeBootstrapDevelopmentProviderError(
                        "release promotion "
                        f"changed bytes: {name}"
                    )
                )

        manager = (
            staging_assets
            / MANAGER_ASSET
        )

        manager.write_bytes(
            _manager_update_metadata(
                staging_assets
                / RUNTIME_ASSET,
                release=version,
            )
        )

        manager_metadata = json.loads(
            manager.read_text(
                encoding="utf-8"
            )
        )

        manager_runtime = (
            manager_metadata.get(
                "artifacts",
                {}
            ).get(
                "runtime",
                {}
            )
        )

        runtime = (
            staging_assets
            / RUNTIME_ASSET
        )

        if (
            manager_metadata.get(
                "release"
            )
            != version
            or manager_runtime.get(
                "filename"
            )
            != RUNTIME_ASSET
            or manager_runtime.get(
                "sha256"
            )
            != _sha256(
                runtime
            )
            or manager_runtime.get(
                "bytes"
            )
            != runtime.stat().st_size
        ):
            raise (
                TreeForgeBootstrapDevelopmentProviderError(
                    "release Manager manifest "
                    "identity mismatch"
                )
            )

        names = (
            *promoted,
            MANAGER_ASSET,
        )

        (
            staging_assets
            / "ASSET-SHA256SUMS"
        ).write_text(
            "".join(
                (
                    _sha256(
                        staging_assets
                        / name
                    )
                    + "  "
                    + name
                    + "\n"
                )
                for name in sorted(
                    names
                )
            ),
            encoding="utf-8",
        )

        if final.exists():
            shutil.rmtree(
                final
            )

        staging.replace(
            final
        )

    except Exception:
        if staging.exists():
            shutil.rmtree(
                staging
            )

        raise

    print(
        f"VERSION={version}"
    )

    print(
        f"DEVELOPMENT_RUN={current}"
    )

    print(
        f"RELEASE_ASSETS={assets}"
    )

    print(
        "RUNTIME_REBUILT=NO"
    )

    print(
        "REALIZER_REBUILT=NO"
    )

    print(
        "REBUILD_PERFORMED=NO"
    )

    print(
        "TREEFORGE_BOOTSTRAP_"
        "RELEASE_PREPARE=PASS"
    )

    return assets


__all__ = [
    "DEVELOPMENT_CURRENT",
    "DEVELOPMENT_RETENTION",
    "DEVELOPMENT_ROOT",
    "DEVELOPMENT_RUNS",
    "TreeForgeBootstrapDevelopmentProviderError",
    "package_development_provider",
    "prepare_release",
    "verify_development_provider",
    "verify_release_candidate",
]
