from __future__ import annotations

import hashlib
import io
import json
import lzma
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path


class TreeForgeBootstrapRealizerProviderError(
    RuntimeError
):
    pass


ROOT = Path(
    __file__
).resolve().parents[2]

PROVIDER_DIR = (
    ROOT
    / "out"
    / "tangorpro"
    / "provider"
)

RUNTIME_ASSET = (
    "treeforge-bootstrap-"
    "tangorpro-android15-runtime.tar.xz"
)

MANAGER_ASSET = (
    "treeforge-bootstrap-"
    "tangorpro-android15-"
    "runtime-update-manifest.json"
)

REALIZER_ASSET = (
    "treeforge-bootstrap-"
    "tangorpro-android15-realizer.tar.xz"
)

REALIZER_ROOT = (
    "treeforge-bootstrap-"
    "tangorpro-android15-realizer"
)

REALIZER_METADATA = (
    "metadata/realizer-provider.json"
)

PROVIDER_CONTRACT = (
    ROOT
    / "provider-contract.json"
)


def _sha256(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        while True:
            chunk = stream.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(
                chunk
            )

    return digest.hexdigest()


def _version_values() -> dict[str, str]:
    result: dict[str, str] = {}

    for raw in (
        ROOT
        / "VERSION"
    ).read_text(
        encoding="utf-8"
    ).splitlines():
        raw = raw.strip()

        if (
            not raw
            or raw.startswith("#")
            or "=" not in raw
        ):
            continue

        key, value = raw.split(
            "=",
            1,
        )

        result[
            key.strip()
        ] = value.strip()

    return result


def _git_commit() -> str:
    return subprocess.check_output(
        [
            "git",
            "-C",
            str(ROOT),
            "rev-parse",
            "HEAD",
        ],
        text=True,
    ).strip()


def _git_dirty() -> bool:
    output = subprocess.check_output(
        [
            "git",
            "-C",
            str(ROOT),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        text=True,
    )

    return bool(
        output.strip()
    )


def _payload_paths() -> list[Path]:
    fixed = [
        Path(".gitignore"),
        Path("README.md"),
        Path("VERSION"),
        Path(
            "profiles/"
            "treeforge-default.json"
        ),
        Path(
            "provider-contract.json"
        ),
        Path("pyproject.toml"),
        Path(
            "runtime/"
            "initramfs/"
            "root/"
            "etc/"
            "treeforge-bootstrap-release"
        ),
        Path(
            "runtime/"
            "initramfs/"
            "src/"
            "adb_service.c"
        ),
        Path(
            "runtime/"
            "initramfs/"
            "src/"
            "diagnostic_init.c"
        ),
        Path("treeforge-bootstrap"),
    ]

    python_sources = sorted(
        path.relative_to(
            ROOT
        )
        for path in (
            ROOT
            / "src"
            / "treeforge_bootstrap"
        ).glob("*.py")
    )

    result = (
        fixed
        + python_sources
    )

    missing = [
        str(path)
        for path in result
        if not (
            ROOT
            / path
        ).is_file()
    ]

    if missing:
        raise (
            TreeForgeBootstrapRealizerProviderError(
                "realizer payload files missing: "
                + ", ".join(
                    missing
                )
            )
        )

    return result


def _load_release_inputs() -> tuple[
    Path,
    Path,
    dict[str, object],
    dict[str, object],
]:
    runtime = (
        PROVIDER_DIR
        / RUNTIME_ASSET
    )

    manager = (
        PROVIDER_DIR
        / MANAGER_ASSET
    )

    provider_json = (
        PROVIDER_DIR
        / "provider.json"
    )

    for path in (
        runtime,
        manager,
        provider_json,
        PROVIDER_CONTRACT,
    ):
        if not path.is_file():
            raise (
                TreeForgeBootstrapRealizerProviderError(
                    "required provider input "
                    f"is missing: {path}"
                )
            )

    provider = json.loads(
        provider_json.read_text(
            encoding="utf-8"
        )
    )

    contract = json.loads(
        PROVIDER_CONTRACT.read_text(
            encoding="utf-8"
        )
    )

    return (
        runtime,
        manager,
        provider,
        contract,
    )


def _validate_contract() -> None:
    (
        runtime,
        manager,
        provider,
        contract,
    ) = _load_release_inputs()

    runtime_sha = _sha256(
        runtime
    )

    manager_sha = _sha256(
        manager
    )

    provider_sha = _sha256(
        PROVIDER_DIR
        / "provider.json"
    )

    sums_sha = _sha256(
        PROVIDER_DIR
        / "SHA256SUMS"
    )

    versions = (
        _version_values()
    )

    bootstrap_version = versions.get(
        "TREEFORGE_BOOTSTRAP_VERSION"
    )

    expected_status = (
        f"{bootstrap_version}-"
        "runtime-realizer-release-contract"
    )

    checks = [
        (
            contract[
                "artifact"
            ].get("bytes"),
            runtime.stat().st_size,
            "artifact bytes",
        ),
        (
            contract[
                "artifact"
            ].get("sha256"),
            runtime_sha,
            "artifact SHA256",
        ),
        (
            contract[
                "artifact"
            ].get(
                "metadata_sha256"
            ),
            provider_sha,
            "provider metadata SHA256",
        ),
        (
            contract[
                "artifact"
            ].get(
                "sha256sums_sha256"
            ),
            sums_sha,
            "runtime SHA256SUMS SHA256",
        ),
        (
            contract[
                "manager_update_manifest"
            ].get("sha256"),
            manager_sha,
            "Manager manifest SHA256",
        ),
        (
            contract[
                "realizer_artifact"
            ][
                "runtime_dependency"
            ].get("sha256"),
            runtime_sha,
            "realizer runtime dependency",
        ),
        (
            contract[
                "reproduction"
            ].get(
                "provider_archive_sha256"
            ),
            runtime_sha,
            "reproduction provider SHA256",
        ),
        (
            contract[
                "runtime"
            ].get("payload"),
            provider.get("payload"),
            "runtime payload",
        ),
        (
            contract.get("status"),
            expected_status,
            "contract status",
        ),
    ]

    for actual, expected, name in checks:
        if actual != expected:
            raise (
                TreeForgeBootstrapRealizerProviderError(
                    f"{name} mismatch: "
                    f"{actual!r} != "
                    f"{expected!r}"
                )
            )


def _write_json(
    path: Path,
    value: object,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _copy_payload(
    payload_root: Path,
) -> None:
    for relative in (
        _payload_paths()
    ):
        source = (
            ROOT
            / relative
        )

        target = (
            payload_root
            / relative
        )

        target.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        shutil.copy2(
            source,
            target,
        )


def _realizer_metadata(
    runtime_sha: str,
) -> dict[str, object]:
    versions = (
        _version_values()
    )

    return {
        "schema": 1,
        "provider":
            "treeforge-bootstrap-host-realizer",
        "provider_type":
            "host-realizer",
        "variant":
            "tangorpro-android15",
        "device":
            "tangorpro",
        "android_release":
            "15",
        "architecture":
            "arm64",
        "entrypoint":
            "payload/treeforge-bootstrap",
        "repository":
            "TreeForgeAOSP/treeforge_bootstrap",
        "version":
            versions[
                "TREEFORGE_BOOTSTRAP_VERSION"
            ],
        "source_commit":
            _git_commit(),
        "source_dirty":
            _git_dirty(),
        "runtime_dependency": {
            "asset":
                RUNTIME_ASSET,
            "provider":
                "treeforge-bootstrap-runtime",
            "required":
                True,
            "sha256":
                runtime_sha,
        },
        "consumer_inputs": {
            "avb_keyset":
                True,
            "device_family":
                True,
        },
        "forbidden_bundled_inputs": {
            "adb_build_provider":
                True,
            "aosp_checkout_test_key":
                True,
            "google_canonical_seed":
                True,
            "private_avb_keys":
                True,
        },
        "verification": {
            "frozen_runtime":
                True,
            "realize_family":
                True,
        },
    }


def _write_internal_sums(
    archive_root: Path,
) -> None:
    sums = (
        archive_root
        / "SHA256SUMS"
    )

    records: list[str] = []

    for path in sorted(
        item
        for item in archive_root.rglob("*")
        if item.is_file()
        and item != sums
    ):
        relative = (
            path.relative_to(
                archive_root
            ).as_posix()
        )

        records.append(
            f"{_sha256(path)}  "
            f"{relative}"
        )

    sums.write_text(
        "\n".join(
            records
        )
        + "\n",
        encoding="utf-8",
    )


def _normalized_tar_bytes(
    archive_root: Path,
) -> bytes:
    buffer = io.BytesIO()

    with tarfile.open(
        fileobj=buffer,
        mode="w",
        format=tarfile.PAX_FORMAT,
    ) as archive:
        entries = [
            archive_root,
            *sorted(
                archive_root.rglob("*"),
                key=lambda path:
                    path.relative_to(
                        archive_root.parent
                    ).as_posix(),
            ),
        ]

        for path in entries:
            arcname = (
                path.relative_to(
                    archive_root.parent
                ).as_posix()
            )

            info = tarfile.TarInfo(
                arcname
            )

            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0

            if path.is_dir():
                info.type = (
                    tarfile.DIRTYPE
                )

                info.mode = 0o755
                info.size = 0

                archive.addfile(
                    info
                )

                continue

            if not path.is_file():
                raise (
                    TreeForgeBootstrapRealizerProviderError(
                        "unsupported payload "
                        f"entry: {path}"
                    )
                )

            source_mode = (
                path.stat().st_mode
                & 0o111
            )

            info.mode = (
                0o755
                if source_mode
                else 0o644
            )

            data = (
                path.read_bytes()
            )

            info.size = len(
                data
            )

            archive.addfile(
                info,
                io.BytesIO(
                    data
                ),
            )

    return buffer.getvalue()


def package_realizer_provider() -> Path:
    _validate_contract()

    runtime = (
        PROVIDER_DIR
        / RUNTIME_ASSET
    )

    runtime_sha = _sha256(
        runtime
    )

    output = (
        PROVIDER_DIR
        / REALIZER_ASSET
    )

    with tempfile.TemporaryDirectory(
        prefix=(
            "treeforge-bootstrap-"
            "realizer-"
        )
    ) as temporary:
        temporary_root = Path(
            temporary
        )

        archive_root = (
            temporary_root
            / REALIZER_ROOT
        )

        payload_root = (
            archive_root
            / "payload"
        )

        metadata_path = (
            archive_root
            / REALIZER_METADATA
        )

        archive_root.mkdir(
            parents=True,
        )

        _copy_payload(
            payload_root
        )

        _write_json(
            metadata_path,
            _realizer_metadata(
                runtime_sha
            ),
        )

        _write_internal_sums(
            archive_root
        )

        tar_bytes = (
            _normalized_tar_bytes(
                archive_root
            )
        )

        compressed = lzma.compress(
            tar_bytes,
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

    print(
        "TreeForge Bootstrap Host Realizer"
    )
    print(
        "=================================="
    )
    print()
    print(
        f"Archive:     {output}"
    )
    print(
        f"Archive bytes: "
        f"{output.stat().st_size}"
    )
    print(
        f"Archive SHA: {_sha256(output)}"
    )
    print()
    print(
        "TREEFORGE_BOOTSTRAP_REALIZER_PACKAGE=PASS"
    )

    return output


def _safe_extract(
    archive_path: Path,
    destination: Path,
) -> Path:
    with tarfile.open(
        archive_path,
        mode="r:xz",
    ) as archive:
        members = (
            archive.getmembers()
        )

        for member in members:
            name = (
                Path(
                    member.name
                )
            )

            if (
                name.is_absolute()
                or ".." in name.parts
                or member.issym()
                or member.islnk()
            ):
                raise (
                    TreeForgeBootstrapRealizerProviderError(
                        "unsafe realizer "
                        f"archive member: "
                        f"{member.name!r}"
                    )
                )

        archive.extractall(
            destination,
            filter="data",
        )

    root = (
        destination
        / REALIZER_ROOT
    )

    if not root.is_dir():
        raise (
            TreeForgeBootstrapRealizerProviderError(
                "realizer archive root missing"
            )
        )

    return root


def verify_realizer_provider() -> None:
    _validate_contract()

    archive_path = (
        PROVIDER_DIR
        / REALIZER_ASSET
    )

    if not archive_path.is_file():
        raise (
            TreeForgeBootstrapRealizerProviderError(
                "realizer provider "
                "archive is missing"
            )
        )

    with tempfile.TemporaryDirectory(
        prefix=(
            "treeforge-bootstrap-"
            "realizer-verify-"
        )
    ) as temporary:
        extracted = (
            _safe_extract(
                archive_path,
                Path(
                    temporary
                ),
            )
        )

        sums_path = (
            extracted
            / "SHA256SUMS"
        )

        if not sums_path.is_file():
            raise (
                TreeForgeBootstrapRealizerProviderError(
                    "realizer SHA256SUMS "
                    "is missing"
                )
            )

        for raw in sums_path.read_text(
            encoding="utf-8"
        ).splitlines():
            digest, name = (
                raw.split(
                    None,
                    1,
                )
            )

            name = name.strip()

            target = (
                extracted
                / name
            )

            if (
                not target.is_file()
                or _sha256(
                    target
                )
                != digest
            ):
                raise (
                    TreeForgeBootstrapRealizerProviderError(
                        "realizer internal "
                        f"checksum mismatch: "
                        f"{name}"
                    )
                )

        metadata = json.loads(
            (
                extracted
                / REALIZER_METADATA
            ).read_text(
                encoding="utf-8"
            )
        )

        versions = (
            _version_values()
        )

        expected = {
            "schema": 1,
            "provider":
                "treeforge-bootstrap-host-realizer",
            "provider_type":
                "host-realizer",
            "variant":
                "tangorpro-android15",
            "device":
                "tangorpro",
            "android_release":
                "15",
            "version":
                versions[
                    "TREEFORGE_BOOTSTRAP_VERSION"
                ],
            "source_commit":
                _git_commit(),
        }

        for key, value in (
            expected.items()
        ):
            if (
                metadata.get(
                    key
                )
                != value
            ):
                raise (
                    TreeForgeBootstrapRealizerProviderError(
                        "realizer metadata "
                        f"mismatch for {key}: "
                        f"{metadata.get(key)!r} "
                        f"!= {value!r}"
                    )
                )

        if metadata.get(
            "source_dirty"
        ) != _git_dirty():
            raise (
                TreeForgeBootstrapRealizerProviderError(
                    "realizer source_dirty "
                    "state mismatch"
                )
            )

        dependency = metadata.get(
            "runtime_dependency"
        )

        if not isinstance(
            dependency,
            dict,
        ):
            raise (
                TreeForgeBootstrapRealizerProviderError(
                    "realizer runtime "
                    "dependency missing"
                )
            )

        runtime = (
            PROVIDER_DIR
            / RUNTIME_ASSET
        )

        if dependency.get(
            "sha256"
        ) != _sha256(
            runtime
        ):
            raise (
                TreeForgeBootstrapRealizerProviderError(
                    "realizer runtime "
                    "dependency SHA mismatch"
                )
            )

        embedded_contract = (
            extracted
            / "payload"
            / "provider-contract.json"
        )

        if (
            embedded_contract.read_bytes()
            != PROVIDER_CONTRACT.read_bytes()
        ):
            raise (
                TreeForgeBootstrapRealizerProviderError(
                    "embedded provider "
                    "contract differs from "
                    "tracked source"
                )
            )

        for relative in (
            _payload_paths()
        ):
            embedded = (
                extracted
                / "payload"
                / relative
            )

            current = (
                ROOT
                / relative
            )

            if (
                not embedded.is_file()
                or embedded.read_bytes()
                != current.read_bytes()
            ):
                raise (
                    TreeForgeBootstrapRealizerProviderError(
                        "realizer payload "
                        "source mismatch: "
                        f"{relative}"
                    )
                )

    print(
        "REALIZER_PROVIDER_SHA256="
        + _sha256(
            archive_path
        )
    )

    print(
        "TREEFORGE_BOOTSTRAP_REALIZER_VERIFY=PASS"
    )


__all__ = [
    "TreeForgeBootstrapRealizerProviderError",
    "package_realizer_provider",
    "verify_realizer_provider",
]
