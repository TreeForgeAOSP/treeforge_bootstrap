from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from .kernel_provider import (
    KERNEL_RELEASE_TAG,
    TreeForgeBootstrapKernelProviderError,
    ensure_kernel_reconstruction_provider,
)


class TreeForgeKernelFamilyError(RuntimeError):
    pass


CACHE_ROOT = (
    Path.home()
    / ".cache"
    / "treeforge"
    / "bootstrap-kernel"
    / KERNEL_RELEASE_TAG
    / "reconstruction"
)

PAYLOAD_ROOT = (
    CACHE_ROOT
    / "payload"
)


CARRIERS = (
    "vendor_kernel_boot",
    "vendor_dlkm",
    "system_dlkm",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for block in iter(
            lambda: stream.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def _provider_archive_root(
    extracted: Path,
) -> Path:
    candidates = [
        entry
        for entry in extracted.iterdir()
        if entry.is_dir()
    ]

    if len(candidates) != 1:
        raise TreeForgeKernelFamilyError(
            "kernel provider archive must contain "
            "one top-level directory"
        )

    return candidates[0]


def _record_path(record: dict) -> str:
    value = record.get("path")

    if not isinstance(value, str) or not value:
        raise TreeForgeKernelFamilyError(
            "kernel provider file record has no path"
        )

    return value


def _record_sha256(record: dict) -> str:
    value = record.get("sha256")

    if (
        not isinstance(value, str)
        or len(value) != 64
    ):
        raise TreeForgeKernelFamilyError(
            "kernel provider file record has no SHA-256"
        )

    return value.lower()


def _resolve_record(
    carrier: str,
    carrier_root: Path,
    relative: str,
) -> Path:
    archive_prefix = (
        f"payload/{carrier}/"
    )

    normalized = relative

    if normalized.startswith(
        archive_prefix
    ):
        normalized = normalized[
            len(archive_prefix):
        ]

    candidates = [
        carrier_root
        / normalized,
    ]

    for candidate in candidates:
        if (
            candidate.is_file()
            or candidate.is_symlink()
        ):
            return candidate

    raise TreeForgeKernelFamilyError(
        "kernel provider payload file missing: "
        f"{relative}"
    )


def _verify_carrier(
    carrier: str,
    root: Path,
    metadata: dict,
) -> None:
    record = (
        metadata["carriers"][carrier]
    )

    files = record.get("files")

    if not isinstance(files, list):
        raise TreeForgeKernelFamilyError(
            f"{carrier} provider file list missing"
        )

    seen = set()

    for item in files:
        if not isinstance(item, dict):
            raise TreeForgeKernelFamilyError(
                f"{carrier} provider file record invalid"
            )

        relative = _record_path(item)

        if relative in seen:
            raise TreeForgeKernelFamilyError(
                f"{carrier} duplicate provider path: "
                f"{relative}"
            )

        seen.add(relative)

        path = _resolve_record(
            carrier,
            root,
            relative,
        )

        if path.is_symlink():
            continue

        expected = _record_sha256(
            item
        )

        actual = _sha256(
            path
        )

        if actual != expected:
            raise TreeForgeKernelFamilyError(
                f"{carrier} provider SHA mismatch: "
                f"{relative}"
            )

    module_count = sum(
        1
        for path in root.rglob("*.ko")
        if path.is_file()
    )

    expected_modules = record.get(
        "module_count"
    )

    if module_count != expected_modules:
        raise TreeForgeKernelFamilyError(
            f"{carrier} module count changed: "
            f"{module_count} != {expected_modules}"
        )


def _verify_materialized(
    root: Path,
    metadata: dict,
) -> None:
    if not root.is_dir():
        raise TreeForgeKernelFamilyError(
            "kernel reconstruction payload missing"
        )

    for carrier in CARRIERS:
        carrier_root = (
            root
            / carrier
        )

        if not carrier_root.is_dir():
            raise TreeForgeKernelFamilyError(
                f"kernel carrier payload missing: "
                f"{carrier}"
            )

        _verify_carrier(
            carrier,
            carrier_root,
            metadata,
        )


def ensure_kernel_family_payload(
) -> dict[str, object]:
    provider = (
        ensure_kernel_reconstruction_provider()
    )

    metadata = provider["metadata"]

    try:
        _verify_materialized(
            PAYLOAD_ROOT,
            metadata,
        )

        return {
            **provider,
            "payload_root":
                PAYLOAD_ROOT,
        }

    except TreeForgeKernelFamilyError:
        pass

    if CACHE_ROOT.exists():
        shutil.rmtree(
            CACHE_ROOT
        )

    CACHE_ROOT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.TemporaryDirectory(
        prefix=".kernel-family-",
        dir=CACHE_ROOT.parent,
    ) as raw:
        temporary = Path(raw)

        extracted = (
            temporary
            / "extract"
        )

        extracted.mkdir()

        archive = provider["archive"]

        result = subprocess.run(
            [
                "tar",
                "--use-compress-program=unzstd",
                "-xf",
                str(archive),
                "-C",
                str(extracted),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        if result.returncode:
            raise TreeForgeKernelFamilyError(
                "unable to extract kernel provider: "
                + result.stderr[-2000:]
            )

        archive_root = (
            _provider_archive_root(
                extracted
            )
        )

        source_payload = (
            archive_root
            / "payload"
        )

        if not source_payload.is_dir():
            raise TreeForgeKernelFamilyError(
                "kernel provider payload directory missing"
            )

        incoming = (
            temporary
            / "reconstruction"
        )

        incoming.mkdir()

        shutil.copytree(
            source_payload,
            incoming / "payload",
        )

        shutil.copy2(
            provider["manifest"],
            incoming / "module-provider.json",
        )

        _verify_materialized(
            incoming / "payload",
            metadata,
        )

        incoming.replace(
            CACHE_ROOT
        )

    _verify_materialized(
        PAYLOAD_ROOT,
        metadata,
    )

    return {
        **provider,
        "payload_root":
            PAYLOAD_ROOT,
    }
