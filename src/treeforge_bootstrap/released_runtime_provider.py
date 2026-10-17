from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request


class TreeForgeReleasedRuntimeProviderError(RuntimeError):
    pass


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROVIDER_CONTRACT = REPOSITORY_ROOT / "provider-contract.json"
CACHE_ROOT = (
    Path.home()
    / ".cache"
    / "treeforge"
    / "providers"
    / "treeforge-bootstrap-runtime"
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


def _contract() -> dict[str, object]:
    try:
        data = json.loads(
            PROVIDER_CONTRACT.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise TreeForgeReleasedRuntimeProviderError(
            "unable to read Bootstrap provider contract"
        ) from error

    artifact = data.get("artifact")
    runtime = data.get("runtime")

    if not isinstance(artifact, dict) or not isinstance(runtime, dict):
        raise TreeForgeReleasedRuntimeProviderError(
            "Bootstrap provider contract is incomplete"
        )

    payload = runtime.get("payload")

    if not isinstance(payload, dict):
        raise TreeForgeReleasedRuntimeProviderError(
            "Bootstrap runtime payload contract is missing"
        )

    cpio = payload.get("initramfs.cpio")

    if not isinstance(cpio, dict):
        raise TreeForgeReleasedRuntimeProviderError(
            "Bootstrap runtime CPIO contract is missing"
        )

    required = {
        "release": runtime.get("canonical_seed_release"),
        "asset": artifact.get("name"),
        "archive_sha256": artifact.get("sha256"),
        "archive_bytes": artifact.get("bytes"),
        "cpio_sha256": cpio.get("sha256"),
        "cpio_bytes": cpio.get("bytes"),
    }

    release = required["release"]

    if (
        not isinstance(release, str)
        or re.fullmatch(
            r"v[0-9]+\.[0-9]+b[0-9]+",
            release,
        )
        is None
    ):
        raise TreeForgeReleasedRuntimeProviderError(
            "Bootstrap canonical seed release is invalid"
        )

    if not isinstance(required["asset"], str) or not required["asset"]:
        raise TreeForgeReleasedRuntimeProviderError(
            "Bootstrap runtime provider asset name is invalid"
        )

    for name in ("archive_sha256", "cpio_sha256"):
        value = required[name]

        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise TreeForgeReleasedRuntimeProviderError(
                f"Bootstrap runtime provider {name} is invalid"
            )

    for name in ("archive_bytes", "cpio_bytes"):
        value = required[name]

        if not isinstance(value, int) or value <= 0:
            raise TreeForgeReleasedRuntimeProviderError(
                f"Bootstrap runtime provider {name} is invalid"
            )

    return required


def _verify_file(path: Path, *, size: int, sha256: str, label: str) -> None:
    if not path.is_file():
        raise TreeForgeReleasedRuntimeProviderError(
            f"{label} is missing: {path}"
        )

    actual_size = path.stat().st_size

    if actual_size != size:
        raise TreeForgeReleasedRuntimeProviderError(
            f"{label} size changed: {actual_size} != {size}"
        )

    actual_sha256 = _sha256(path)

    if actual_sha256 != sha256:
        raise TreeForgeReleasedRuntimeProviderError(
            f"{label} identity changed: {actual_sha256} != {sha256}"
        )


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "TreeForge-Bootstrap/1",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            with destination.open("wb") as output:
                shutil.copyfileobj(
                    response,
                    output,
                    length=1024 * 1024,
                )
    except (OSError, urllib.error.URLError) as error:
        raise TreeForgeReleasedRuntimeProviderError(
            "unable to download released Bootstrap runtime provider"
        ) from error


def ensure_released_runtime_archive() -> Path:
    contract = _contract()
    release = str(contract["release"])
    root = CACHE_ROOT / release
    archive = root / str(contract["asset"])

    if archive.is_file():
        try:
            _verify_file(
                archive,
                size=int(contract["archive_bytes"]),
                sha256=str(contract["archive_sha256"]),
                label="released Bootstrap runtime provider",
            )
            print(f"[canonical-provider] CACHE: {archive}")
            print("[canonical-provider] ARCHIVE VERIFY: PASS")
            return archive
        except TreeForgeReleasedRuntimeProviderError:
            archive.unlink(missing_ok=True)

    root.mkdir(parents=True, exist_ok=True)

    url = (
        "https://github.com/TreeForgeAOSP/"
        "treeforge_bootstrap/releases/download/"
        + release
        + "/"
        + str(contract["asset"])
    )

    print(
        "[canonical-provider] DOWNLOAD: "
        + f"TreeForge Bootstrap {release} runtime provider"
    )

    with tempfile.NamedTemporaryFile(
        prefix=".runtime-provider-",
        suffix=".partial",
        dir=root,
        delete=False,
    ) as handle:
        temporary = Path(handle.name)

    try:
        _download(url, temporary)
        _verify_file(
            temporary,
            size=int(contract["archive_bytes"]),
            sha256=str(contract["archive_sha256"]),
            label="downloaded Bootstrap runtime provider",
        )
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)

    print("[canonical-provider] ARCHIVE VERIFY: PASS")
    return archive


def ensure_released_runtime_cpio() -> Path:
    contract = _contract()
    release = str(contract["release"])
    root = CACHE_ROOT / release
    cpio = root / "initramfs.cpio"

    if cpio.is_file():
        try:
            _verify_file(
                cpio,
                size=int(contract["cpio_bytes"]),
                sha256=str(contract["cpio_sha256"]),
                label="released Bootstrap runtime CPIO",
            )
            print(f"[canonical-provider] CPIO CACHE: {cpio}")
            print("[canonical-provider] CPIO VERIFY: PASS")
            return cpio
        except TreeForgeReleasedRuntimeProviderError:
            cpio.unlink(missing_ok=True)

    archive = ensure_released_runtime_archive()
    expected_member = (
        "treeforge-bootstrap-tangorpro-android15-runtime/"
        "payload/initramfs.cpio"
    )

    try:
        with tarfile.open(archive, mode="r:xz") as bundle:
            matches = [
                member
                for member in bundle.getmembers()
                if member.name == expected_member
            ]

            if len(matches) != 1:
                raise TreeForgeReleasedRuntimeProviderError(
                    "released Bootstrap runtime provider has no unique CPIO payload"
                )

            member = matches[0]

            if not member.isfile() or member.issym() or member.islnk():
                raise TreeForgeReleasedRuntimeProviderError(
                    "released Bootstrap runtime CPIO member is not a regular file"
                )

            source = bundle.extractfile(member)

            if source is None:
                raise TreeForgeReleasedRuntimeProviderError(
                    "unable to read released Bootstrap runtime CPIO"
                )

            root.mkdir(parents=True, exist_ok=True)

            with tempfile.NamedTemporaryFile(
                prefix=".initramfs-",
                suffix=".partial",
                dir=root,
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                shutil.copyfileobj(
                    source,
                    handle,
                    length=1024 * 1024,
                )
    except (OSError, tarfile.TarError) as error:
        raise TreeForgeReleasedRuntimeProviderError(
            "unable to extract released Bootstrap runtime provider"
        ) from error

    try:
        _verify_file(
            temporary,
            size=int(contract["cpio_bytes"]),
            sha256=str(contract["cpio_sha256"]),
            label="released Bootstrap runtime CPIO",
        )
        temporary.replace(cpio)
    finally:
        temporary.unlink(missing_ok=True)

    print(f"[canonical-provider] CPIO: {cpio}")
    print("[canonical-provider] CPIO VERIFY: PASS")
    return cpio


__all__ = [
    "TreeForgeReleasedRuntimeProviderError",
    "ensure_released_runtime_archive",
    "ensure_released_runtime_cpio",
]
