from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import urllib.error
import urllib.parse
import urllib.request

from dataclasses import dataclass
from pathlib import Path

from .paths import (
    PROVIDERS,
    REPOSITORY_ROOT,
)


class ExternalProviderError(
    RuntimeError
):
    pass


CONTRACT_PATH = (
    REPOSITORY_ROOT
    / "provider-contract.json"
)

CACHE_ROOT = (
    Path.home()
    / ".cache"
    / "treeforge"
    / "bootstrap-providers"
)


@dataclass(frozen=True)
class ProviderLayout:
    destination: Path
    archive_payload: Path
    identity_relative: Path


LAYOUTS = {
    "treeforge-bootstrap-adbd":
        ProviderLayout(
            destination=(
                PROVIDERS
                / "external"
                / "treeforge-bootstrap-adbd"
                / "android-15.0.0_r36-arm64"
                / "rootfs"
            ),
            archive_payload=Path(
                "payload/rootfs"
            ),
            identity_relative=Path(
                "system/bin/"
                "treeforge-bootstrap-adbd"
            ),
        ),

    "kexec-tools":
        ProviderLayout(
            destination=(
                PROVIDERS
                / "external"
                / "kexec-tools"
                / "android-15.0.0_r36-linux-arm64"
            ),
            archive_payload=Path("."),
            identity_relative=Path(
                "payload/bin/kexec"
            ),
        ),
}


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


def _contract() -> dict:
    if not CONTRACT_PATH.is_file():
        raise ExternalProviderError(
            "Bootstrap provider contract "
            f"is missing: {CONTRACT_PATH}"
        )

    try:
        data = json.loads(
            CONTRACT_PATH.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise ExternalProviderError(
            "unable to read Bootstrap "
            "provider contract"
        ) from error

    providers = data.get(
        "providers"
    )

    if not isinstance(
        providers,
        dict,
    ):
        raise ExternalProviderError(
            "Bootstrap provider contract "
            "has no providers object"
        )

    return data


def declared_provider_names() -> tuple[str, ...]:
    providers = _contract()[
        "providers"
    ]

    return tuple(
        sorted(
            str(name)
            for name in providers
        )
    )


def _provider_record(
    name: str,
) -> dict[str, str]:
    providers = _contract()[
        "providers"
    ]

    if name not in providers:
        raise ExternalProviderError(
            f"Bootstrap runtime requires "
            f"{name}, but provider-contract.json "
            "does not declare it"
        )

    raw = providers[name]

    if not isinstance(
        raw,
        dict,
    ):
        raise ExternalProviderError(
            f"{name} provider record "
            "is invalid"
        )

    required = (
        "repository",
        "release",
        "asset",
        "archive_sha256",
        "runtime_sha256",
    )

    result: dict[str, str] = {}

    for field in required:
        value = raw.get(
            field
        )

        if (
            not isinstance(
                value,
                str,
            )
            or not value.strip()
        ):
            raise ExternalProviderError(
                f"{name} provider has "
                f"invalid {field}"
            )

        result[field] = (
            value.strip()
        )

    if (
        result["repository"]
        != "TreeForgeAOSP/treeforge_toolchain"
    ):
        raise ExternalProviderError(
            f"{name} provider repository "
            "is outside TreeForge Toolchain: "
            + result["repository"]
        )

    for field in (
        "archive_sha256",
        "runtime_sha256",
    ):
        if not re.fullmatch(
            r"[0-9a-f]{64}",
            result[field],
        ):
            raise ExternalProviderError(
                f"{name} provider has "
                f"invalid {field}"
            )

    if not result["asset"].endswith(
        ".tar.xz"
    ):
        raise ExternalProviderError(
            f"{name} provider asset "
            "must be .tar.xz"
        )

    return result


def _identity_path(
    name: str,
    root: Path,
) -> Path:
    return (
        root
        / LAYOUTS[name]
        .identity_relative
    )


def _verify_runtime(
    name: str,
    root: Path,
    expected: str,
) -> bool:
    identity = _identity_path(
        name,
        root,
    )

    return (
        identity.is_file()
        and _sha256(identity)
        == expected
    )


def _download(
    name: str,
    record: dict[str, str],
) -> Path:
    expected = (
        record[
            "archive_sha256"
        ]
    )

    asset = record["asset"]

    archive = (
        CACHE_ROOT
        / name
        / expected
        / asset
    )

    archive.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if archive.is_file():
        actual = _sha256(
            archive
        )

        if actual == expected:
            print(
                f"[provider:{name}] "
                "CACHE VERIFY: PASS"
            )
            print(
                f"[provider:{name}] "
                f"CACHE: {archive}"
            )

            return archive

        print(
            f"[provider:{name}] "
            "CACHE INVALID: removing"
        )

        archive.unlink()

    release = urllib.parse.quote(
        record["release"],
        safe="/",
    )

    asset_component = (
        urllib.parse.quote(
            asset,
            safe="",
        )
    )

    url = (
        "https://github.com/"
        + record["repository"]
        + "/releases/download/"
        + release
        + "/"
        + asset_component
    )

    partial = archive.with_name(
        archive.name
        + ".part"
    )

    partial.unlink(
        missing_ok=True
    )

    print(
        f"[provider:{name}] "
        "RESOLVE: "
        f"{record['release']}"
    )

    print(
        f"[provider:{name}] "
        f"DOWNLOAD: {url}"
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent":
                "TreeForge-Bootstrap",
        },
    )

    try:
        response = (
            urllib.request.urlopen(
                request,
                timeout=30,
            )
        )
    except urllib.error.URLError as error:
        raise ExternalProviderError(
            f"unable to download "
            f"{name}: {error}"
        ) from error

    downloaded = 0
    report_at = 1024 * 1024

    size_header = (
        response.headers.get(
            "Content-Length"
        )
    )

    try:
        total = (
            int(size_header)
            if size_header
            else None
        )
    except ValueError:
        total = None

    try:
        with (
            response,
            partial.open("wb")
            as stream,
        ):
            while True:
                block = response.read(
                    1024 * 1024
                )

                if not block:
                    break

                stream.write(
                    block
                )

                downloaded += len(
                    block
                )

                if (
                    downloaded
                    >= report_at
                    or (
                        total is not None
                        and downloaded
                        >= total
                    )
                ):
                    if total:
                        print(
                            f"[provider:{name}] "
                            "DOWNLOAD: "
                            f"{downloaded}/"
                            f"{total} bytes"
                        )
                    else:
                        print(
                            f"[provider:{name}] "
                            "DOWNLOAD: "
                            f"{downloaded} bytes"
                        )

                    report_at = (
                        downloaded
                        + 1024 * 1024
                    )

            stream.flush()

            os.fsync(
                stream.fileno()
            )

    except BaseException:
        partial.unlink(
            missing_ok=True
        )

        raise

    actual = _sha256(
        partial
    )

    print(
        f"[provider:{name}] "
        f"ARCHIVE SHA256: {actual}"
    )

    if actual != expected:
        partial.unlink(
            missing_ok=True
        )

        raise ExternalProviderError(
            f"{name} archive identity "
            f"mismatch: {actual}; "
            f"expected {expected}"
        )

    partial.replace(
        archive
    )

    print(
        f"[provider:{name}] "
        "ARCHIVE VERIFY: PASS"
    )

    return archive


def _extract_payload(
    name: str,
    archive: Path,
    record: dict[str, str],
    extraction: Path,
) -> Path:
    extraction.mkdir(
        parents=True,
        exist_ok=False,
    )

    print(
        f"[provider:{name}] "
        "EXTRACT"
    )

    try:
        with tarfile.open(
            archive,
            mode="r:xz",
        ) as tar:
            tar.extractall(
                extraction,
                filter="data",
            )
    except (
        tarfile.TarError,
        OSError,
    ) as error:
        raise ExternalProviderError(
            f"unable to extract "
            f"{name}"
        ) from error

    root_name = (
        record["asset"]
        .removesuffix(
            ".tar.xz"
        )
    )

    root = (
        extraction
        / root_name
    )

    if not root.is_dir():
        raise ExternalProviderError(
            f"{name} archive root "
            f"is missing: {root}"
        )

    source = (
        root
        / LAYOUTS[name]
        .archive_payload
    )

    if not source.is_dir():
        raise ExternalProviderError(
            f"{name} archive payload "
            f"is missing: {source}"
        )

    return source


def ensure_external_provider(
    name: str,
) -> Path:
    if name not in LAYOUTS:
        raise ExternalProviderError(
            "unsupported Bootstrap "
            f"external provider: {name}"
        )

    record = _provider_record(
        name
    )

    destination = (
        LAYOUTS[name]
        .destination
    )

    if destination.exists():
        print(
            f"[provider:{name}] "
            "VERIFY existing: "
            f"{destination}"
        )

        if not _verify_runtime(
            name,
            destination,
            record["runtime_sha256"],
        ):
            raise ExternalProviderError(
                f"existing {name} "
                "provider has an invalid "
                "runtime identity"
            )

        print(
            f"[provider:{name}] "
            "VERIFY runtime identity: PASS"
        )

        return destination

    archive = _download(
        name,
        record,
    )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    extraction = (
        destination.parent
        / (
            "."
            + destination.name
            + ".extract-"
            + str(
                os.getpid()
            )
        )
    )

    temporary = (
        destination.parent
        / (
            "."
            + destination.name
            + ".materialize-"
            + str(
                os.getpid()
            )
        )
    )

    for path in (
        extraction,
        temporary,
    ):
        if path.exists():
            shutil.rmtree(
                path
            )

    try:
        source = _extract_payload(
            name,
            archive,
            record,
            extraction,
        )

        identity = _identity_path(
            name,
            source,
        )

        if not identity.is_file():
            raise ExternalProviderError(
                f"{name} identity "
                "file is missing: "
                f"{identity}"
            )

        actual = _sha256(
            identity
        )

        print(
            f"[provider:{name}] "
            f"RUNTIME SHA256: {actual}"
        )

        if (
            actual
            != record[
                "runtime_sha256"
            ]
        ):
            raise ExternalProviderError(
                f"{name} runtime "
                "identity mismatch: "
                f"{actual}; expected "
                + record[
                    "runtime_sha256"
                ]
            )

        print(
            f"[provider:{name}] "
            "RUNTIME VERIFY: PASS"
        )

        shutil.copytree(
            source,
            temporary,
            symlinks=True,
        )

        if not _verify_runtime(
            name,
            temporary,
            record["runtime_sha256"],
        ):
            raise ExternalProviderError(
                f"{name} materialized "
                "provider failed "
                "verification"
            )

        print(
            f"[provider:{name}] "
            "MATERIALIZE: "
            f"{destination}"
        )

        temporary.replace(
            destination
        )

        print(
            f"[provider:{name}] "
            "MATERIALIZE: PASS"
        )

    finally:
        if extraction.exists():
            shutil.rmtree(
                extraction
            )

        if temporary.exists():
            shutil.rmtree(
                temporary
            )

    return destination


def ensure_declared_external_providers(
) -> tuple[Path, ...]:
    declared = set(
        declared_provider_names()
    )

    results: list[Path] = []

    for name in LAYOUTS:
        if name not in declared:
            continue

        results.append(
            ensure_external_provider(
                name
            )
        )

    return tuple(
        results
    )


__all__ = (
    "ExternalProviderError",
    "declared_provider_names",
    "ensure_declared_external_providers",
    "ensure_external_provider",
)
