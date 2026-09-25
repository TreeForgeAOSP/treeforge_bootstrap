from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import tempfile
import urllib.error
import urllib.request


class TreeForgeBootstrapKernelProviderError(
    RuntimeError
):
    pass


KERNEL_REPOSITORY = (
    "TreeForgeAOSP/treeforge_kernel"
)

KERNEL_RELEASE_TAG = (
    "treeforge-bootstrap-"
    "tangorpro-android15-r0.94-4"
)

KERNEL_ASSET = "boot.img"

KERNEL_URL = (
    "https://github.com/"
    "TreeForgeAOSP/treeforge_kernel/"
    "releases/download/"
    + KERNEL_RELEASE_TAG
    + "/boot.img"
)

EXPECTED_KERNEL_BYTES = 67108864

EXPECTED_KERNEL_SHA256 = (
    "59d9103f7c9e343a96af6d37f9307f4610db7d228976b9d67ac59fab00bcf20b"
)

KERNEL_CACHE = (
    Path.home()
    / ".cache"
    / "treeforge"
    / "bootstrap-kernel"
    / KERNEL_RELEASE_TAG
)

KERNEL_CACHE_IMAGE = (
    KERNEL_CACHE
    / KERNEL_ASSET
)


def sha256(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(
            lambda: handle.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def _verify(
    path: Path,
) -> None:
    if not path.is_file():
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge Bootstrap kernel "
            f"missing: {path}"
        )

    size = path.stat().st_size

    if size != EXPECTED_KERNEL_BYTES:
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge Bootstrap kernel "
            "size changed: "
            f"{size}"
        )

    actual = sha256(
        path
    )

    if actual != EXPECTED_KERNEL_SHA256:
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge Bootstrap kernel "
            "identity changed: "
            f"{actual}"
        )


def _download() -> Path:
    KERNEL_CACHE.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.TemporaryDirectory(
        prefix=".download-",
        dir=KERNEL_CACHE,
    ) as raw:
        temporary = Path(raw)

        downloaded = (
            temporary
            / KERNEL_ASSET
        )

        request = urllib.request.Request(
            KERNEL_URL,
            headers={
                "User-Agent":
                    "TreeForge-Bootstrap/1",
            },
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=60,
            ) as response:
                with downloaded.open(
                    "wb"
                ) as output:
                    shutil.copyfileobj(
                        response,
                        output,
                        length=1024 * 1024,
                    )
        except (
            OSError,
            urllib.error.URLError,
        ) as exc:
            raise TreeForgeBootstrapKernelProviderError(
                "unable to fetch released "
                "TreeForge Bootstrap kernel"
            ) from exc

        _verify(
            downloaded
        )

        replacement = (
            KERNEL_CACHE
            / ".boot.img.new"
        )

        if replacement.exists():
            replacement.unlink()

        shutil.copyfile(
            downloaded,
            replacement,
        )

        _verify(
            replacement
        )

        replacement.replace(
            KERNEL_CACHE_IMAGE
        )

    _verify(
        KERNEL_CACHE_IMAGE
    )

    return KERNEL_CACHE_IMAGE


def ensure_bootstrap_kernel() -> Path:
    try:
        _verify(
            KERNEL_CACHE_IMAGE
        )

        return KERNEL_CACHE_IMAGE

    except TreeForgeBootstrapKernelProviderError:
        return _download()
