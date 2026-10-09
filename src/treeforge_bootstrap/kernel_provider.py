from __future__ import annotations

import hashlib
import json
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
    "r0.94-v1.0b2"
)

KERNEL_ASSET = "boot.img"

KERNEL_MODULE_PROVIDER_ASSET = (
    "module-provider.json"
)

KERNEL_MODULE_ARCHIVE_ASSET = (
    "treeforge-kernel-modules-"
    "tangorpro-android15-"
    + KERNEL_RELEASE_TAG
    + ".tar.zst"
)

KERNEL_URL = (
    "https://github.com/"
    + KERNEL_REPOSITORY
    + "/releases/download/"
    + KERNEL_RELEASE_TAG
    + "/"
    + KERNEL_ASSET
)

EXPECTED_KERNEL_BYTES = 67108864

EXPECTED_KERNEL_SHA256 = (
    "51f863c0b872ca0f10a8f2d92e82b3"
    "f465447fff48920fd1fd0e802dd499f27b"
)

EXPECTED_MODULE_PROVIDER_BYTES = 473737

EXPECTED_MODULE_PROVIDER_SHA256 = (
    "6c600187087fbeb3a41123f9dc5ca596"
    "dbe9109f2f81706749b5aa447ccbb821"
)

EXPECTED_MODULE_ARCHIVE_BYTES = 16891974

EXPECTED_MODULE_ARCHIVE_SHA256 = (
    "1c8aa8caec6b48c5b63831f179e11fab"
    "4b482cf920c489954397d33df2faf3b3"
)

SUPPORTED_BASELINE = {
    "vendor_kernel_boot_sha256":
        "810fab21f77ed66295799cd04208958b"
        "fbee11180433b499726c282df9e382fc",

    "vendor_dlkm_sha256":
        "b35713610f16dc6fc19649abfcab1ade"
        "1c8b2bf4fd026c2f7a49ffb1e45fd1e8",

    "system_dlkm_sha256":
        "1daf1af2a01e5cd6d12e84c2b41c08c"
        "45ef949fd0977f0defd835081594cec7e",
}

_RELEASE_ASSETS = {
    KERNEL_ASSET: {
        "bytes": EXPECTED_KERNEL_BYTES,
        "sha256": EXPECTED_KERNEL_SHA256,
    },
    KERNEL_MODULE_PROVIDER_ASSET: {
        "bytes": EXPECTED_MODULE_PROVIDER_BYTES,
        "sha256": EXPECTED_MODULE_PROVIDER_SHA256,
    },
    KERNEL_MODULE_ARCHIVE_ASSET: {
        "bytes": EXPECTED_MODULE_ARCHIVE_BYTES,
        "sha256": EXPECTED_MODULE_ARCHIVE_SHA256,
    },
}

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

KERNEL_CACHE_MODULE_PROVIDER = (
    KERNEL_CACHE
    / KERNEL_MODULE_PROVIDER_ASSET
)

KERNEL_CACHE_MODULE_ARCHIVE = (
    KERNEL_CACHE
    / KERNEL_MODULE_ARCHIVE_ASSET
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


def _asset_url(
    asset: str,
) -> str:
    return (
        "https://github.com/"
        + KERNEL_REPOSITORY
        + "/releases/download/"
        + KERNEL_RELEASE_TAG
        + "/"
        + asset
    )


def _verify_asset(
    path: Path,
    asset: str,
) -> None:
    record = _RELEASE_ASSETS.get(
        asset
    )

    if record is None:
        raise TreeForgeBootstrapKernelProviderError(
            "unknown TreeForge kernel release "
            f"asset: {asset}"
        )

    if not path.is_file():
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel release asset "
            f"missing: {path}"
        )

    size = path.stat().st_size

    if size != record["bytes"]:
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel release asset "
            f"size changed: {asset}: {size}"
        )

    actual = sha256(
        path
    )

    if actual != record["sha256"]:
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel release asset "
            f"identity changed: {asset}: {actual}"
        )


def _verify(
    path: Path,
) -> None:
    #
    # Compatibility wrapper retained for image.py and
    # existing Bootstrap callers.
    #
    _verify_asset(
        path,
        KERNEL_ASSET,
    )


def _download_asset(
    asset: str,
) -> Path:
    KERNEL_CACHE.mkdir(
        parents=True,
        exist_ok=True,
    )

    destination = (
        KERNEL_CACHE
        / asset
    )

    with tempfile.TemporaryDirectory(
        prefix=".download-",
        dir=KERNEL_CACHE,
    ) as raw:
        temporary = Path(raw)

        downloaded = (
            temporary
            / asset
        )

        request = urllib.request.Request(
            _asset_url(asset),
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
                "TreeForge kernel asset: "
                f"{asset}"
            ) from exc

        _verify_asset(
            downloaded,
            asset,
        )

        replacement = (
            KERNEL_CACHE
            / (
                "."
                + asset
                + ".new"
            )
        )

        if replacement.exists():
            replacement.unlink()

        shutil.copyfile(
            downloaded,
            replacement,
        )

        _verify_asset(
            replacement,
            asset,
        )

        replacement.replace(
            destination
        )

    _verify_asset(
        destination,
        asset,
    )

    return destination


def _ensure_asset(
    asset: str,
) -> Path:
    path = (
        KERNEL_CACHE
        / asset
    )

    try:
        _verify_asset(
            path,
            asset,
        )

        return path

    except TreeForgeBootstrapKernelProviderError:
        return _download_asset(
            asset
        )


def _verify_provider_contract(
    path: Path,
) -> dict[str, object]:
    try:
        metadata = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel module provider "
            "metadata is unreadable"
        ) from exc

    if (
        metadata.get("schema")
        != "treeforge.kernel.module-provider.v1"
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel provider schema changed"
        )

    if (
        metadata.get("release")
        != KERNEL_RELEASE_TAG
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel provider release changed"
        )

    reconstruction = metadata.get(
        "reconstruction"
    )

    if not isinstance(
        reconstruction,
        dict,
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel reconstruction "
            "contract is missing"
        )

    if (
        reconstruction.get(
            "module_tree_policy"
        )
        != "replace_exact"
        or reconstruction.get(
            "regenerate_module_metadata"
        )
        is not True
        or reconstruction.get(
            "partition_images_distributed"
        )
        is not False
        or reconstruction.get(
            "owner_avb"
        )
        != "local-device-owner-resign"
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel reconstruction "
            "policy changed"
        )

    vendor_kernel_boot = (
        reconstruction.get(
            "vendor_kernel_boot"
        )
    )

    if (
        not isinstance(
            vendor_kernel_boot,
            dict,
        )
        or vendor_kernel_boot.get(
            "source"
        )
        != "current-installed"
        or vendor_kernel_boot.get(
            "image_structure"
        )
        != "preserve"
        or vendor_kernel_boot.get(
            "module_tree_policy"
        )
        != "replace_exact"
        or vendor_kernel_boot.get(
            "ramdisk_compression"
        )
        != "lz4"
        or vendor_kernel_boot.get(
            "rebuild"
        )
        is not True
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge vendor_kernel_boot "
            "reconstruction policy changed"
        )

    baseline = metadata.get(
        "supported_baseline"
    )

    if not isinstance(
        baseline,
        dict,
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel source baseline "
            "is missing"
        )

    if (
        baseline.get("type")
        != "pixel-partitioner-aosp-backup"
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel source baseline "
            "type changed"
        )

    for key, expected in (
        SUPPORTED_BASELINE.items()
    ):
        if (
            baseline.get(key)
            != expected
        ):
            raise TreeForgeBootstrapKernelProviderError(
                "TreeForge kernel source baseline "
                f"changed: {key}"
            )

    carriers = metadata.get(
        "carriers"
    )

    if (
        not isinstance(
            carriers,
            dict,
        )
        or set(carriers)
        != {
            "vendor_kernel_boot",
            "vendor_dlkm",
            "system_dlkm",
        }
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel carrier set changed"
        )

    return metadata


def ensure_bootstrap_kernel() -> Path:
    return _ensure_asset(
        KERNEL_ASSET
    )


def ensure_kernel_reconstruction_provider(
) -> dict[str, object]:
    boot = _ensure_asset(
        KERNEL_ASSET
    )

    manifest = _ensure_asset(
        KERNEL_MODULE_PROVIDER_ASSET
    )

    archive = _ensure_asset(
        KERNEL_MODULE_ARCHIVE_ASSET
    )

    metadata = (
        _verify_provider_contract(
            manifest
        )
    )

    return {
        "release":
            KERNEL_RELEASE_TAG,

        "boot":
            boot,

        "manifest":
            manifest,

        "archive":
            archive,

        "metadata":
            metadata,
    }
