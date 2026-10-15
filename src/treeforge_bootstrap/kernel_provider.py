from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request


class TreeForgeBootstrapKernelProviderError(
    RuntimeError
):
    pass


KERNEL_REPOSITORY = (
    "TreeForgeAOSP/treeforge_kernel"
)

#
# This is a workspace/channel label only.
# It is NOT a GitHub release tag.
#
KERNEL_CHANNEL = "current"

KERNEL_ASSET = "boot.img"

KERNEL_MODULE_PROVIDER_ASSET = (
    "module-provider.json"
)

KERNEL_CHECKSUMS_ASSET = (
    "SHA256SUMS"
)

KERNEL_CACHE_ROOT = (
    Path.home()
    / ".cache"
    / "treeforge"
    / "bootstrap-kernel"
)

KERNEL_RELEASE_RE = re.compile(
    r"r([0-9]+)\.([0-9]+)-"
    r"v([0-9]+)\.([0-9]+)b([0-9]+)"
)

_RESOLVED_RELEASE: dict[str, object] | None = None

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


_KERNEL_PROVIDER_OVERRIDE: Path | None = None


def _verify_development_checksums(
    root: Path,
) -> None:
    sums = root / "SHA256SUMS"

    if not sums.is_file():
        raise TreeForgeBootstrapKernelProviderError(
            "kernel development provider "
            "SHA256SUMS missing"
        )

    seen: set[str] = set()

    for raw in sums.read_text(
        encoding="utf-8"
    ).splitlines():
        if not raw.strip():
            continue

        try:
            digest, relative = raw.split(
                "  ",
                1,
            )
        except ValueError as error:
            raise TreeForgeBootstrapKernelProviderError(
                "invalid kernel development "
                "provider checksum line"
            ) from error

        if relative in seen:
            raise TreeForgeBootstrapKernelProviderError(
                "duplicate kernel development "
                f"provider checksum: {relative}"
            )

        seen.add(relative)

        target = root / relative

        if not target.is_file():
            raise TreeForgeBootstrapKernelProviderError(
                "kernel development provider "
                f"asset missing: {relative}"
            )

        if sha256(target) != digest:
            raise TreeForgeBootstrapKernelProviderError(
                "kernel development provider "
                f"checksum mismatch: {relative}"
            )

    required = {
        "boot.img",
        "module-provider.json",
    }

    if not required.issubset(seen):
        raise TreeForgeBootstrapKernelProviderError(
            "kernel development provider "
            "checksum membership incomplete"
        )


def _development_android_archive(
    root: Path,
) -> Path:
    matches = sorted(
        root.glob(
            "treeforge-kernel-modules-"
            "*.tar.zst"
        )
    )

    if len(matches) != 1:
        raise TreeForgeBootstrapKernelProviderError(
            "kernel development provider "
            "must contain exactly one Android "
            "module archive"
        )

    return matches[0]


def _verify_development_provider_contract(
    root: Path,
) -> dict[str, object]:
    development_path = (
        root
        / "development-provider.json"
    )

    module_path = (
        root
        / "module-provider.json"
    )

    if not development_path.is_file():
        raise TreeForgeBootstrapKernelProviderError(
            "kernel development-provider.json "
            f"missing: {root}"
        )

    try:
        development = json.loads(
            development_path.read_text(
                encoding="utf-8"
            )
        )

        metadata = json.loads(
            module_path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise TreeForgeBootstrapKernelProviderError(
            "kernel development provider "
            "metadata is unreadable"
        ) from error

    if (
        not isinstance(development, dict)
        or development.get("schema")
        != "treeforge.development-provider.v1"
        or development.get("provider")
        != "kernel"
        or development.get("channel")
        != "development"
        or development.get("release_eligible")
        is not False
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "kernel development provider "
            "identity changed"
        )

    version = development.get(
        "version"
    )

    if (
        not isinstance(version, str)
        or not version
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "kernel development provider "
            "version missing"
        )

    if (
        not isinstance(metadata, dict)
        or metadata.get("schema")
        != "treeforge.kernel.module-provider.v2"
        or metadata.get("release")
        != version
        or metadata.get("target")
        != "tangorpro"
        or metadata.get("android_base")
        != "android15"
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "kernel development module "
            "provider identity changed"
        )

    reconstruction = metadata.get(
        "reconstruction"
    )

    if (
        not isinstance(
            reconstruction,
            dict,
        )
        or reconstruction.get(
            "carrier_source"
        )
        != "current-installed"
        or reconstruction.get(
            "carrier_policy"
        )
        != "patch-current"
        or reconstruction.get(
            "non_module_payload"
        )
        != "preserve-exact"
        or reconstruction.get(
            "module_tree_policy"
        )
        != "replace-exact"
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
            "kernel development carrier "
            "policy changed"
        )

    carrier_policy = reconstruction.get(
        "carriers"
    )

    if (
        not isinstance(
            carrier_policy,
            dict,
        )
        or set(carrier_policy)
        != {
            "vendor_kernel_boot",
            "vendor_dlkm",
            "system_dlkm",
        }
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "kernel development carrier "
            "policy set changed"
        )

    carriers = metadata.get(
        "carriers"
    )

    if (
        not isinstance(carriers, dict)
        or set(carriers)
        != {
            "vendor_kernel_boot",
            "vendor_dlkm",
            "system_dlkm",
        }
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "kernel development carrier "
            "payload set changed"
        )

    _verify_development_checksums(
        root
    )

    boot = root / "boot.img"

    if (
        not boot.is_file()
        or sha256(boot)
        != metadata.get("boot_sha256")
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "kernel development boot "
            "identity mismatch"
        )

    archive = (
        _development_android_archive(
            root
        )
    )

    return {
        "release": version,
        "boot": boot,
        "manifest": module_path,
        "archive": archive,
        "metadata": metadata,
        "development": development,
        "root": root,
    }


def configure_kernel_provider_override(
    root: Path | None,
) -> None:
    global _KERNEL_PROVIDER_OVERRIDE

    if root is None:
        _KERNEL_PROVIDER_OVERRIDE = None
        return

    resolved = (
        root
        .expanduser()
        .resolve()
    )

    _verify_development_provider_contract(
        resolved
    )

    _KERNEL_PROVIDER_OVERRIDE = (
        resolved
    )


def kernel_provider_override(
) -> Path | None:
    return _KERNEL_PROVIDER_OVERRIDE


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


def _github_token(
) -> str | None:
    for name in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
    ):
        value = os.environ.get(
            name,
            "",
        ).strip()

        if value:
            return value

    gh = shutil.which(
        "gh"
    )

    if gh is None:
        return None

    completed = subprocess.run(
        [
            gh,
            "auth",
            "token",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    if completed.returncode != 0:
        return None

    value = completed.stdout.strip()

    return value or None


def _github_request(
    url: str,
    *,
    token: str | None,
    accept: str,
) -> urllib.request.Request:
    headers = {
        "Accept":
            accept,

        "User-Agent":
            "TreeForge-Bootstrap/1",

        "X-GitHub-Api-Version":
            "2022-11-28",
    }

    if token:
        headers[
            "Authorization"
        ] = f"Bearer {token}"

    return urllib.request.Request(
        url,
        headers=headers,
    )


def _release_key(
    tag: str,
) -> tuple[int, ...]:
    match = KERNEL_RELEASE_RE.fullmatch(
        tag
    )

    if match is None:
        raise TreeForgeBootstrapKernelProviderError(
            "unsupported TreeForge kernel "
            f"release tag: {tag}"
        )

    return tuple(
        int(value)
        for value in match.groups()
    )


def _published_release_tags(
    token: str | None,
) -> tuple[str, ...]:
    tags: list[str] = []

    page = 1

    while True:
        url = (
            "https://api.github.com/repos/"
            + KERNEL_REPOSITORY
            + f"/releases?per_page=100&page={page}"
        )

        try:
            with urllib.request.urlopen(
                _github_request(
                    url,
                    token=token,
                    accept=(
                        "application/"
                        "vnd.github+json"
                    ),
                ),
                timeout=60,
            ) as response:
                records = json.load(
                    response
                )

        except (
            OSError,
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
        ) as error:
            raise TreeForgeBootstrapKernelProviderError(
                "unable to enumerate published "
                "TreeForge kernel releases"
            ) from error

        if not isinstance(
            records,
            list,
        ):
            raise TreeForgeBootstrapKernelProviderError(
                "TreeForge kernel release listing "
                "is not an array"
            )

        for record in records:
            if not isinstance(
                record,
                dict,
            ):
                continue

            if (
                record.get("draft") is True
                or record.get(
                    "prerelease"
                ) is True
            ):
                continue

            tag = record.get(
                "tag_name"
            )

            if (
                isinstance(tag, str)
                and KERNEL_RELEASE_RE.fullmatch(
                    tag
                )
            ):
                tags.append(
                    tag
                )

        if len(records) < 100:
            break

        page += 1

    releases = sorted(
        set(tags),
        key=_release_key,
        reverse=True,
    )

    if not releases:
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel has no supported "
            "published releases"
        )

    return tuple(
        releases
    )


def _release_assets(
    tag: str,
    token: str | None,
) -> dict[str, str]:
    encoded = urllib.parse.quote(
        tag,
        safe="",
    )

    url = (
        "https://api.github.com/repos/"
        + KERNEL_REPOSITORY
        + "/releases/tags/"
        + encoded
    )

    try:
        with urllib.request.urlopen(
            _github_request(
                url,
                token=token,
                accept=(
                    "application/"
                    "vnd.github+json"
                ),
            ),
            timeout=60,
        ) as response:
            release = json.load(
                response
            )

    except (
        OSError,
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
    ) as error:
        raise TreeForgeBootstrapKernelProviderError(
            "unable to inspect TreeForge "
            f"kernel release: {tag}"
        ) from error

    if not isinstance(
        release,
        dict,
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel release metadata "
            "is not an object"
        )

    result: dict[str, str] = {}

    for record in release.get(
        "assets",
        [],
    ):
        if not isinstance(
            record,
            dict,
        ):
            continue

        name = record.get(
            "name"
        )

        download = record.get(
            "browser_download_url"
        )

        if (
            isinstance(name, str)
            and isinstance(
                download,
                str,
            )
        ):
            result[name] = download

    return result


def _download_release_asset(
    url: str,
    destination: Path,
    *,
    token: str | None,
) -> None:
    try:
        with urllib.request.urlopen(
            _github_request(
                url,
                token=token,
                accept=(
                    "application/"
                    "octet-stream"
                ),
            ),
            timeout=120,
        ) as response:
            with destination.open(
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
        TimeoutError,
    ) as error:
        raise TreeForgeBootstrapKernelProviderError(
            "unable to download TreeForge "
            "kernel release asset: "
            f"{destination.name}"
        ) from error


def _parse_sums(
    path: Path,
) -> dict[str, str]:
    if not path.is_file():
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel SHA256SUMS "
            "is missing"
        )

    result: dict[str, str] = {}

    for raw in path.read_text(
        encoding="utf-8"
    ).splitlines():
        line = raw.strip()

        if not line:
            continue

        fields = line.split(
            None,
            1,
        )

        if len(fields) != 2:
            raise TreeForgeBootstrapKernelProviderError(
                "invalid TreeForge kernel "
                "SHA256SUMS entry"
            )

        digest, name = fields

        name = name.strip()

        if name.startswith("*"):
            name = name[1:]

        if (
            len(digest) != 64
            or any(
                character
                not in
                "0123456789abcdef"
                for character
                in digest.lower()
            )
        ):
            raise TreeForgeBootstrapKernelProviderError(
                "invalid TreeForge kernel "
                f"SHA256 digest: {name}"
            )

        result[name] = (
            digest.lower()
        )

    return result


def _kernel_module_archive_name(
    release: str,
) -> str:
    return (
        "treeforge-kernel-modules-"
        "tangorpro-android15-"
        + release
        + ".tar.zst"
    )


def _verify_release_root(
    root: Path,
    *,
    expected_release: str,
) -> dict[str, object]:
    archive_name = (
        _kernel_module_archive_name(
            expected_release
        )
    )

    required = {
        KERNEL_ASSET,
        KERNEL_MODULE_PROVIDER_ASSET,
        KERNEL_CHECKSUMS_ASSET,
        archive_name,
    }

    for name in required:
        path = root / name

        if not path.is_file():
            raise TreeForgeBootstrapKernelProviderError(
                "TreeForge kernel release "
                f"asset missing: {name}"
            )

    sums = _parse_sums(
        root
        / KERNEL_CHECKSUMS_ASSET
    )

    for name in (
        KERNEL_ASSET,
        KERNEL_MODULE_PROVIDER_ASSET,
        archive_name,
    ):
        expected = sums.get(
            name
        )

        if expected is None:
            raise TreeForgeBootstrapKernelProviderError(
                "TreeForge kernel SHA256SUMS "
                f"does not contain: {name}"
            )

        actual = sha256(
            root / name
        )

        if actual != expected:
            raise TreeForgeBootstrapKernelProviderError(
                "TreeForge kernel release "
                f"checksum mismatch: {name}: "
                f"{actual} != {expected}"
            )

    boot_sha256 = sums[
        KERNEL_ASSET
    ]

    metadata = _verify_provider_contract(
        root
        / KERNEL_MODULE_PROVIDER_ASSET,
        expected_release=(
            expected_release
        ),
        expected_boot_sha256=(
            boot_sha256
        ),
    )

    return {
        "release":
            expected_release,

        "boot":
            root / KERNEL_ASSET,

        "manifest":
            root
            / KERNEL_MODULE_PROVIDER_ASSET,

        "archive":
            root / archive_name,

        "metadata":
            metadata,

        "root":
            root,
    }


def _materialize_release_provider(
) -> dict[str, object]:
    global _RESOLVED_RELEASE

    if _RESOLVED_RELEASE is not None:
        root = Path(
            _RESOLVED_RELEASE[
                "root"
            ]
        )

        release = str(
            _RESOLVED_RELEASE[
                "release"
            ]
        )

        _RESOLVED_RELEASE = (
            _verify_release_root(
                root,
                expected_release=release,
            )
        )

        return _RESOLVED_RELEASE

    token = _github_token()

    release = (
        _published_release_tags(
            token
        )[0]
    )

    print(
        "[provider:kernel] "
        "RESOLVE latest published release: "
        + release
    )

    cache = (
        KERNEL_CACHE_ROOT
        / release
    )

    if cache.is_dir():
        try:
            result = (
                _verify_release_root(
                    cache,
                    expected_release=release,
                )
            )

            print(
                "[provider:kernel] "
                "VERIFY cache: "
                + str(cache)
            )

            _RESOLVED_RELEASE = result

            return result

        except (
            TreeForgeBootstrapKernelProviderError
        ):
            shutil.rmtree(
                cache
            )

    assets = _release_assets(
        release,
        token,
    )

    archive_name = (
        _kernel_module_archive_name(
            release
        )
    )

    required = {
        KERNEL_ASSET,
        KERNEL_MODULE_PROVIDER_ASSET,
        KERNEL_CHECKSUMS_ASSET,
        archive_name,
    }

    missing = sorted(
        required
        - set(assets)
    )

    if missing:
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel release "
            f"{release} is missing assets: "
            f"{missing!r}"
        )

    KERNEL_CACHE_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.TemporaryDirectory(
        prefix=(
            "."
            + release
            + ".partial-"
        ),
        dir=KERNEL_CACHE_ROOT,
    ) as raw:
        temporary = Path(
            raw
        )

        for name in sorted(
            required
        ):
            _download_release_asset(
                assets[name],
                temporary / name,
                token=token,
            )

        _verify_release_root(
            temporary,
            expected_release=release,
        )

        if cache.exists():
            shutil.rmtree(
                cache
            )

        shutil.copytree(
            temporary,
            cache,
        )

    result = (
        _verify_release_root(
            cache,
            expected_release=release,
        )
    )

    print(
        "[provider:kernel] "
        "MATERIALIZE: "
        + str(cache)
    )

    _RESOLVED_RELEASE = result

    return result


def _verify_provider_contract(
    path: Path,
    *,
    expected_release: str,
    expected_boot_sha256: str,
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
    ) as error:
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel module provider "
            "metadata is unreadable"
        ) from error

    if not isinstance(metadata, dict):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel provider metadata "
            "is not an object"
        )

    if (
        metadata.get("schema")
        != "treeforge.kernel.module-provider.v2"
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel provider schema changed"
        )

    if (
        metadata.get("release")
        != expected_release
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel provider release changed"
        )

    if (
        metadata.get("target")
        != "tangorpro"
        or metadata.get("android_base")
        != "android15"
        or metadata.get("boot_sha256")
        != expected_boot_sha256
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel provider identity changed"
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

    expected_reconstruction = {
        "carrier_source":
            "current-installed",
        "carrier_policy":
            "patch-current",
        "non_module_payload":
            "preserve-exact",
        "module_tree_policy":
            "replace-exact",
        "regenerate_module_metadata":
            True,
        "partition_images_distributed":
            False,
        "owner_avb":
            "local-device-owner-resign",
    }

    for key, expected in (
        expected_reconstruction.items()
    ):
        if reconstruction.get(key) != expected:
            raise TreeForgeBootstrapKernelProviderError(
                "TreeForge kernel reconstruction "
                f"policy changed: {key}"
            )

    carrier_policy = reconstruction.get(
        "carriers"
    )

    if (
        not isinstance(carrier_policy, dict)
        or set(carrier_policy)
        != {
            "vendor_kernel_boot",
            "vendor_dlkm",
            "system_dlkm",
        }
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel carrier policy set changed"
        )

    expected_dlkm = {
        "filesystem_structure":
            "preserve",
        "module_tree_policy":
            "replace-exact",
        "non_module_payload":
            "preserve-exact",
    }

    for name in (
        "vendor_dlkm",
        "system_dlkm",
    ):
        record = carrier_policy.get(name)

        if (
            not isinstance(record, dict)
            or record != expected_dlkm
        ):
            raise TreeForgeBootstrapKernelProviderError(
                "TreeForge kernel carrier "
                f"policy changed: {name}"
            )

    expected_vendor_kernel_boot = {
        "image_structure":
            "preserve",
        "module_tree_policy":
            "replace-exact",
        "non_module_payload":
            "preserve-exact",
        "ramdisk_compression":
            "lz4",
    }

    if (
        carrier_policy.get(
            "vendor_kernel_boot"
        )
        != expected_vendor_kernel_boot
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge vendor_kernel_boot "
            "carrier policy changed"
        )

    baseline = metadata.get(
        "supported_baseline"
    )

    if (
        not isinstance(baseline, dict)
        or baseline.get("type")
        != "pixel-partitioner-aosp-backup"
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel source baseline "
            "is missing"
        )

    for name, expected in (
        SUPPORTED_BASELINE.items()
    ):
        if baseline.get(name) != expected:
            raise TreeForgeBootstrapKernelProviderError(
                "TreeForge kernel source baseline "
                f"changed: {name}"
            )

    carriers = metadata.get(
        "carriers"
    )

    if (
        not isinstance(carriers, dict)
        or set(carriers)
        != {
            "vendor_kernel_boot",
            "vendor_dlkm",
            "system_dlkm",
        }
    ):
        raise TreeForgeBootstrapKernelProviderError(
            "TreeForge kernel carrier payload "
            "set changed"
        )

    return metadata

def ensure_bootstrap_kernel(
) -> Path:
    if _KERNEL_PROVIDER_OVERRIDE is not None:
        provider = (
            _verify_development_provider_contract(
                _KERNEL_PROVIDER_OVERRIDE
            )
        )

        return Path(
            provider["boot"]
        )

    provider = (
        _materialize_release_provider()
    )

    return Path(
        provider["boot"]
    )


def ensure_kernel_reconstruction_provider(
) -> dict[str, object]:
    if _KERNEL_PROVIDER_OVERRIDE is not None:
        return (
            _verify_development_provider_contract(
                _KERNEL_PROVIDER_OVERRIDE
            )
        )

    return (
        _materialize_release_provider()
    )


def resolved_kernel_release(
) -> str:
    provider = (
        ensure_kernel_reconstruction_provider()
    )

    return str(
        provider["release"]
    )
