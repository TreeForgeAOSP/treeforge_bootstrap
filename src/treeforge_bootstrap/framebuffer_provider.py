from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


class TreeForgeFramebufferProviderError(RuntimeError):
    pass


PROVIDER_NAME = "treeforge_bootstrap_framebuffer"
PROVIDER_VERSION = "v1.0b1"
PROVIDER_ABI = 1
PROVIDER_ENV = "TREEFORGE_BOOTSTRAP_FRAMEBUFFER_PROVIDER"

PROVIDER_REPOSITORY = (
    "TreeForgeDEV/treeforge_bootstrap_framebuffer"
)
PROVIDER_RELEASE_ASSET = (
    "treeforge-bootstrap-framebuffer-v1.0b1-provider.tar.xz"
)
PROVIDER_RELEASE_SHA256 = (
    "1ac64371bb52dc0c6be869a5d6f517619da8e36f16d4549825cde47ae9f08f82"
)
PROVIDER_MANIFEST_SHA256 = (
    "104f3df33d4de8236c04d7edea7b87a68eb852d5a5bb3908c96052b5d12e8197"
)
PROVIDER_ARCHIVE_PREFIX = PROVIDER_NAME
PROVIDER_CACHE_ROOT = (
    Path.home()
    / ".cache"
    / "treeforge"
    / "providers"
    / PROVIDER_NAME
)
PROVIDER_CACHE = (
    PROVIDER_CACHE_ROOT
    / PROVIDER_VERSION
)


@dataclass(frozen=True)
class FramebufferProvider:
    root: Path
    primitives_source: str
    transport_source: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for block in iter(
            lambda: stream.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def _github_token() -> str | None:
    for name in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
    ):
        value = os.environ.get(name, "").strip()

        if value:
            return value

    gh = shutil.which("gh")

    if gh is None:
        return None

    completed = subprocess.run(
        [gh, "auth", "token"],
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
    token: str,
    accept: str,
) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "User-Agent": "TreeForge-Bootstrap/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )


def _release_asset_api_url(token: str) -> str:
    encoded_tag = urllib.parse.quote(
        PROVIDER_VERSION,
        safe="",
    )
    release_url = (
        "https://api.github.com/repos/"
        + PROVIDER_REPOSITORY
        + "/releases/tags/"
        + encoded_tag
    )

    try:
        with urllib.request.urlopen(
            _github_request(
                release_url,
                token=token,
                accept="application/vnd.github+json",
            ),
            timeout=60,
        ) as response:
            release = json.load(response)
    except (
        OSError,
        urllib.error.URLError,
        json.JSONDecodeError,
    ) as error:
        raise TreeForgeFramebufferProviderError(
            "unable to resolve released TreeForge framebuffer provider"
        ) from error

    for asset in release.get("assets", []):
        if asset.get("name") != PROVIDER_RELEASE_ASSET:
            continue

        url = asset.get("url")

        if isinstance(url, str) and url:
            return url

    raise TreeForgeFramebufferProviderError(
        "released TreeForge framebuffer provider asset is missing: "
        + PROVIDER_RELEASE_ASSET
    )


def _download_release_archive(
    destination: Path,
    token: str,
) -> None:
    asset_url = _release_asset_api_url(token)

    try:
        with urllib.request.urlopen(
            _github_request(
                asset_url,
                token=token,
                accept="application/octet-stream",
            ),
            timeout=120,
        ) as response:
            with destination.open("wb") as output:
                shutil.copyfileobj(
                    response,
                    output,
                    length=1024 * 1024,
                )
    except (
        OSError,
        urllib.error.URLError,
    ) as error:
        raise TreeForgeFramebufferProviderError(
            "unable to download released TreeForge framebuffer provider"
        ) from error

    actual = _sha256(destination)

    if actual != PROVIDER_RELEASE_SHA256:
        raise TreeForgeFramebufferProviderError(
            "released framebuffer provider archive identity changed: "
            f"{actual} != {PROVIDER_RELEASE_SHA256}"
        )


def _safe_extract_release(
    archive: Path,
    destination: Path,
) -> Path:
    prefix = Path(PROVIDER_ARCHIVE_PREFIX)

    try:
        with tarfile.open(archive, mode="r:xz") as bundle:
            members = bundle.getmembers()

            if not members:
                raise TreeForgeFramebufferProviderError(
                    "released framebuffer provider archive is empty"
                )

            for member in members:
                member_path = Path(member.name)

                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or not member_path.parts
                    or member_path.parts[0] != prefix.name
                ):
                    raise TreeForgeFramebufferProviderError(
                        "released framebuffer provider archive has "
                        f"unsafe member: {member.name}"
                    )

                if member.issym() or member.islnk():
                    raise TreeForgeFramebufferProviderError(
                        "released framebuffer provider archive has "
                        f"link member: {member.name}"
                    )

            bundle.extractall(
                destination,
                filter="data",
            )
    except (
        OSError,
        tarfile.TarError,
    ) as error:
        raise TreeForgeFramebufferProviderError(
            "unable to extract released TreeForge framebuffer provider"
        ) from error

    root = destination / prefix

    if not root.is_dir():
        raise TreeForgeFramebufferProviderError(
            "released framebuffer provider archive root is missing"
        )

    return root


def _verify_manifest_identity(root: Path) -> None:
    manifest = root / "provider.json"

    if not manifest.is_file():
        raise TreeForgeFramebufferProviderError(
            "TreeForge framebuffer provider manifest is missing: "
            f"{manifest}"
        )

    actual = _sha256(manifest)

    if actual != PROVIDER_MANIFEST_SHA256:
        raise TreeForgeFramebufferProviderError(
            "framebuffer provider manifest identity changed: "
            f"{actual} != {PROVIDER_MANIFEST_SHA256}"
        )


def _materialize_release_provider() -> Path:
    if PROVIDER_CACHE.is_dir():
        try:
            _verify_manifest_identity(PROVIDER_CACHE)
            return PROVIDER_CACHE
        except TreeForgeFramebufferProviderError:
            shutil.rmtree(PROVIDER_CACHE)

    token = _github_token()

    if token is None:
        raise TreeForgeFramebufferProviderError(
            "TreeForge framebuffer provider is private. "
            "Authenticate with `gh auth login`, or set "
            "GH_TOKEN / GITHUB_TOKEN."
        )

    PROVIDER_CACHE_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.TemporaryDirectory(
        prefix=f".{PROVIDER_VERSION}.partial-",
        dir=PROVIDER_CACHE_ROOT,
    ) as raw:
        temporary = Path(raw)
        archive = temporary / PROVIDER_RELEASE_ASSET

        _download_release_archive(
            archive,
            token,
        )

        extracted = _safe_extract_release(
            archive,
            temporary / "extract",
        )
        _verify_manifest_identity(extracted)

        replacement = (
            PROVIDER_CACHE_ROOT
            / f".{PROVIDER_VERSION}.new-{os.getpid()}"
        )

        if replacement.exists():
            shutil.rmtree(replacement)

        shutil.copytree(
            extracted,
            replacement,
        )
        _verify_manifest_identity(replacement)

        if PROVIDER_CACHE.exists():
            shutil.rmtree(PROVIDER_CACHE)

        replacement.replace(PROVIDER_CACHE)

    _verify_manifest_identity(PROVIDER_CACHE)
    return PROVIDER_CACHE


def _provider_root() -> Path:
    explicit = os.environ.get(PROVIDER_ENV)

    if explicit:
        root = Path(explicit).expanduser().resolve()
        _verify_manifest_identity(root)
        return root

    return _materialize_release_provider()


def _relative_payload(
    root: Path,
    record: object,
    field: str,
) -> Path:
    if not isinstance(record, dict):
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider {field} contract is missing"
        )

    raw_path = record.get("path")
    expected_sha256 = record.get("sha256")

    if not isinstance(raw_path, str) or not raw_path:
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider {field} path is invalid"
        )

    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in expected_sha256
        )
    ):
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider {field} sha256 is invalid"
        )

    relative = Path(raw_path)

    if relative.is_absolute() or ".." in relative.parts:
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider {field} path escapes provider root"
        )

    path = root / relative

    if not path.is_file():
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider {field} payload is missing: {path}"
        )

    actual_sha256 = _sha256(path)

    if actual_sha256 != expected_sha256:
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider {field} identity changed: "
            f"{actual_sha256} != {expected_sha256}"
        )

    return path


def load_framebuffer_provider() -> FramebufferProvider:
    root = _provider_root()
    manifest_path = root / "provider.json"

    _verify_manifest_identity(root)

    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise TreeForgeFramebufferProviderError(
            "unable to read TreeForge framebuffer provider manifest"
        ) from error

    if manifest.get("schema_version") != 1:
        raise TreeForgeFramebufferProviderError(
            "unsupported framebuffer provider schema"
        )

    if manifest.get("provider") != PROVIDER_NAME:
        raise TreeForgeFramebufferProviderError(
            "framebuffer provider identity changed"
        )

    if manifest.get("version") != PROVIDER_VERSION:
        raise TreeForgeFramebufferProviderError(
            "framebuffer provider version mismatch: "
            f"expected={PROVIDER_VERSION} "
            f"actual={manifest.get('version')}"
        )

    if manifest.get("abi") != PROVIDER_ABI:
        raise TreeForgeFramebufferProviderError(
            "framebuffer provider ABI mismatch: "
            f"expected={PROVIDER_ABI} "
            f"actual={manifest.get('abi')}"
        )

    userspace = manifest.get("userspace")

    if not isinstance(userspace, dict):
        raise TreeForgeFramebufferProviderError(
            "framebuffer provider userspace contract is missing"
        )

    primitives_path = _relative_payload(
        root,
        userspace.get("primitives"),
        "primitives",
    )
    transport_path = _relative_payload(
        root,
        userspace.get("transport"),
        "transport",
    )

    return FramebufferProvider(
        root=root,
        primitives_source=primitives_path.read_text(
            encoding="utf-8"
        ).removesuffix("\n"),
        transport_source=transport_path.read_text(
            encoding="utf-8"
        ).removesuffix("\n"),
    )
