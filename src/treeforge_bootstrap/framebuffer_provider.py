from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


class TreeForgeFramebufferProviderError(RuntimeError):
    pass


PROVIDER_NAME = "treeforge_bootstrap_framebuffer"
PROVIDER_ABI = 1
PROVIDER_REPOSITORY = "TreeForgeDEV/treeforge_bootstrap_framebuffer"
PROVIDER_ARCHIVE_PREFIX = PROVIDER_NAME
PROVIDER_CACHE_ROOT = (
    Path.home()
    / ".cache"
    / "treeforge"
    / "providers"
    / PROVIDER_NAME
)
RELEASE_RE = re.compile(r"v1\.0b([0-9]+)")

_PROVIDER_OVERRIDE: Path | None = None
_RESOLVED_RELEASE: tuple[Path, str] | None = None


@dataclass(frozen=True)
class FramebufferProvider:
    root: Path
    version: str
    primitives_source: str
    transport_source: str


def configure_framebuffer_provider_override(root: Path | None) -> None:
    global _PROVIDER_OVERRIDE

    if root is None:
        _PROVIDER_OVERRIDE = None
        return

    resolved = root.expanduser().resolve()

    if not resolved.is_dir():
        raise TreeForgeFramebufferProviderError(
            "explicit TreeForge framebuffer provider root "
            f"is missing: {resolved}"
        )

    _PROVIDER_OVERRIDE = resolved


def framebuffer_provider_override() -> Path | None:
    return _PROVIDER_OVERRIDE


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _github_token() -> str | None:
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
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


def _github_request(url: str, *, token: str, accept: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "User-Agent": "TreeForge-Bootstrap/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )


def _beta_number(tag: str) -> int:
    match = RELEASE_RE.fullmatch(tag)
    if match is None:
        raise TreeForgeFramebufferProviderError(
            f"unsupported framebuffer provider release: {tag}"
        )
    return int(match.group(1))


def _published_release_tags(token: str) -> tuple[str, ...]:
    tags: list[str] = []
    page = 1

    while True:
        url = (
            "https://api.github.com/repos/"
            + PROVIDER_REPOSITORY
            + f"/releases?per_page=100&page={page}"
        )
        try:
            with urllib.request.urlopen(
                _github_request(
                    url,
                    token=token,
                    accept="application/vnd.github+json",
                ),
                timeout=60,
            ) as response:
                records = json.load(response)
        except (
            OSError,
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
        ) as error:
            raise TreeForgeFramebufferProviderError(
                "unable to enumerate TreeForge framebuffer provider releases"
            ) from error

        if not isinstance(records, list):
            raise TreeForgeFramebufferProviderError(
                "TreeForge framebuffer provider release listing is not an array"
            )

        for record in records:
            if not isinstance(record, dict):
                continue
            if record.get("draft") is True or record.get("prerelease") is True:
                continue
            tag = record.get("tag_name")
            if isinstance(tag, str) and RELEASE_RE.fullmatch(tag):
                tags.append(tag)

        if len(records) < 100:
            break
        page += 1

    unique = sorted(set(tags), key=_beta_number, reverse=True)
    if not unique:
        raise TreeForgeFramebufferProviderError(
            "TreeForge framebuffer provider has no supported published releases"
        )
    return tuple(unique)


def _release_assets(tag: str, token: str) -> dict[str, str]:
    encoded = urllib.parse.quote(tag, safe="")
    url = (
        "https://api.github.com/repos/"
        + PROVIDER_REPOSITORY
        + "/releases/tags/"
        + encoded
    )
    try:
        with urllib.request.urlopen(
            _github_request(
                url,
                token=token,
                accept="application/vnd.github+json",
            ),
            timeout=60,
        ) as response:
            release = json.load(response)
    except (
        OSError,
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
    ) as error:
        raise TreeForgeFramebufferProviderError(
            f"unable to resolve framebuffer provider release {tag}"
        ) from error

    if not isinstance(release, dict):
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider release {tag} is invalid"
        )
    if release.get("draft") is True or release.get("prerelease") is True:
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider release {tag} is not published"
        )
    if release.get("tag_name") != tag:
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider release tag changed: {tag}"
        )

    result: dict[str, str] = {}
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider release {tag} has no asset list"
        )
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        asset_url = asset.get("url")
        if isinstance(name, str) and name and isinstance(asset_url, str) and asset_url:
            result[name] = asset_url
    return result


def _download_asset(url: str, destination: Path, *, token: str) -> None:
    try:
        with urllib.request.urlopen(
            _github_request(
                url,
                token=token,
                accept="application/octet-stream",
            ),
            timeout=120,
        ) as response:
            with destination.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
    except (OSError, urllib.error.URLError, TimeoutError) as error:
        raise TreeForgeFramebufferProviderError(
            f"unable to download framebuffer provider asset: {destination.name}"
        ) from error


def _parse_sums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise TreeForgeFramebufferProviderError(
            f"unable to read framebuffer provider checksums: {path}"
        ) from error

    for raw in lines:
        if not raw.strip():
            continue
        try:
            digest, name = raw.split("  ", 1)
        except ValueError as error:
            raise TreeForgeFramebufferProviderError(
                f"invalid framebuffer provider checksum line: {raw!r}"
            ) from error
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not name
            or name in result
        ):
            raise TreeForgeFramebufferProviderError(
                f"invalid framebuffer provider checksum entry: {raw!r}"
            )
        result[name] = digest
    return result


def _provider_version(root: Path) -> str:
    version_file = root / "VERSION"
    if not version_file.is_file():
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider VERSION is missing: {version_file}"
        )
    version = version_file.read_text(encoding="utf-8").strip()
    if RELEASE_RE.fullmatch(version) is None:
        raise TreeForgeFramebufferProviderError(
            f"unsupported framebuffer provider VERSION: {version!r}"
        )
    return version


def _provider_manifest(root: Path, *, expected_version: str) -> dict[str, object]:
    manifest_path = root / "provider.json"
    if not manifest_path.is_file():
        raise TreeForgeFramebufferProviderError(
            f"TreeForge framebuffer provider manifest is missing: {manifest_path}"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TreeForgeFramebufferProviderError(
            "unable to read TreeForge framebuffer provider manifest"
        ) from error
    if not isinstance(manifest, dict):
        raise TreeForgeFramebufferProviderError(
            "TreeForge framebuffer provider manifest is not an object"
        )
    if manifest.get("schema_version") != 1:
        raise TreeForgeFramebufferProviderError(
            "unsupported framebuffer provider schema"
        )
    if manifest.get("provider") != PROVIDER_NAME:
        raise TreeForgeFramebufferProviderError(
            "framebuffer provider identity changed"
        )
    if manifest.get("version") != expected_version:
        raise TreeForgeFramebufferProviderError(
            "framebuffer provider version mismatch: "
            f"expected={expected_version} actual={manifest.get('version')}"
        )
    if manifest.get("abi") != PROVIDER_ABI:
        raise TreeForgeFramebufferProviderError(
            "framebuffer provider ABI mismatch: "
            f"expected={PROVIDER_ABI} actual={manifest.get('abi')}"
        )
    return manifest


def _verify_sums(root: Path) -> None:
    sums_path = root / "SHA256SUMS"
    if not sums_path.is_file():
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider SHA256SUMS is missing: {sums_path}"
        )
    sums = _parse_sums(sums_path)
    if "provider.json" not in sums or "VERSION" not in sums:
        raise TreeForgeFramebufferProviderError(
            "framebuffer provider checksums are missing provider metadata"
        )
    for relative, expected in sums.items():
        path = root / relative
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise TreeForgeFramebufferProviderError(
                f"framebuffer provider checksum path escapes root: {relative}"
            )
        if not path.is_file():
            raise TreeForgeFramebufferProviderError(
                f"framebuffer provider checksum payload is missing: {path}"
            )
        actual = _sha256(path)
        if actual != expected:
            raise TreeForgeFramebufferProviderError(
                f"framebuffer provider checksum mismatch: {relative}"
            )


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
        or any(character not in "0123456789abcdef" for character in expected_sha256)
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


def _verify_provider_root(root: Path, *, expected_version: str) -> dict[str, object]:
    actual_version = _provider_version(root)
    if actual_version != expected_version:
        raise TreeForgeFramebufferProviderError(
            "framebuffer provider VERSION mismatch: "
            f"expected={expected_version} actual={actual_version}"
        )
    manifest = _provider_manifest(root, expected_version=expected_version)
    _verify_sums(root)
    userspace = manifest.get("userspace")
    if not isinstance(userspace, dict):
        raise TreeForgeFramebufferProviderError(
            "framebuffer provider userspace contract is missing"
        )
    _relative_payload(root, userspace.get("primitives"), "primitives")
    _relative_payload(root, userspace.get("transport"), "transport")
    return manifest


def _safe_extract_release(archive: Path, destination: Path) -> Path:
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
                    or member_path.parts[0] != PROVIDER_ARCHIVE_PREFIX
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
            bundle.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as error:
        raise TreeForgeFramebufferProviderError(
            "unable to extract released TreeForge framebuffer provider"
        ) from error

    root = destination / PROVIDER_ARCHIVE_PREFIX
    if not root.is_dir():
        raise TreeForgeFramebufferProviderError(
            "released framebuffer provider archive root is missing"
        )
    return root


def _materialize_release_provider() -> tuple[Path, str]:
    global _RESOLVED_RELEASE

    if _RESOLVED_RELEASE is not None:
        root, version = _RESOLVED_RELEASE
        _verify_provider_root(root, expected_version=version)
        return root, version

    token = _github_token()
    if token is None:
        raise TreeForgeFramebufferProviderError(
            "TreeForge framebuffer provider is private. Authenticate with "
            "`gh auth login`, or set GH_TOKEN / GITHUB_TOKEN."
        )

    version = _published_release_tags(token)[0]
    print(
        "[provider:treeforge_bootstrap_framebuffer] "
        f"RESOLVE latest published release: {version}"
    )
    cache = PROVIDER_CACHE_ROOT / version

    if cache.is_dir():
        try:
            _verify_provider_root(cache, expected_version=version)
            print(
                "[provider:treeforge_bootstrap_framebuffer] "
                f"VERIFY cache: {cache}"
            )
            _RESOLVED_RELEASE = (cache, version)
            return cache, version
        except TreeForgeFramebufferProviderError:
            shutil.rmtree(cache)

    assets = _release_assets(version, token)
    archive_name = f"treeforge-bootstrap-framebuffer-{version}-provider.tar.xz"
    sidecar_name = f"{archive_name}.sha256"
    required = {
        "provider.json",
        "SHA256SUMS",
        archive_name,
        sidecar_name,
    }
    missing = sorted(required - set(assets))
    if missing:
        raise TreeForgeFramebufferProviderError(
            f"framebuffer provider {version} is missing release assets: {missing!r}"
        )

    PROVIDER_CACHE_ROOT.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix=f".{version}.partial-",
        dir=PROVIDER_CACHE_ROOT,
    ) as raw:
        temporary = Path(raw)
        for name in sorted(required):
            _download_asset(assets[name], temporary / name, token=token)

        metadata_sums = _parse_sums(temporary / "SHA256SUMS")
        expected_metadata = metadata_sums.get("provider.json")
        if expected_metadata is None:
            raise TreeForgeFramebufferProviderError(
                f"framebuffer provider {version} SHA256SUMS lacks provider.json"
            )
        if _sha256(temporary / "provider.json") != expected_metadata:
            raise TreeForgeFramebufferProviderError(
                f"framebuffer provider {version} metadata identity mismatch"
            )
        metadata = _provider_manifest(temporary, expected_version=version)
        if metadata.get("abi") != PROVIDER_ABI:
            raise TreeForgeFramebufferProviderError(
                f"framebuffer provider {version} ABI is incompatible"
            )

        sidecar = (temporary / sidecar_name).read_text(encoding="utf-8").strip()
        try:
            expected_archive, recorded_name = sidecar.split("  ", 1)
        except ValueError as error:
            raise TreeForgeFramebufferProviderError(
                f"framebuffer provider {version} archive checksum is invalid"
            ) from error
        if recorded_name != archive_name or _sha256(temporary / archive_name) != expected_archive:
            raise TreeForgeFramebufferProviderError(
                f"framebuffer provider {version} archive identity mismatch"
            )

        extracted = _safe_extract_release(
            temporary / archive_name,
            temporary / "extract",
        )
        if _sha256(extracted / "provider.json") != _sha256(temporary / "provider.json"):
            raise TreeForgeFramebufferProviderError(
                f"framebuffer provider {version} archive metadata mismatch"
            )
        if _sha256(extracted / "SHA256SUMS") != _sha256(temporary / "SHA256SUMS"):
            raise TreeForgeFramebufferProviderError(
                f"framebuffer provider {version} archive checksums mismatch"
            )
        _verify_provider_root(extracted, expected_version=version)

        replacement = PROVIDER_CACHE_ROOT / f".{version}.new-{os.getpid()}"
        if replacement.exists():
            shutil.rmtree(replacement)
        shutil.copytree(extracted, replacement)
        _verify_provider_root(replacement, expected_version=version)
        if cache.exists():
            shutil.rmtree(cache)
        replacement.replace(cache)

    _verify_provider_root(cache, expected_version=version)
    print(
        "[provider:treeforge_bootstrap_framebuffer] "
        f"MATERIALIZE: {cache}"
    )
    _RESOLVED_RELEASE = (cache, version)
    return cache, version


def _provider_root() -> tuple[Path, str, bool]:
    if _PROVIDER_OVERRIDE is not None:
        version = _provider_version(_PROVIDER_OVERRIDE)
        _verify_provider_root(_PROVIDER_OVERRIDE, expected_version=version)
        return _PROVIDER_OVERRIDE, version, True

    root, version = _materialize_release_provider()
    return root, version, False


def load_framebuffer_provider() -> FramebufferProvider:
    root, version, _explicit = _provider_root()
    manifest = _verify_provider_root(root, expected_version=version)
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
        version=version,
        primitives_source=primitives_path.read_text(encoding="utf-8").removesuffix("\n"),
        transport_source=transport_path.read_text(encoding="utf-8").removesuffix("\n"),
    )


__all__ = [
    "FramebufferProvider",
    "TreeForgeFramebufferProviderError",
    "configure_framebuffer_provider_override",
    "framebuffer_provider_override",
    "load_framebuffer_provider",
]
