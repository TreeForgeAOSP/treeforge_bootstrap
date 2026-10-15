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


class TreeForgeMenuProviderError(RuntimeError):
    pass


PROVIDER_NAME = "treeforge_bootstrap_menu"
PROVIDER_ABI = 1
PROVIDER_REPOSITORY = "TreeForgeAOSP/treeforge_bootstrap_menu"
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
class MenuProvider:
    root: Path
    version: str
    boot_manager_version: str
    abi: int
    default_profile_path: Path
    core_source: str
    ui_source: str
    touch_source: str
    controller_source: str


def configure_menu_provider_override(root: Path | None) -> None:
    global _PROVIDER_OVERRIDE
    if root is None:
        _PROVIDER_OVERRIDE = None
        return
    resolved = root.expanduser().resolve()
    if not resolved.is_dir():
        raise TreeForgeMenuProviderError(
            "explicit TreeForge menu provider root is missing: "
            f"{resolved}"
        )
    _PROVIDER_OVERRIDE = resolved


def menu_provider_override() -> Path | None:
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


def _github_request(
    url: str,
    *,
    token: str | None,
    accept: str,
) -> urllib.request.Request:
    headers = {
        "Accept": accept,
        "User-Agent": "TreeForge-Bootstrap/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    if token:
        headers["Authorization"] = (
            f"Bearer {token}"
        )

    return urllib.request.Request(
        url,
        headers=headers,
    )

def _beta_number(tag: str) -> int:
    match = RELEASE_RE.fullmatch(tag)
    if match is None:
        raise TreeForgeMenuProviderError(
            f"unsupported menu provider release: {tag}"
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
                _github_request(url, token=token, accept="application/vnd.github+json"),
                timeout=60,
            ) as response:
                records = json.load(response)
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise TreeForgeMenuProviderError(
                "unable to enumerate TreeForge menu provider releases"
            ) from error
        if not isinstance(records, list):
            raise TreeForgeMenuProviderError(
                "TreeForge menu provider release listing is not an array"
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
        raise TreeForgeMenuProviderError(
            "TreeForge menu provider has no supported published releases"
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
            _github_request(url, token=token, accept="application/vnd.github+json"),
            timeout=60,
        ) as response:
            release = json.load(response)
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise TreeForgeMenuProviderError(
            f"unable to resolve menu provider release {tag}"
        ) from error
    if not isinstance(release, dict):
        raise TreeForgeMenuProviderError(f"menu provider release {tag} is invalid")
    if release.get("draft") is True or release.get("prerelease") is True:
        raise TreeForgeMenuProviderError(f"menu provider release {tag} is not published")
    if release.get("tag_name") != tag:
        raise TreeForgeMenuProviderError(f"menu provider release tag changed: {tag}")
    result: dict[str, str] = {}
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise TreeForgeMenuProviderError(f"menu provider release {tag} has no asset list")
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
            _github_request(url, token=token, accept="application/octet-stream"),
            timeout=120,
        ) as response:
            with destination.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
    except (OSError, urllib.error.URLError, TimeoutError) as error:
        raise TreeForgeMenuProviderError(
            f"unable to download menu provider asset: {destination.name}"
        ) from error


def _parse_versions(root: Path) -> dict[str, str]:
    path = root / "VERSION"
    if not path.is_file():
        raise TreeForgeMenuProviderError(f"menu provider VERSION is missing: {path}")
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise TreeForgeMenuProviderError(f"invalid menu VERSION entry: {line!r}")
        key, value = line.split("=", 1)
        key = key.strip(); value = value.strip()
        if not key or not value or key in result:
            raise TreeForgeMenuProviderError(f"invalid menu VERSION entry: {line!r}")
        result[key] = value
    required = {
        "TREEFORGE_BOOT_MENU_VERSION",
        "TREEFORGE_BOOT_MANAGER_VERSION",
        "TREEFORGE_MENU_ABI",
    }
    if set(result) != required:
        raise TreeForgeMenuProviderError(
            "menu VERSION keys changed: " + repr(sorted(result))
        )
    if RELEASE_RE.fullmatch(result["TREEFORGE_BOOT_MENU_VERSION"]) is None:
        raise TreeForgeMenuProviderError("unsupported menu provider VERSION")
    if RELEASE_RE.fullmatch(result["TREEFORGE_BOOT_MANAGER_VERSION"]) is None:
        raise TreeForgeMenuProviderError("unsupported Boot Manager VERSION")
    if result["TREEFORGE_MENU_ABI"] != str(PROVIDER_ABI):
        raise TreeForgeMenuProviderError("menu provider ABI changed")
    return result


def _provider_version(root: Path) -> str:
    return _parse_versions(root)["TREEFORGE_BOOT_MENU_VERSION"]


def _parse_sums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise TreeForgeMenuProviderError(f"unable to read menu provider checksums: {path}") from error
    for raw in lines:
        if not raw.strip():
            continue
        try:
            digest, name = raw.split("  ", 1)
        except ValueError as error:
            raise TreeForgeMenuProviderError(f"invalid menu provider checksum line: {raw!r}") from error
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not name
            or name in result
        ):
            raise TreeForgeMenuProviderError(f"invalid menu provider checksum entry: {raw!r}")
        result[name] = digest
    return result


def _provider_manifest(root: Path, *, expected_version: str) -> dict[str, object]:
    path = root / "provider.json"
    if not path.is_file():
        raise TreeForgeMenuProviderError(f"TreeForge menu provider manifest is missing: {path}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TreeForgeMenuProviderError("unable to read TreeForge menu provider manifest") from error
    if not isinstance(manifest, dict):
        raise TreeForgeMenuProviderError("TreeForge menu provider manifest is not an object")
    if manifest.get("schema_version") != 1:
        raise TreeForgeMenuProviderError("unsupported menu provider schema")
    if manifest.get("provider") != PROVIDER_NAME:
        raise TreeForgeMenuProviderError("menu provider identity changed")
    if manifest.get("version") != expected_version:
        raise TreeForgeMenuProviderError(
            "menu provider version mismatch: "
            f"expected={expected_version} actual={manifest.get('version')}"
        )
    if manifest.get("abi") != PROVIDER_ABI:
        raise TreeForgeMenuProviderError("menu provider ABI is incompatible")
    components = manifest.get("component_versions")
    if not isinstance(components, dict):
        raise TreeForgeMenuProviderError("menu provider component versions are missing")
    boot_manager = components.get("boot_manager")
    if not isinstance(boot_manager, str) or RELEASE_RE.fullmatch(boot_manager) is None:
        raise TreeForgeMenuProviderError("menu provider Boot Manager version is invalid")
    if (root / "VERSION").is_file():
        versions = _parse_versions(root)
        if boot_manager != versions["TREEFORGE_BOOT_MANAGER_VERSION"]:
            raise TreeForgeMenuProviderError("menu provider Boot Manager version mismatch")
    return manifest


def _verify_sums(root: Path) -> None:
    path = root / "SHA256SUMS"
    if not path.is_file():
        raise TreeForgeMenuProviderError(f"menu provider SHA256SUMS is missing: {path}")
    sums = _parse_sums(path)
    for relative, expected in sums.items():
        item = root / relative
        if not item.is_file():
            raise TreeForgeMenuProviderError(f"menu provider checksum path is missing: {relative}")
        actual = _sha256(item)
        if actual != expected:
            raise TreeForgeMenuProviderError(
                f"menu provider checksum mismatch: {relative}: {actual} != {expected}"
            )


def _relative_payload(root: Path, record: object, field: str) -> Path:
    if not isinstance(record, dict):
        raise TreeForgeMenuProviderError(f"menu provider {field} contract is missing")
    raw_path = record.get("path")
    expected_sha256 = record.get("sha256")
    if not isinstance(raw_path, str) or not raw_path:
        raise TreeForgeMenuProviderError(f"menu provider {field} path is invalid")
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise TreeForgeMenuProviderError(f"menu provider {field} sha256 is invalid")
    relative = Path(raw_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise TreeForgeMenuProviderError(f"menu provider {field} path escapes provider root")
    path = root / relative
    if not path.is_file():
        raise TreeForgeMenuProviderError(f"menu provider {field} payload is missing: {path}")
    actual = _sha256(path)
    if actual != expected_sha256:
        raise TreeForgeMenuProviderError(
            f"menu provider {field} identity changed: {actual} != {expected_sha256}"
        )
    return path


def _verify_provider_root(root: Path, *, expected_version: str) -> dict[str, object]:
    actual_version = _provider_version(root)
    if actual_version != expected_version:
        raise TreeForgeMenuProviderError(
            f"menu provider VERSION mismatch: expected={expected_version} actual={actual_version}"
        )
    manifest = _provider_manifest(root, expected_version=expected_version)
    _verify_sums(root)
    profile = manifest.get("profile")
    userspace = manifest.get("userspace")
    if not isinstance(profile, dict) or not isinstance(userspace, dict):
        raise TreeForgeMenuProviderError("menu provider payload contract is incomplete")
    _relative_payload(root, profile.get("default"), "default profile")
    for name in ("core", "ui", "touch", "controller"):
        _relative_payload(root, userspace.get(name), name)
    return manifest


def _safe_extract_release(archive: Path, destination: Path) -> Path:
    try:
        with tarfile.open(archive, mode="r:xz") as bundle:
            members = bundle.getmembers()
            if not members:
                raise TreeForgeMenuProviderError("released menu provider archive is empty")
            for member in members:
                member_path = Path(member.name)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or not member_path.parts
                    or member_path.parts[0] != PROVIDER_ARCHIVE_PREFIX
                ):
                    raise TreeForgeMenuProviderError(
                        f"released menu provider archive has unsafe member: {member.name}"
                    )
                if member.issym() or member.islnk():
                    raise TreeForgeMenuProviderError(
                        f"released menu provider archive has link member: {member.name}"
                    )
            bundle.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as error:
        raise TreeForgeMenuProviderError("unable to extract released TreeForge menu provider") from error
    root = destination / PROVIDER_ARCHIVE_PREFIX
    if not root.is_dir():
        raise TreeForgeMenuProviderError("released menu provider archive root is missing")
    return root


def _materialize_release_provider() -> tuple[Path, str]:
    global _RESOLVED_RELEASE
    if _RESOLVED_RELEASE is not None:
        root, version = _RESOLVED_RELEASE
        _verify_provider_root(root, expected_version=version)
        return root, version
    token = _github_token()
    version = _published_release_tags(token)[0]
    print(f"[provider:{PROVIDER_NAME}] RESOLVE latest published release: {version}")
    cache = PROVIDER_CACHE_ROOT / version
    if cache.is_dir():
        try:
            _verify_provider_root(cache, expected_version=version)
            print(f"[provider:{PROVIDER_NAME}] VERIFY cache: {cache}")
            _RESOLVED_RELEASE = (cache, version)
            return cache, version
        except TreeForgeMenuProviderError:
            shutil.rmtree(cache)
    assets = _release_assets(version, token)
    archive_name = f"treeforge-bootstrap-menu-{version}-provider.tar.xz"
    sidecar_name = f"{archive_name}.sha256"
    required = {"provider.json", "SHA256SUMS", archive_name, sidecar_name}
    missing = sorted(required - set(assets))
    if missing:
        raise TreeForgeMenuProviderError(
            f"menu provider {version} is missing release assets: {missing!r}"
        )
    PROVIDER_CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{version}.partial-", dir=PROVIDER_CACHE_ROOT) as raw:
        temporary = Path(raw)
        for name in sorted(required):
            _download_asset(assets[name], temporary / name, token=token)
        metadata_sums = _parse_sums(temporary / "SHA256SUMS")
        expected_metadata = metadata_sums.get("provider.json")
        if expected_metadata is None:
            raise TreeForgeMenuProviderError(f"menu provider {version} SHA256SUMS lacks provider.json")
        if _sha256(temporary / "provider.json") != expected_metadata:
            raise TreeForgeMenuProviderError(f"menu provider {version} metadata identity mismatch")
        _provider_manifest(temporary, expected_version=version)
        sidecar = (temporary / sidecar_name).read_text(encoding="utf-8").strip()
        try:
            expected_archive, recorded_name = sidecar.split("  ", 1)
        except ValueError as error:
            raise TreeForgeMenuProviderError(f"menu provider {version} archive checksum is invalid") from error
        if recorded_name != archive_name or _sha256(temporary / archive_name) != expected_archive:
            raise TreeForgeMenuProviderError(f"menu provider {version} archive identity mismatch")
        extracted = _safe_extract_release(temporary / archive_name, temporary / "extract")
        if _sha256(extracted / "provider.json") != _sha256(temporary / "provider.json"):
            raise TreeForgeMenuProviderError(f"menu provider {version} archive metadata mismatch")
        if _sha256(extracted / "SHA256SUMS") != _sha256(temporary / "SHA256SUMS"):
            raise TreeForgeMenuProviderError(f"menu provider {version} archive checksums mismatch")
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
    print(f"[provider:{PROVIDER_NAME}] MATERIALIZE: {cache}")
    _RESOLVED_RELEASE = (cache, version)
    return cache, version


def _provider_root() -> tuple[Path, str, bool]:
    if _PROVIDER_OVERRIDE is not None:
        version = _provider_version(_PROVIDER_OVERRIDE)
        _verify_provider_root(_PROVIDER_OVERRIDE, expected_version=version)
        return _PROVIDER_OVERRIDE, version, True
    root, version = _materialize_release_provider()
    return root, version, False


def load_menu_provider() -> MenuProvider:
    root, version, _explicit = _provider_root()
    manifest = _verify_provider_root(root, expected_version=version)
    versions = _parse_versions(root)
    profile = manifest.get("profile")
    userspace = manifest.get("userspace")
    if not isinstance(profile, dict) or not isinstance(userspace, dict):
        raise TreeForgeMenuProviderError("menu provider payload contract is incomplete")
    default_profile = _relative_payload(root, profile.get("default"), "default profile")
    paths = {
        name: _relative_payload(root, userspace.get(name), name)
        for name in ("core", "ui", "touch", "controller")
    }
    return MenuProvider(
        root=root,
        version=version,
        boot_manager_version=versions["TREEFORGE_BOOT_MANAGER_VERSION"],
        abi=PROVIDER_ABI,
        default_profile_path=default_profile,
        core_source=paths["core"].read_text(encoding="utf-8"),
        ui_source=paths["ui"].read_text(encoding="utf-8"),
        touch_source=paths["touch"].read_text(encoding="utf-8"),
        controller_source=paths["controller"].read_text(encoding="utf-8"),
    )


__all__ = [
    "MenuProvider",
    "TreeForgeMenuProviderError",
    "configure_menu_provider_override",
    "load_menu_provider",
    "menu_provider_override",
]
