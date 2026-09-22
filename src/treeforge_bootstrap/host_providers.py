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


REPOSITORY = "TreeForgeAOSP/treeforge_toolchain"

HOST_CACHE_ROOT = (
    Path.home()
    / ".cache"
    / "treeforge"
    / "android-host-provider"
)

KERNEL_CACHE_ROOT = (
    Path.home()
    / ".cache"
    / "treeforge"
    / "providers"
    / "kernel"
)

KERNEL_RELEASE = "android-15.0.0_r0.94"

CLANG_PROVIDER = (
    KERNEL_CACHE_ROOT
    / KERNEL_RELEASE
    / "clang"
)

CLANG_REVISION = (
    "7775eb113f960bc69a780b621d03a715914d4bca"
)

CLANG_REPOSITORY = (
    "https://android.googlesource.com/"
    "platform/prebuilts/clang/host/linux-x86"
)

CLANG_RELATIVE = Path(
    "clang-r487747c/bin/clang"
)


class HostProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class HostProvider:
    name: str
    release: str
    tag: str
    executables: dict[str, tuple[str, str]]


HOST_PROVIDERS = {
    "android-image-tools": HostProvider(
        name="android-image-tools",
        release="android-15.0.0_r36-linux-x86_64",
        tag="android-image-tools/android-15.0.0_r36-1",
        executables={
            "mkbootimg": (
                "bin/mkbootimg",
                "c610d80ac3cd1e2de3ab535ecbf88b27"
                "e5539fc639fa865e8ee9911273b72d58",
            ),
            "unpack_bootimg": (
                "bin/unpack_bootimg",
                "ff1339356d3ec46b855dab87388cd11e"
                "3e5de15a9bf8c4dbc8aa6653a2704278",
            ),
        },
    ),
    "avbtool": HostProvider(
        name="avbtool",
        release="android-15.0.0_r36-linux-x86_64",
        tag="avbtool/android-15.0.0_r36-2",
        executables={
            "avbtool": (
                "bin/avbtool",
                "ff418b18d3b3b48dea2201124f62fc46"
                "9c677bba93ca134829673254357ae17b",
            ),
        },
    ),
    "treeforge-adb": HostProvider(
        name="treeforge-adb",
        release="android-15.0.0_r36-linux-x86_64",
        tag="treeforge-adb/android-15.0.0_r36-1",
        executables={
            "adb": (
                "bin/adb",
                "b8762103831406816bedc3b8d9c32146"
                "be2ea9a87b9e468d38546640de5c500b",
            ),
        },
    ),
    "treeforge-fastboot": HostProvider(
        name="treeforge-fastboot",
        release="android-15.0.0_r36-linux-x86_64",
        tag="treeforge-fastboot/android-15.0.0_r36-1",
        executables={
            "fastboot": (
                "bin/fastboot",
                "340c23293ee6f3fb60d689e8c2042d23"
                "ef969d511981c2df3c423973d6ff4898",
            ),
        },
    ),
}


TOOL_PROVIDER = {
    "adb": "treeforge-adb",
    "mkbootimg": "android-image-tools",
    "unpack_bootimg": "android-image-tools",
    "avbtool": "avbtool",
    "fastboot": "treeforge-fastboot",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def _run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    if result.returncode != 0:
        raise HostProviderError(
            f"command failed ({result.returncode}): "
            f"{' '.join(args)}\n{result.stdout}"
        )

    return result


def _git_output(
    root: Path,
    *args: str,
) -> str:
    return _run(
        ["git", "-C", str(root), *args]
    ).stdout.strip()


def _verify_clang_provider(root: Path) -> Path:
    if not root.is_dir():
        raise HostProviderError(
            f"clang provider missing: {root}"
        )

    try:
        revision = _git_output(
            root,
            "rev-parse",
            "HEAD",
        )
    except HostProviderError as exc:
        raise HostProviderError(
            f"clang provider is not a valid "
            f"Git checkout: {root}"
        ) from exc

    if revision != CLANG_REVISION:
        raise HostProviderError(
            "clang provider revision mismatch\n"
            f"expected={CLANG_REVISION}\n"
            f"actual={revision}"
        )

    dirty = _git_output(
        root,
        "status",
        "--porcelain",
    )

    if dirty:
        raise HostProviderError(
            f"clang provider cache is dirty: {root}"
        )

    attrs = root / ".gitattributes"

    if attrs.is_file():
        text = attrs.read_text(
            encoding="utf-8",
            errors="replace",
        )

        if "filter=lfs" in text:
            raise HostProviderError(
                "clang provider unexpectedly "
                "requires Git LFS"
            )

    clang = root / CLANG_RELATIVE

    if not clang.is_file():
        raise HostProviderError(
            f"clang executable missing: {clang}"
        )

    if not os.access(clang, os.X_OK):
        raise HostProviderError(
            f"clang executable bit missing: {clang}"
        )

    return clang


def ensure_clang() -> Path:
    try:
        return _verify_clang_provider(
            CLANG_PROVIDER
        )
    except HostProviderError:
        pass

    CLANG_PROVIDER.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = (
        CLANG_PROVIDER.parent
        / f".clang.partial-{os.getpid()}"
    )

    replaced = (
        CLANG_PROVIDER.parent
        / f".clang.replaced-{os.getpid()}"
    )

    for path in (temporary, replaced):
        if path.exists():
            shutil.rmtree(path)

    env = os.environ.copy()
    env["GIT_LFS_SKIP_SMUDGE"] = "1"

    temporary.mkdir(parents=True)

    cache_moved = False

    try:
        _run(
            ["git", "init", "-q"],
            cwd=temporary,
            env=env,
        )

        _run(
            [
                "git",
                "remote",
                "add",
                "origin",
                CLANG_REPOSITORY,
            ],
            cwd=temporary,
            env=env,
        )

        _run(
            [
                "git",
                "fetch",
                "--depth=1",
                "origin",
                CLANG_REVISION,
            ],
            cwd=temporary,
            env=env,
        )

        _run(
            [
                "git",
                "checkout",
                "--detach",
                "FETCH_HEAD",
            ],
            cwd=temporary,
            env=env,
        )

        _verify_clang_provider(temporary)

        if CLANG_PROVIDER.exists():
            CLANG_PROVIDER.rename(replaced)
            cache_moved = True

        temporary.rename(CLANG_PROVIDER)

        _verify_clang_provider(
            CLANG_PROVIDER
        )

        if cache_moved and replaced.exists():
            shutil.rmtree(replaced)

    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)

        if (
            cache_moved
            and replaced.exists()
            and not CLANG_PROVIDER.exists()
        ):
            replaced.rename(CLANG_PROVIDER)

        raise

    return _verify_clang_provider(
        CLANG_PROVIDER
    )


def _provider_cache(
    provider: HostProvider,
) -> Path:
    return (
        HOST_CACHE_ROOT
        / provider.name
        / provider.release
    )


def _payload_path(
    root: Path,
    relative: str,
) -> Path:
    packaged = (
        root
        / "payload"
        / relative
    )

    if packaged.is_file():
        return packaged

    return root / relative


def _verify_host_provider(
    provider: HostProvider,
    root: Path,
) -> None:
    if not root.is_dir():
        raise HostProviderError(
            f"{provider.name}: cache missing: "
            f"{root}"
        )

    checked = 0

    for (
        executable,
        (
            relative,
            expected,
        ),
    ) in provider.executables.items():
        path = _payload_path(
            root,
            relative,
        )

        if not path.is_file():
            raise HostProviderError(
                f"{provider.name}: missing "
                f"{relative}"
            )

        actual = sha256(path)

        if actual != expected:
            raise HostProviderError(
                f"{provider.name}: hash mismatch: "
                f"{relative}\n"
                f"expected={expected}\n"
                f"actual={actual}"
            )

        if not os.access(path, os.X_OK):
            raise HostProviderError(
                f"{provider.name}: executable "
                f"bit missing: {path}"
            )

        checked += 1

    if checked == 0:
        raise HostProviderError(
            f"{provider.name}: no executable "
            "records verified"
        )


def _request_json(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent":
                "TreeForge-Bootstrap-Provider/1",
            "Accept":
                "application/vnd.github+json",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=60,
        ) as response:
            return json.loads(
                response.read().decode(
                    "utf-8"
                )
            )
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
    ) as exc:
        raise HostProviderError(
            f"provider metadata request "
            f"failed: {url}: {exc}"
        ) from exc


def _download(
    url: str,
    destination: Path,
) -> None:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent":
                "TreeForge-Bootstrap-Provider/1",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=120,
        ) as response:
            with destination.open(
                "wb"
            ) as output:
                shutil.copyfileobj(
                    response,
                    output,
                )
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
    ) as exc:
        raise HostProviderError(
            f"provider download failed: "
            f"{url}: {exc}"
        ) from exc


def _release_assets(
    provider: HostProvider,
) -> dict[str, str]:
    encoded = urllib.parse.quote(
        provider.tag,
        safe="",
    )

    data = _request_json(
        "https://api.github.com/repos/"
        f"{REPOSITORY}/releases/tags/"
        f"{encoded}"
    )

    if data.get("tag_name") != provider.tag:
        raise HostProviderError(
            f"{provider.name}: release tag "
            "identity mismatch"
        )

    assets: dict[str, str] = {}

    for record in data.get(
        "assets",
        [],
    ):
        if not isinstance(record, dict):
            continue

        name = record.get("name")
        url = record.get(
            "browser_download_url"
        )

        if (
            isinstance(name, str)
            and name
            and isinstance(url, str)
            and url
        ):
            assets[name] = url

    return assets


def _safe_extract(
    archive: Path,
    destination: Path,
    expected_root: str,
) -> Path:
    with tarfile.open(
        archive,
        "r:xz",
    ) as handle:
        for member in handle.getmembers():
            relative = Path(member.name)

            if (
                relative.is_absolute()
                or ".." in relative.parts
                or member.issym()
                or member.islnk()
            ):
                raise HostProviderError(
                    "unsafe provider archive "
                    f"member: {member.name}"
                )

        handle.extractall(
            destination,
            filter="data",
        )

    roots = [
        path
        for path in destination.iterdir()
        if path.is_dir()
    ]

    if len(roots) != 1:
        raise HostProviderError(
            "provider archive must contain "
            "exactly one package root"
        )

    root = roots[0]

    if root.name != expected_root:
        raise HostProviderError(
            "provider package root mismatch: "
            f"expected={expected_root} "
            f"actual={root.name}"
        )

    return root


def _verify_sidecar(
    archive: Path,
    sidecar: Path,
) -> None:
    fields = sidecar.read_text(
        encoding="utf-8",
    ).strip().split()

    if len(fields) < 2:
        raise HostProviderError(
            "invalid provider SHA-256 sidecar"
        )

    expected = fields[0].lower()
    recorded_name = Path(
        fields[-1]
    ).name

    if recorded_name != archive.name:
        raise HostProviderError(
            "provider SHA-256 sidecar "
            "identity mismatch"
        )

    actual = sha256(archive)

    if actual != expected:
        raise HostProviderError(
            "provider archive SHA-256 "
            "mismatch\n"
            f"expected={expected}\n"
            f"actual={actual}"
        )


def _verify_internal_ledger(
    root: Path,
) -> None:
    ledger = root / "SHA256SUMS"

    if not ledger.is_file():
        raise HostProviderError(
            f"provider SHA256SUMS missing: "
            f"{ledger}"
        )

    checked = 0

    for raw in ledger.read_text(
        encoding="utf-8",
    ).splitlines():
        line = raw.strip()

        if not line:
            continue

        fields = line.split(
            None,
            1,
        )

        if len(fields) != 2:
            raise HostProviderError(
                "invalid SHA256SUMS record"
            )

        expected = fields[0].lower()
        relative_text = (
            fields[1].strip()
        )

        if relative_text.startswith("*"):
            relative_text = (
                relative_text[1:]
            )

        relative = Path(
            relative_text
        )

        if (
            relative.is_absolute()
            or ".." in relative.parts
        ):
            raise HostProviderError(
                "unsafe SHA256SUMS path: "
                f"{relative_text}"
            )

        path = root / relative

        if not path.is_file():
            raise HostProviderError(
                "SHA256SUMS file missing: "
                f"{relative_text}"
            )

        actual = sha256(path)

        if actual != expected:
            raise HostProviderError(
                "internal provider hash "
                f"mismatch: {relative_text}"
            )

        checked += 1

    if checked == 0:
        raise HostProviderError(
            "provider SHA256SUMS empty"
        )


def _verify_release_identity(
    provider: HostProvider,
    root: Path,
    asset: str,
) -> None:
    release_path = root / "RELEASE.json"

    if not release_path.is_file():
        raise HostProviderError(
            f"{provider.name}: "
            "RELEASE.json missing"
        )

    release = json.loads(
        release_path.read_text(
            encoding="utf-8",
        )
    )

    expected = {
        "provider": provider.name,
        "release_tag": provider.tag,
        "asset_name": asset,
    }

    for key, value in expected.items():
        if release.get(key) != value:
            raise HostProviderError(
                f"{provider.name}: "
                f"RELEASE.json {key} "
                "mismatch"
            )

    consumer_path = (
        root
        / "consumer"
        / "manifest.json"
    )

    if not consumer_path.is_file():
        raise HostProviderError(
            f"{provider.name}: consumer "
            "manifest missing"
        )

    consumer = json.loads(
        consumer_path.read_text(
            encoding="utf-8",
        )
    )

    if (
        consumer.get("schema") != 2
        or consumer.get("name")
        != provider.name
        or consumer.get("release")
        != provider.release
    ):
        raise HostProviderError(
            f"{provider.name}: consumer "
            "manifest identity mismatch"
        )


def _fetch_host_provider(
    provider: HostProvider,
) -> Path:
    cache = _provider_cache(
        provider
    )

    asset = (
        f"{provider.name}-"
        f"{provider.release}.tar.xz"
    )

    sidecar = asset + ".sha256"

    assets = _release_assets(
        provider
    )

    if asset not in assets:
        raise HostProviderError(
            f"{provider.name}: release "
            f"{provider.tag} missing "
            f"{asset}"
        )

    if sidecar not in assets:
        raise HostProviderError(
            f"{provider.name}: release "
            f"{provider.tag} missing "
            f"{sidecar}"
        )

    cache.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.TemporaryDirectory(
        prefix=(
            f".{provider.name}-download-"
        ),
        dir=cache.parent,
    ) as raw:
        temp = Path(raw)

        archive = temp / asset
        checksum = temp / sidecar
        extracted = temp / "extracted"

        extracted.mkdir()

        _download(
            assets[asset],
            archive,
        )

        _download(
            assets[sidecar],
            checksum,
        )

        _verify_sidecar(
            archive,
            checksum,
        )

        package = _safe_extract(
            archive,
            extracted,
            (
                f"{provider.name}-"
                f"{provider.release}"
            ),
        )

        _verify_internal_ledger(
            package
        )

        _verify_release_identity(
            provider,
            package,
            asset,
        )

        _verify_host_provider(
            provider,
            package,
        )

        replacement = (
            cache.parent
            / f".{cache.name}.new-"
              f"{os.getpid()}"
        )

        old = (
            cache.parent
            / f".{cache.name}.old-"
              f"{os.getpid()}"
        )

        for path in (
            replacement,
            old,
        ):
            if path.exists():
                shutil.rmtree(path)

        shutil.copytree(
            package,
            replacement,
            symlinks=False,
        )

        _verify_host_provider(
            provider,
            replacement,
        )

        moved = False

        try:
            if cache.exists():
                cache.rename(old)
                moved = True

            replacement.rename(cache)

            _verify_host_provider(
                provider,
                cache,
            )

            if moved and old.exists():
                shutil.rmtree(old)

        except Exception:
            if replacement.exists():
                shutil.rmtree(
                    replacement
                )

            if (
                moved
                and old.exists()
                and not cache.exists()
            ):
                old.rename(cache)

            raise

    return cache


def ensure_host_provider(
    name: str,
) -> Path:
    try:
        provider = HOST_PROVIDERS[
            name
        ]
    except KeyError as exc:
        raise HostProviderError(
            f"unknown host provider: {name}"
        ) from exc

    cache = _provider_cache(
        provider
    )

    try:
        _verify_host_provider(
            provider,
            cache,
        )
        return cache
    except HostProviderError:
        return _fetch_host_provider(
            provider
        )


def ensure_host_tool(name: str) -> Path:
    try:
        provider_name = (
            TOOL_PROVIDER[name]
        )
    except KeyError as exc:
        raise HostProviderError(
            f"unknown host tool: {name}"
        ) from exc

    provider = HOST_PROVIDERS[
        provider_name
    ]

    root = ensure_host_provider(
        provider_name
    )

    relative, expected = (
        provider.executables[name]
    )

    path = _payload_path(
        root,
        relative,
    )

    actual = sha256(path)

    if actual != expected:
        raise HostProviderError(
            f"{name}: executable SHA "
            "mismatch"
        )

    return path


def resolved_contract() -> dict:
    clang = ensure_clang()

    tools = {
        name: ensure_host_tool(name)
        for name in (
            "mkbootimg",
            "unpack_bootimg",
            "avbtool",
            "fastboot",
        )
    }

    return {
        "schema": 1,
        "family":
            "treeforge-bootstrap-host-providers",
        "clang": {
            "release": KERNEL_RELEASE,
            "revision": CLANG_REVISION,
            "toolchain": "clang-r487747c",
            "path": str(clang),
        },
        "tools": {
            name: {
                "path": str(path),
                "sha256": sha256(path),
                "provider":
                    TOOL_PROVIDER[name],
            }
            for name, path
            in tools.items()
        },
    }
