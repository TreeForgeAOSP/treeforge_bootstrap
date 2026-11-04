from __future__ import annotations

"""Authenticated, exact-tag GitHub release-asset download for Bootstrap.

The caller independently verifies provider metadata, checksums, archive
sidecars and extracted payloads. Do not interpret transport success as
provider acceptance or relax any existing verification.
"""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


class GitHubReleaseAssetError(RuntimeError):
    pass


def download_release_assets(
    *, repository: str, tag: str, names: set[str], destination: Path,
) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise GitHubReleaseAssetError("unsafe release repository")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+b[0-9]+", tag):
        raise GitHubReleaseAssetError("unsafe beta release tag")
    if not names or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", n) for n in names):
        raise GitHubReleaseAssetError("unsafe release asset name set")
    if not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()):
        raise GitHubReleaseAssetError("release download directory must be empty")

    gh = shutil.which("gh")
    if gh is None:
        raise GitHubReleaseAssetError("GitHub CLI (gh) is required to download release assets")

    # Each attempt uses its own disposable directory. Partial download failures
    # never become cached providers and never overwrite existing assets.
    for attempt in range(1, 4):
        with tempfile.TemporaryDirectory(prefix=".gh-assets-", dir=destination) as scratch:
            stage = Path(scratch)
            command = [gh, "release", "download", tag, "--repo", repository,
                       "--dir", str(stage)]
            for name in sorted(names):
                command.extend(["--pattern", name])
            print(f"GITHUB_ASSET_DOWNLOAD_REPOSITORY={repository} TAG={tag} "
                  f"ATTEMPT={attempt}/3", flush=True)
            result = subprocess.run(command, check=False)
            if result.returncode == 0:
                downloaded = {p.name for p in stage.iterdir()}
                if downloaded != names:
                    raise GitHubReleaseAssetError(
                        f"release asset membership mismatch: missing={sorted(names-downloaded)} "
                        f"unexpected={sorted(downloaded-names)}"
                    )
                for name in sorted(names):
                    file = stage / name
                    if (file.is_symlink() or not file.is_file()
                            or file.stat().st_nlink != 1 or file.stat().st_size == 0):
                        raise GitHubReleaseAssetError("unsafe or empty release asset: " + name)
                for name in sorted(names):
                    (stage / name).replace(destination / name)
                print(f"GITHUB_ASSET_DOWNLOAD=PASS REPOSITORY={repository} "
                      f"TAG={tag} COUNT={len(names)}", flush=True)
                return
            print(f"GITHUB_ASSET_DOWNLOAD=RETRY RC={result.returncode} "
                  f"REPOSITORY={repository} TAG={tag}", flush=True)
        if attempt < 3:
            time.sleep(attempt)
    raise GitHubReleaseAssetError(
        f"GitHub release asset download failed after 3 attempts: {repository} {tag}"
    )
