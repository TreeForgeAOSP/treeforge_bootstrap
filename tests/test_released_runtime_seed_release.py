from __future__ import annotations

from pathlib import Path

from treeforge_bootstrap import (
    released_runtime_provider,
)


ROOT = Path(__file__).resolve().parents[1]


def _build_version() -> str:
    for raw in (
        ROOT / "VERSION"
    ).read_text(
        encoding="utf-8"
    ).splitlines():
        key, separator, value = raw.partition("=")

        if (
            separator
            and key.strip()
            == "TREEFORGE_BOOTSTRAP_VERSION"
        ):
            return value.strip()

    raise AssertionError(
        "Bootstrap version missing"
    )


def test_build_version_and_seed_release_are_separate():
    assert _build_version() == "v1.0b2"

    seed = (
        released_runtime_provider
        ._contract()
    )

    assert seed["release"] == "v1.0b1"
    assert seed["release"] != _build_version()


def test_seed_matches_published_v1_0b1_identity():
    seed = (
        released_runtime_provider
        ._contract()
    )

    assert (
        seed["asset"]
        == "treeforge-bootstrap-tangorpro-android15-runtime.tar.xz"
    )

    assert (
        seed["archive_bytes"]
        == 12240128
    )

    assert (
        seed["archive_sha256"]
        == "c45078944b66086dff77a9a20b3560fbb1c62c5abbb4153cf5cfd78d39162a71"
    )

    assert (
        seed["cpio_bytes"]
        == 15592816
    )

    assert (
        seed["cpio_sha256"]
        == "d9c186b16039b30b3a25afbd8eb34e725eaa56a55597fd000e1d50207d011fc1"
    )


def test_seed_is_not_derived_from_build_version():
    source = (
        ROOT
        / "src"
        / "treeforge_bootstrap"
        / "released_runtime_provider.py"
    ).read_text(
        encoding="utf-8"
    )

    assert "VERSION_FILE" not in source
    assert "_release_tag" not in source

    assert (
        "TREEFORGE_BOOTSTRAP_VERSION"
        not in source
    )
