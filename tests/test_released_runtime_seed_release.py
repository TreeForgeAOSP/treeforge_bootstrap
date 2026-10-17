from __future__ import annotations

import json
from pathlib import Path

from treeforge_bootstrap import (
    released_runtime_provider,
)


ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


def _version() -> str:
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


def test_development_version_is_distinct_from_seed_release():
    data = json.loads(
        (
            ROOT
            / "provider-contract.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    assert _version() == "v1.0b2"

    assert (
        data["runtime"][
            "canonical_seed_release"
        ]
        == "v1.0b1"
    )

    contract = (
        released_runtime_provider
        ._contract()
    )

    assert contract["release"] == "v1.0b1"


def test_runtime_seed_does_not_derive_from_build_version():
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
