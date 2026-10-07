from __future__ import annotations

from pathlib import Path


REPOSITORY_ROOT = (
    Path(__file__).resolve().parents[2]
)

VERSION_FILE = (
    REPOSITORY_ROOT
    / "VERSION"
)


def _versions() -> dict[str, str]:
    if not VERSION_FILE.is_file():
        raise RuntimeError(
            "TreeForge VERSION file is missing: "
            f"{VERSION_FILE}"
        )

    result: dict[str, str] = {}

    for raw in VERSION_FILE.read_text(
        encoding="utf-8"
    ).splitlines():
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            raise RuntimeError(
                "invalid VERSION entry: "
                + repr(line)
            )

        key, value = line.split("=", 1)

        key = key.strip()
        value = value.strip()

        if not key or not value:
            raise RuntimeError(
                "invalid VERSION entry: "
                + repr(line)
            )

        if key in result:
            raise RuntimeError(
                "duplicate VERSION key: "
                + key
            )

        result[key] = value

    required = {
        "TREEFORGE_BOOTSTRAP_VERSION",
        "TREEFORGE_BOOT_MANAGER_VERSION",
        "TREEFORGE_RUNTIME_ABI_VERSION",
    }

    if set(result) != required:
        raise RuntimeError(
            "VERSION keys changed: "
            + repr(sorted(result))
        )

    return result


def project_version() -> str:
    return _versions()[
        "TREEFORGE_BOOTSTRAP_VERSION"
    ]


def boot_manager_version() -> str:
    return _versions()[
        "TREEFORGE_BOOT_MANAGER_VERSION"
    ]


def runtime_abi_version() -> str:
    return _versions()[
        "TREEFORGE_RUNTIME_ABI_VERSION"
    ]


def runtime_identity() -> str:
    return (
        "TreeForge Bootstrap\n"
        f"Version: {project_version()}"
    )


__all__ = (
    "VERSION_FILE",
    "boot_manager_version",
    "project_version",
    "runtime_abi_version",
    "runtime_identity",
)
