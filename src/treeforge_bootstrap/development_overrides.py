from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Callable


class TreeForgeDevelopmentOverrideError(
    RuntimeError
):
    pass


SCHEMA = (
    "treeforge.bootstrap."
    "development-providers.v1"
)

PROVIDERS = (
    "kernel",
    "framebuffer",
    "menu",
)


def _config_home() -> Path:
    override = os.environ.get(
        "XDG_CONFIG_HOME",
        "",
    ).strip()

    if override:
        return (
            Path(override)
            .expanduser()
            .resolve()
        )

    return (
        Path.home()
        / ".config"
    )


def config_file() -> Path:
    return (
        _config_home()
        / "treeforge"
        / "bootstrap"
        / "development-providers.json"
    )


def _load() -> dict[str, str]:
    path = config_file()

    if not path.is_file():
        return {}

    try:
        data = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise TreeForgeDevelopmentOverrideError(
            "development-provider config "
            f"is invalid: {path}"
        ) from error

    if (
        not isinstance(data, dict)
        or data.get("schema") != SCHEMA
        or not isinstance(
            data.get("providers"),
            dict,
        )
    ):
        raise TreeForgeDevelopmentOverrideError(
            "development-provider config "
            f"contract changed: {path}"
        )

    result: dict[str, str] = {}

    for name, value in (
        data["providers"].items()
    ):
        if (
            name in PROVIDERS
            and isinstance(value, str)
            and value.strip()
        ):
            result[name] = value

    return result


def _write(
    providers: dict[str, str],
) -> None:
    path = config_file()

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = path.with_name(
        "." + path.name + ".tmp"
    )

    temporary.write_text(
        json.dumps(
            {
                "schema": SCHEMA,
                "providers": providers,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    os.chmod(
        temporary,
        0o600,
    )

    os.replace(
        temporary,
        path,
    )


def remembered(
    name: str,
) -> Path | None:
    if name not in PROVIDERS:
        raise TreeForgeDevelopmentOverrideError(
            f"unknown development provider: {name}"
        )

    value = _load().get(name)

    if value is None:
        return None

    return (
        Path(value)
        .expanduser()
        .resolve()
    )


def remove(
    name: str,
) -> bool:
    providers = _load()

    existed = name in providers

    providers.pop(
        name,
        None,
    )

    _write(
        providers
    )

    return existed


def save(
    name: str,
    path: Path,
) -> None:
    providers = _load()

    providers[name] = str(
        path.expanduser().resolve()
    )

    _write(
        providers
    )


def resolve_requested(
    name: str,
    value: str | None,
    *,
    prompt_label: str,
) -> tuple[Path | None, bool]:
    if value is None:
        return None, False

    if value != "":
        return (
            Path(value)
            .expanduser()
            .resolve(),
            True,
        )

    saved = remembered(
        name
    )

    if saved is not None:
        return saved, False

    if not sys.stdin.isatty():
        raise TreeForgeDevelopmentOverrideError(
            f"--dev-provider-{name} has "
            "no remembered path; supply "
            "an explicit path"
        )

    raw = input(
        prompt_label + ": "
    ).strip()

    if not raw:
        raise TreeForgeDevelopmentOverrideError(
            f"{name} development-provider "
            "path is required"
        )

    return (
        Path(raw)
        .expanduser()
        .resolve(),
        True,
    )


def activate(
    name: str,
    value: str | None,
    *,
    prompt_label: str,
    validator: Callable[[Path], object],
) -> tuple[Path | None, object | None]:
    path, should_save = (
        resolve_requested(
            name,
            value,
            prompt_label=prompt_label,
        )
    )

    if path is None:
        return None, None

    result = validator(
        path
    )

    if should_save:
        save(
            name,
            path,
        )

    return path, result


__all__ = [
    "TreeForgeDevelopmentOverrideError",
    "activate",
    "config_file",
    "remembered",
    "remove",
    "resolve_requested",
    "save",
]
