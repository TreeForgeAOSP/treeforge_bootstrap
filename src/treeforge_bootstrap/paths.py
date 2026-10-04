from pathlib import Path

REPOSITORY_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

PROJECT_ROOT = REPOSITORY_ROOT

INITRAMFS = (
    REPOSITORY_ROOT
    / "runtime"
    / "initramfs"
)

INITRAMFS_ROOT = (
    INITRAMFS
    / "root"
)

INITRAMFS_SRC = (
    INITRAMFS
    / "src"
)

WORK = (
    REPOSITORY_ROOT
    / "work"
)

OUT = (
    REPOSITORY_ROOT
    / "out"
    / "tangorpro"
)

SMOKE = (
    REPOSITORY_ROOT
    / ".smoke"
)

PROVIDERS = (
    REPOSITORY_ROOT
    / "providers"
)


# Default B3 retains the existing paths.
import os as _tfb_os
import sys as _tfb_sys

_tfb_selected = []
_tfb_args = _tfb_sys.argv[1:]

for _i, _arg in enumerate(_tfb_args):
    if _arg == "--profile":
        if _i + 1 >= len(_tfb_args):
            raise ValueError("--profile requires a value")
        _tfb_selected.append(_tfb_args[_i + 1])
    elif _arg.startswith("--profile="):
        _tfb_selected.append(_arg.split("=", 1)[1])

if len(_tfb_selected) > 1:
    raise ValueError("Duplicate --profile")

_tfb_env = _tfb_os.environ.get("TREEFORGE_BOOTSTRAP_PROFILE")

if _tfb_env and _tfb_selected and _tfb_env != _tfb_selected[0]:
    raise ValueError("Environment and CLI profiles differ")

BUILD_PROFILE = (
    _tfb_selected[0] if _tfb_selected
    else _tfb_env or "treeforge-default"
)

if BUILD_PROFILE not in ("treeforge-default", "treeforge-chromiumos"):
    raise ValueError("Unsupported Bootstrap profile: " + BUILD_PROFILE)

if BUILD_PROFILE == "treeforge-chromiumos":
    OUT = OUT / "profiles" / BUILD_PROFILE
    WORK = WORK / "profiles" / BUILD_PROFILE
