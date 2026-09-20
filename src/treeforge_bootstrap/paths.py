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
