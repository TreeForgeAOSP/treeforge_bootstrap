from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import stat
import tempfile

from .host_providers import ensure_host_tool


class TreeForgeBootstrapAvbKeysetError(
    RuntimeError
):
    pass


@dataclass(
    frozen=True,
    slots=True,
)
class ResolvedAvbKeyset:
    keyset_id: str
    manifest_path: Path
    manifest_sha256: str

    device: str
    android_release: str

    boot_chain_private_key: Path
    boot_chain_private_key_sha256: str
    boot_chain_public_key_sha1: str

    root_vbmeta_private_key: Path
    root_vbmeta_private_key_sha256: str
    root_vbmeta_public_key_sha1: str


_HEX_40 = re.compile(
    r"^[0-9a-f]{40}$"
)

_HEX_64 = re.compile(
    r"^[0-9a-f]{64}$"
)


def _sha256(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for block in iter(
            lambda: stream.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def _resolve_manifest(
    path: Path,
) -> Path:
    candidate = (
        path
        .expanduser()
        .resolve()
    )

    if candidate.is_dir():
        candidate = (
            candidate
            / "keyset.json"
        )

    if not candidate.is_file():
        raise TreeForgeBootstrapAvbKeysetError(
            "AVB keyset manifest is missing: "
            f"{candidate}"
        )

    return candidate


def _private_key_path(
    *,
    root: Path,
    value: object,
    role: str,
) -> Path:
    if (
        not isinstance(value, str)
        or not value
    ):
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} private_key is invalid"
        )

    raw = Path(value)

    if raw.is_absolute():
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} private_key must be "
            "relative to the keyset directory"
        )

    candidate = (
        root
        / raw
    ).resolve()

    try:
        candidate.relative_to(
            root
        )
    except ValueError as exc:
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} private_key escapes "
            "the keyset directory"
        ) from exc

    if candidate.is_symlink():
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} private_key may not "
            "be a symlink"
        )

    if not candidate.is_file():
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} private key is missing: "
            f"{candidate}"
        )

    mode = stat.S_IMODE(
        candidate.stat().st_mode
    )

    if mode & 0o077:
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} private key permissions "
            "must not permit group/world access: "
            f"{oct(mode)}"
        )

    return candidate


def _validate_entry(
    *,
    root: Path,
    entry: object,
    role: str,
    expected_public_blob_size: int,
) -> tuple[
    Path,
    str,
    str,
]:
    if not isinstance(
        entry,
        dict,
    ):
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} key record is invalid"
        )

    private_key = _private_key_path(
        root=root,
        value=entry.get(
            "private_key"
        ),
        role=role,
    )

    expected_private_sha = (
        entry.get(
            "private_key_sha256"
        )
    )

    expected_public_sha1 = (
        entry.get(
            "public_key_sha1"
        )
    )

    if (
        not isinstance(
            expected_private_sha,
            str,
        )
        or _HEX_64.fullmatch(
            expected_private_sha
        )
        is None
    ):
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} private_key_sha256 "
            "is invalid"
        )

    if (
        not isinstance(
            expected_public_sha1,
            str,
        )
        or _HEX_40.fullmatch(
            expected_public_sha1
        )
        is None
    ):
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} public_key_sha1 "
            "is invalid"
        )

    actual_private_sha = _sha256(
        private_key
    )

    if (
        actual_private_sha
        != expected_private_sha
    ):
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} private key SHA-256 "
            "does not match keyset manifest"
        )

    avbtool = ensure_host_tool(
        "avbtool"
    )

    with tempfile.TemporaryDirectory(
        prefix="treeforge-avb-keyset-"
    ) as temporary:
        public_key = (
            Path(temporary)
            / "key.avbpubkey"
        )

        import subprocess

        result = subprocess.run(
            [
                str(avbtool),
                "extract_public_key",
                "--key",
                str(private_key),
                "--output",
                str(public_key),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise TreeForgeBootstrapAvbKeysetError(
                f"{role} AVB public-key "
                "extraction failed:\n"
                + result.stdout
            )

        payload = (
            public_key.read_bytes()
        )

    if (
        len(payload)
        != expected_public_blob_size
    ):
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} AVB public-key size "
            "does not match expected role: "
            f"{len(payload)} != "
            f"{expected_public_blob_size}"
        )

    actual_public_sha1 = (
        hashlib.sha1(
            payload
        ).hexdigest()
    )

    if (
        actual_public_sha1
        != expected_public_sha1
    ):
        raise TreeForgeBootstrapAvbKeysetError(
            f"{role} public-key identity "
            "does not match keyset manifest"
        )

    return (
        private_key,
        actual_private_sha,
        actual_public_sha1,
    )


def load_avb_keyset(
    path: Path,
) -> ResolvedAvbKeyset:
    manifest_path = (
        _resolve_manifest(
            path
        )
    )

    try:
        data = json.loads(
            manifest_path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        raise TreeForgeBootstrapAvbKeysetError(
            "unable to parse AVB keyset "
            f"manifest: {manifest_path}"
        ) from exc

    if not isinstance(data, dict):
        raise TreeForgeBootstrapAvbKeysetError(
            "AVB keyset manifest root "
            "must be an object"
        )

    if data.get("schema") != 1:
        raise TreeForgeBootstrapAvbKeysetError(
            "unsupported AVB keyset schema"
        )

    if (
        data.get("kind")
        != "treeforge-avb-keyset"
    ):
        raise TreeForgeBootstrapAvbKeysetError(
            "invalid AVB keyset kind"
        )

    if (
        data.get("policy")
        != "preserve-root-identity"
    ):
        raise TreeForgeBootstrapAvbKeysetError(
            "unsupported AVB keyset policy"
        )

    keyset_id = data.get(
        "keyset_id"
    )

    device = data.get(
        "device"
    )

    android_release = data.get(
        "android_release"
    )

    for name, value in (
        ("keyset_id", keyset_id),
        ("device", device),
        (
            "android_release",
            android_release,
        ),
    ):
        if (
            not isinstance(value, str)
            or not value
        ):
            raise TreeForgeBootstrapAvbKeysetError(
                f"invalid keyset {name}"
            )

    keyset_root = (
        manifest_path.parent.resolve()
    )

    (
        boot_key,
        boot_private_sha,
        boot_public_sha1,
    ) = _validate_entry(
        root=keyset_root,
        entry=data.get(
            "boot_chain"
        ),
        role="boot_chain",
        expected_public_blob_size=520,
    )

    (
        root_key,
        root_private_sha,
        root_public_sha1,
    ) = _validate_entry(
        root=keyset_root,
        entry=data.get(
            "root_vbmeta"
        ),
        role="root_vbmeta",
        expected_public_blob_size=1032,
    )

    return ResolvedAvbKeyset(
        keyset_id=keyset_id,

        manifest_path=manifest_path,

        manifest_sha256=_sha256(
            manifest_path
        ),

        device=device,

        android_release=(
            android_release
        ),

        boot_chain_private_key=(
            boot_key
        ),

        boot_chain_private_key_sha256=(
            boot_private_sha
        ),

        boot_chain_public_key_sha1=(
            boot_public_sha1
        ),

        root_vbmeta_private_key=(
            root_key
        ),

        root_vbmeta_private_key_sha256=(
            root_private_sha
        ),

        root_vbmeta_public_key_sha1=(
            root_public_sha1
        ),
    )
