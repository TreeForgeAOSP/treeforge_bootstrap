"""Prepare an owner-signed raw image family. This module never installs images.

The image payload and non-chain descriptors are conserved byte-for-byte. RSA
signing is performed by OpenSSL and the final graph is checked by avbtool.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

from .avb_graph import (
    REQUIRED_PARTITIONS, _input_roots, _resolve_source_images,
    _validate_source_manifest, _info_image, _verify_avb_image,
    _verify_chain_edges, _verify_descriptor_graph, _header_fields,
)


class OwnerFamilyError(RuntimeError):
    pass


def sha256(path: Path, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while limit is None or limit > 0:
            block = stream.read(min(limit, 1024 * 1024) if limit is not None else 1024 * 1024)
            if not block:
                if limit:
                    raise OwnerFamilyError("Truncated image payload")
                break
            digest.update(block)
            if limit is not None:
                limit -= len(block)
    return digest.hexdigest()


def command(args: list[str], data: bytes | None = None) -> bytes:
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise OwnerFamilyError(f"{Path(args[0]).name} {args[1]} failed: " + result.stderr.decode(errors="replace")[-2000:])
    return result.stdout


def read_metadata(image: Path) -> tuple[bytes, bytes, int, bytes | None]:
    size = image.stat().st_size
    with image.open("rb") as stream:
        if stream.read(4) == b"\x3a\xff\x26\xed":
            raise OwnerFamilyError("Owner preparation requires raw acquired images, not sparse images")
        if size < 256:
            raise OwnerFamilyError("Image is too small for AVB metadata")
        stream.seek(size - 64)
        footer = stream.read(64)
        if footer[:4] == b"AVBf":
            major, minor, original, offset, declared_size = struct.unpack_from("!IIQQQ", footer, 4)
            if major != 1 or minor != 0 or original > offset or offset + declared_size > size - 64:
                raise OwnerFamilyError("Unsupported or malformed AVB footer")
        else:
            footer, offset, declared_size = None, 0, None
        stream.seek(offset)
        header = stream.read(256)
        if header[:4] != b"AVB0" or struct.unpack_from("!I", header, 4)[0] != 1:
            raise OwnerFamilyError("Unsupported AVB header")
        auth, aux = struct.unpack_from("!QQ", header, 12)
        total = 256 + auth + aux
        if auth % 64 or aux % 64 or total > 65536 or offset + total > size - (64 if footer else 0):
            raise OwnerFamilyError("Invalid AVB metadata bounds")
        if declared_size is not None and declared_size != total:
            raise OwnerFamilyError("AVB footer/header size mismatch")
        if struct.unpack_from("!I", header, 120)[0] != 0:
            raise OwnerFamilyError("Verification-disabled/nonzero AVB flags are not accepted")
        if struct.unpack_from("!Q", header, 88)[0] != 0:
            raise OwnerFamilyError("AVB public-key metadata needs an explicit migration policy")
        stream.seek(offset + 256 + auth)
        auxiliary = stream.read(aux)
        desc_offset, desc_size = struct.unpack_from("!QQ", header, 96)
        if desc_offset + desc_size > aux:
            raise OwnerFamilyError("AVB descriptors exceed auxiliary data")
        return header, auxiliary[desc_offset:desc_offset + desc_size], offset, footer


def _public_bits(public: bytes) -> int:
    if len(public) < 4:
        raise OwnerFamilyError(
            "Owner AVB public key is truncated"
        )

    bits = struct.unpack_from(
        "!I",
        public,
        0,
    )[0]

    expected = {
        2048: 520,
        4096: 1032,
    }

    if (
        bits not in expected
        or len(public) != expected[bits]
    ):
        raise OwnerFamilyError(
            "Owner AVB public key must be RSA-2048 or RSA-4096"
        )

    return bits


def rewrite_descriptors(
    data: bytes,
    chain_public: bytes,
) -> bytes:
    output = bytearray()
    cursor = 0
    seen = set()

    while cursor < len(data):
        if len(data) - cursor < 16:
            raise OwnerFamilyError(
                "Truncated descriptor header"
            )

        tag, following = struct.unpack_from(
            "!QQ",
            data,
            cursor,
        )
        end = cursor + 16 + following

        if (
            following % 8
            or end > len(data)
            or tag not in {0, 1, 2, 3, 4}
        ):
            raise OwnerFamilyError(
                "Malformed or unsupported AVB descriptor"
            )

        record = data[cursor:end]

        if tag == 4:
            if len(record) < 92:
                raise OwnerFamilyError(
                    "Truncated chain descriptor"
                )

            (
                location,
                name_len,
                key_len,
                flags,
            ) = struct.unpack_from(
                "!IIII",
                record,
                16,
            )

            if (
                92 + name_len + key_len > len(record)
                or flags != 0
            ):
                raise OwnerFamilyError(
                    "Unsupported chain descriptor layout/flags"
                )

            name = record[
                92 : 92 + name_len
            ]

            if (
                name.decode("ascii")
                not in REQUIRED_PARTITIONS
                or name in seen
                or location == 0
            ):
                raise OwnerFamilyError(
                    "Unknown or duplicate AVB chain target"
                )

            seen.add(name)

            record = bytearray(
                record[:92]
                + name
                + chain_public
            )
            record.extend(
                b"\0" * (-len(record) % 8)
            )

            struct.pack_into(
                "!Q",
                record,
                8,
                len(record) - 16,
            )
            struct.pack_into(
                "!I",
                record,
                24,
                len(chain_public),
            )

        output.extend(record)
        cursor = end

    return bytes(output)


def resign(
    image: Path,
    private_key: Path,
    signing_public: bytes,
    chain_public: bytes,
) -> dict:
    (
        header,
        descriptors,
        offset,
        footer,
    ) = read_metadata(image)

    original_header = header
    payload_sha = sha256(
        image,
        offset,
    )

    descriptors = rewrite_descriptors(
        descriptors,
        chain_public,
    )

    bits = _public_bits(
        signing_public
    )

    if bits == 2048:
        algorithm_type = 1
        signature_size = 256
        authentication_size = 320
    elif bits == 4096:
        algorithm_type = 2
        signature_size = 512
        authentication_size = 576
    else:
        raise OwnerFamilyError(
            "Unsupported owner AVB key size"
        )

    auxiliary = (
        descriptors
        + signing_public
    )
    auxiliary += (
        b"\0"
        * (-len(auxiliary) % 64)
    )

    header = bytearray(header)

    struct.pack_into(
        "!QQI",
        header,
        12,
        authentication_size,
        len(auxiliary),
        algorithm_type,
    )

    struct.pack_into(
        "!QQQQ",
        header,
        32,
        0,
        32,
        32,
        signature_size,
    )

    struct.pack_into(
        "!QQQQQQ",
        header,
        64,
        len(descriptors),
        len(signing_public),
        len(descriptors) + len(signing_public),
        0,
        0,
        len(descriptors),
    )

    signed = (
        bytes(header)
        + auxiliary
    )

    signature = command(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(private_key),
        ],
        signed,
    )

    if len(signature) != signature_size:
        raise OwnerFamilyError(
            "Unexpected owner signature size"
        )

    authentication = (
        hashlib.sha256(signed).digest()
        + signature
    )
    authentication += (
        b"\0"
        * (
            authentication_size
            - len(authentication)
        )
    )

    if len(authentication) != authentication_size:
        raise OwnerFamilyError(
            "Owner authentication block size mismatch"
        )

    blob = (
        bytes(header)
        + authentication
        + auxiliary
    )

    old_auth, old_aux = struct.unpack_from(
        "!QQ",
        original_header,
        12,
    )
    old_size = (
        256
        + old_auth
        + old_aux
    )

    limit = (
        image.stat().st_size
        - (64 if footer else 0)
    )

    if (
        offset + len(blob) > limit
        or len(blob) > 65536
    ):
        raise OwnerFamilyError(
            "Owner AVB metadata does not fit the existing image"
        )

    with image.open("r+b") as stream:
        if len(blob) > old_size:
            stream.seek(
                offset + old_size
            )
            growth = (
                len(blob) - old_size
            )

            if any(
                stream.read(growth)
            ):
                raise OwnerFamilyError(
                    "AVB expansion would overwrite non-padding data"
                )

        stream.seek(offset)
        stream.write(blob)

        if old_size > len(blob):
            stream.write(
                b"\0"
                * (
                    old_size
                    - len(blob)
                )
            )

        if footer:
            footer = bytearray(
                footer
            )

            struct.pack_into(
                "!Q",
                footer,
                28,
                len(blob),
            )

            stream.seek(
                -64,
                2,
            )
            stream.write(
                footer
            )

        stream.flush()
        os.fsync(
            stream.fileno()
        )

    if sha256(
        image,
        offset,
    ) != payload_sha:
        raise OwnerFamilyError(
            "Image payload changed during owner signing"
        )

    (
        after,
        after_descriptors,
        after_offset,
        _,
    ) = read_metadata(image)

    if (
        after[:12]
        != original_header[:12]
        or after[112:]
        != original_header[112:]
        or after_descriptors
        != descriptors
        or after_offset
        != offset
    ):
        raise OwnerFamilyError(
            "AVB contract preservation failed"
        )

    return {
        "payload_bytes": offset,
        "payload_sha256": payload_sha,
        "payload_preserved": True,
        "algorithm": f"SHA256_RSA{bits}",
    }


def verify_family(
    avbtool: Path,
    images: dict[str, Path],
    public_sha1_by_partition: dict[str, str] | None = None,
) -> None:
    infos = {}

    for name in REQUIRED_PARTITIONS:
        _verify_avb_image(
            avbtool,
            images[name],
            follow_chain_partitions=True,
        )

        infos[name] = _info_image(
            avbtool,
            images[name],
        )

        read_metadata(
            images[name]
        )

        if public_sha1_by_partition is not None:
            expected = public_sha1_by_partition[
                name
            ]
            actual = _header_fields(
                infos[name]
            ).get(
                "Public key (sha1)"
            )

            if actual != expected:
                raise OwnerFamilyError(
                    f"Owner signing identity mismatch: {name}"
                )

    _verify_chain_edges(infos)
    _verify_descriptor_graph(infos)


def prepare(
    input_family: Path,
    output: Path,
    private_key: Path,
    public_key: Path,
    owner_manifest: Path,
    child_private_key: Path,
    child_public_key: Path,
    child_owner_manifest: Path,
    avbtool: Path,
    replacements: dict[str, tuple[Path, str]] | None = None,
) -> Path:
    (
        source_root,
        images_root,
        source_manifest,
    ) = _input_roots(
        input_family
    )

    sources = _resolve_source_images(
        images_root
    )

    if source_manifest is None:
        raise OwnerFamilyError(
            "A complete acquired source manifest is required"
        )

    manifest = _validate_source_manifest(
        source_manifest,
        sources,
    )

    identity = manifest.get(
        "identity",
        {},
    )

    if (
        identity.get("product") != "tangorpro"
        or str(
            identity.get(
                "android_release"
            )
        )
        != "15"
    ):
        raise OwnerFamilyError(
            "Owner preparation v1 requires tangorpro Android 15"
        )

    source_manifest_hash = sha256(
        source_manifest
    )

    def load_owner(
        manifest_path: Path,
        public_path: Path,
        bits: int,
    ) -> tuple[dict, bytes, str]:
        owner_record = json.loads(
            manifest_path.read_text()
        )
        public_blob = (
            public_path.read_bytes()
        )

        if _public_bits(
            public_blob
        ) != bits:
            raise OwnerFamilyError(
                f"Owner identity must be RSA-{bits}"
            )

        fingerprint = hashlib.sha256(
            public_blob
        ).hexdigest()

        if (
            owner_record.get("kind")
            != "treeforge-owner-avb"
            or owner_record.get("schema")
            != 1
            or owner_record.get("algorithm")
            != f"SHA256_RSA{bits}"
            or owner_record.get(
                "public_key_sha256"
            )
            != fingerprint
            or owner_record.get("key_id")
            != "owner-avb-" + fingerprint
        ):
            raise OwnerFamilyError(
                "Owner manifest/public-key identity mismatch"
            )

        return (
            owner_record,
            public_blob,
            fingerprint,
        )

    (
        owner,
        public,
        fingerprint,
    ) = load_owner(
        owner_manifest,
        public_key,
        4096,
    )

    (
        child_owner,
        child_public,
        child_fingerprint,
    ) = load_owner(
        child_owner_manifest,
        child_public_key,
        2048,
    )

    output = (
        output.expanduser()
        .absolute()
    )

    if output.is_symlink():
        raise OwnerFamilyError(
            "Output must not be a symlink"
        )

    output = output.resolve()

    if (
        output.exists()
        or output.is_relative_to(
            source_root
        )
    ):
        raise OwnerFamilyError(
            "Output must be new and outside the source backup"
        )

    replacements = (
        replacements or {}
    )

    if (
        set(replacements)
        - {"boot", "init_boot"}
    ):
        raise OwnerFamilyError(
            "Only explicit boot/init_boot replacements are supported in v1"
        )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.TemporaryDirectory(
        prefix=".owner-family-",
        dir=output.parent,
    ) as directory:
        stage = Path(directory)

        # Confirm both private/public bindings independently of callers.
        for (
            label,
            signing_key,
            expected_public,
        ) in (
            (
                "root",
                private_key,
                public,
            ),
            (
                "child",
                child_private_key,
                child_public,
            ),
        ):
            extracted = (
                stage
                / f"{label}.avbpubkey"
            )

            command(
                [
                    str(avbtool),
                    "extract_public_key",
                    "--key",
                    str(signing_key),
                    "--output",
                    str(extracted),
                ]
            )

            if (
                extracted.read_bytes()
                != expected_public
            ):
                raise OwnerFamilyError(
                    f"{label} signing key does not match owner public key"
                )

            extracted.unlink()

        images = {}
        source_hashes = {}

        for name, source in sources.items():
            target = (
                stage
                / f"{name}.img"
            )

            shutil.copyfile(
                source,
                target,
            )

            source_hashes[name] = sha256(
                target
            )
            images[name] = target

        print(
            "[Owner AVB] Verifying acquired source graph...",
            flush=True,
        )

        verify_family(
            avbtool,
            images,
        )

        inputs = dict(
            source_hashes
        )

        for (
            name,
            (
                replacement,
                expected_sha,
            ),
        ) in replacements.items():
            if (
                len(expected_sha) != 64
                or sha256(replacement)
                != expected_sha.lower()
            ):
                raise OwnerFamilyError(
                    f"Replacement SHA-256 mismatch: {name}"
                )

            if (
                replacement.stat().st_size
                != images[name].stat().st_size
            ):
                raise OwnerFamilyError(
                    f"Replacement partition size mismatch: {name}"
                )

            (
                old_header,
                _,
                _,
                _,
            ) = read_metadata(
                images[name]
            )

            (
                new_header,
                _,
                _,
                _,
            ) = read_metadata(
                replacement
            )

            if (
                struct.unpack_from(
                    "!Q",
                    new_header,
                    112,
                )[0]
                <
                struct.unpack_from(
                    "!Q",
                    old_header,
                    112,
                )[0]
                or new_header[124:128]
                != old_header[124:128]
            ):
                raise OwnerFamilyError(
                    f"Replacement rollback contract mismatch: {name}"
                )

            shutil.copyfile(
                replacement,
                images[name],
            )

            if (
                sha256(images[name])
                != expected_sha.lower()
            ):
                raise OwnerFamilyError(
                    f"Replacement changed while staging: {name}"
                )

            _verify_avb_image(
                avbtool,
                images[name],
            )

            inputs[name] = (
                expected_sha.lower()
            )

        records = []

        for name in REQUIRED_PARTITIONS:
            is_root = (
                name == "vbmeta"
            )

            signing_key = (
                private_key
                if is_root
                else child_private_key
            )

            signing_public = (
                public
                if is_root
                else child_public
            )

            signing_owner = (
                owner
                if is_root
                else child_owner
            )

            print(
                f"[Owner AVB] Signing {name} "
                f"with {signing_owner['algorithm']}...",
                flush=True,
            )

            preservation = resign(
                images[name],
                signing_key,
                signing_public,
                child_public,
            )

            records.append(
                {
                    "partition": name,
                    "realized_file": f"{name}.img",
                    "source_sha256": source_hashes[name],
                    "input_sha256": inputs[name],
                    "realized_sha256": sha256(
                        images[name]
                    ),
                    "size_bytes": images[
                        name
                    ].stat().st_size,
                    "key_id": signing_owner[
                        "key_id"
                    ],
                    **preservation,
                }
            )

        print(
            "[Owner AVB] Verifying all owner signatures and graph bindings...",
            flush=True,
        )

        root_sha1 = hashlib.sha1(
            public
        ).hexdigest()

        child_sha1 = hashlib.sha1(
            child_public
        ).hexdigest()

        expected_sha1 = {
            name: (
                root_sha1
                if name == "vbmeta"
                else child_sha1
            )
            for name in REQUIRED_PARTITIONS
        }

        verify_family(
            avbtool,
            images,
            expected_sha1,
        )

        for (
            name,
            source,
        ) in sources.items():
            if (
                sha256(source)
                != source_hashes[name]
            ):
                raise OwnerFamilyError(
                    f"Source changed during preparation: {name}"
                )

        if (
            sha256(source_manifest)
            != source_manifest_hash
        ):
            raise OwnerFamilyError(
                "Source manifest changed during preparation"
            )

        result = {
            "schema": 2,
            "family": "treeforge-owner-prepared-family",
            "device": "tangorpro",
            "android_release": "15",
            "source_manifest_sha256": source_manifest_hash,
            "source_slot": identity.get(
                "source_slot"
            ),

            # Keep key_id as the canonical root identity for compatibility
            # with the Pixel Partitioner writer admission contract.
            "key_id": owner["key_id"],

            "key_ids": {
                "root_rsa4096": owner[
                    "key_id"
                ],
                "child_rsa2048": child_owner[
                    "key_id"
                ],
            },

            "owner_public_key_sha256": fingerprint,
            "child_owner_public_key_sha256": child_fingerprint,

            "algorithm": "MIXED_SHA256_RSA4096_RSA2048",

            "algorithms": {
                "vbmeta": "SHA256_RSA4096",
                "all_other_partitions": "SHA256_RSA2048",
            },

            "artifacts": records,
            "artifact_count": len(records),

            "verification": {
                "complete_graph": True,
                "all_owner_signatures": True,
                "payloads_preserved": True,
                "source_unchanged": True,
            },

            "installation_enabled": False,

            "pending_acceptance": [
                "Android first-stage key references",
                "B-first installer and Android boot validation",
            ],
        }

        (
            stage
            / "owner-family.json"
        ).write_text(
            json.dumps(
                result,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

        # Do not claim compatibility with the legacy two-image install
        # manifest.
        output.mkdir()

        try:
            for entry in stage.iterdir():
                entry.replace(
                    output
                    / entry.name
                )
        except BaseException:
            shutil.rmtree(
                output
            )
            raise

    print(
        f"OWNER_FAMILY_PREPARED={output}",
        flush=True,
    )
    print(
        "DEVICE_WRITES=NO\nINSTALLATION_ENABLED=NO",
        flush=True,
    )

    return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__
    )

    for option in (
        "input-family",
        "output-family",
        "private-key",
        "public-key",
        "owner-manifest",
        "child-private-key",
        "child-public-key",
        "child-owner-manifest",
        "avbtool",
    ):
        parser.add_argument(
            "--" + option,
            type=Path,
            required=True,
        )

    for name in (
        "boot",
        "init-boot",
    ):
        parser.add_argument(
            "--" + name,
            type=Path,
        )
        parser.add_argument(
            "--" + name + "-sha256"
        )

    args = parser.parse_args()
    replacements = {}

    for name in (
        "boot",
        "init_boot",
    ):
        path = getattr(
            args,
            name,
        )
        digest = getattr(
            args,
            name + "_sha256",
        )

        if (
            (path is None)
            != (digest is None)
        ):
            parser.error(
                f"{name} replacement requires both path and SHA-256"
            )

        if path is not None:
            replacements[name] = (
                path,
                digest,
            )

    prepare(
        args.input_family,
        args.output_family,
        args.private_key,
        args.public_key,
        args.owner_manifest,
        args.child_private_key,
        args.child_public_key,
        args.child_owner_manifest,
        args.avbtool,
        replacements,
    )


if __name__ == "__main__":
    main()
