"""Bind a selected provider into the existing signed ramdisk, without compiling it."""
from dataclasses import replace
import hashlib
from pathlib import Path
import re
import struct
import subprocess
from .newc import parse_newc_archive, serialize_newc_archive

DESTINATION = b'/dev/treeforge-bootstrap-runtime/etc/kernel-contract-v1'

def expected_contract(provider: dict) -> bytes | None:
    identity = provider['metadata'].get('boot_identity')
    if identity is None:
        return None  # Legacy provider is not storage-v1 proof capable.
    if identity.get('schema') != 'treeforge.kernel.boot-identity.v1':
        raise ValueError('unsupported kernel measurement')
    build = identity.get('gnu_build_id','')
    sha = identity.get('boot_payload_sha256','')
    length = identity.get('boot_payload_bytes')
    if not re.fullmatch(r'[0-9a-f]{32,128}',build) or len(build)%2 or not re.fullmatch(r'[0-9a-f]{64}',sha):
        raise ValueError('invalid measured kernel identity')
    boot = Path(provider['boot']).read_bytes(); footer = boot[-64:]
    if (type(length) is not int or not 4096 <= length <= 67108800 or footer[:4] != b'AVBf'
            or int.from_bytes(footer[12:20],'big') != length
            or hashlib.sha256(boot[:length]).hexdigest() != sha):
        raise ValueError('provider boot payload measurement mismatch')
    abi = provider['metadata']['kernel_abi'].encode('ascii')
    if not 1 <= len(abi) <= 127 or any(c<33 or c>126 for c in abi):
        raise ValueError('invalid measured kernel ABI')
    result = bytearray(512); result[:8] = b'TFKERN1\0'
    result[8:40] = hashlib.sha256(Path(provider['manifest']).read_bytes()).digest()
    result[40:72] = bytes.fromhex(sha)
    struct.pack_into('<QI',result,72,length,len(build)//2)
    result[84:84+len(build)//2] = bytes.fromhex(build)
    struct.pack_into('<H',result,148,len(abi));result[150:150+len(abi)] = abi
    return bytes(result)


def bind_dispatcher(elf: bytes, contract: bytes, destination: bytes = DESTINATION) -> bytes:
    if not contract or len(contract)>4096 or elf[-16:-8]!=b'TFRTEND1':
        raise ValueError('kernel proof requires retained-runtime dispatcher')
    length = int.from_bytes(elf[-8:],'little'); start = len(elf)-16-length
    if start<64 or elf[start:start+8]!=b'TFRTB001':
        raise ValueError('invalid retained-runtime trailer')
    body = bytearray(elf[start:-16]); count,reserved = struct.unpack_from('<II',body,8)
    if reserved or count>256:
        raise ValueError('invalid retained-runtime header')
    p=16
    for _ in range(count):
        n,mode,size=struct.unpack_from('<IIQ',body,p);p+=16
        if not 1<=n<=511 or p+n+size>len(body) or body[p:p+n]==destination:
            raise ValueError('invalid/duplicate retained-runtime entry')
        p+=n+size
    if p!=len(body):
        raise ValueError('retained-runtime payload length mismatch')
    struct.pack_into('<I',body,8,count+1)
    body.extend(struct.pack('<IIQ',len(destination),0o600,len(contract))+destination+contract)
    return elf[:start]+body+b'TFRTEND1'+len(body).to_bytes(8,'little')


def bind_ramdisk(source: Path, output: Path, provider: dict, lz4: Path, security: bytes | None = None) -> Path:
    contract=expected_contract(provider)
    if contract is None:
        return source
    raw=subprocess.check_output([str(lz4),'-d','-c',str(source)])
    archive=parse_newc_archive(raw)
    dispatchers=[e for e in archive.entries if e.name=='init']
    if len(dispatchers)==1 and b'TREEFORGE_KERNEL_PROOF_PRODUCER_V1' not in dispatchers[0].data:
        if security is not None:
            raise ValueError('selected runtime lacks kernel proof producer')
        return source  # Frozen legacy runtime cannot advertise a proof producer.
    if sum(e.name=='init' for e in archive.entries)!=1:
        raise ValueError('canonical ramdisk requires exactly one dispatcher')
    def bind(elf):
        elf = bind_dispatcher(elf, contract)
        if security is not None:
            from .security_handoff import DESTINATION as security_path
            if b'TREEFORGE_SECURITY_HANDOFF_PRODUCER_V1' not in elf:
                raise ValueError('selected runtime lacks security handoff producer')
            elf = bind_dispatcher(elf, security, security_path)
        return elf
    entries=tuple(replace(e,data=bind(e.data)) if e.name=='init' else e for e in archive.entries)
    realized=serialize_newc_archive(replace(archive,entries=entries))
    output.parent.mkdir(parents=True,exist_ok=True)
    compressed=subprocess.check_output([str(lz4),'-l','-12','-c'],input=realized)
    output.write_bytes(compressed)
    return output
