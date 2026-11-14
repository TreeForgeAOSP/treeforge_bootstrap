"""Public carrier facts for the signed runtime; never configure Trusty or keys.

The digest of the final AVB family is observed at boot, not embedded into one
of its own images. Source hashes below identify inputs, not that final digest.
"""
import datetime
import hashlib
import re
import struct
import subprocess
from pathlib import Path

DESTINATION = b'/dev/treeforge-bootstrap-runtime/etc/security-profile-v1'
EXPECTED_TRUSTY_BUILD = 12518823  # Audited shipping cloudripper firmware only.


def carrier_profile(properties: dict[str, tuple], provider: dict, system_image: Path | None = None) -> bytes | None:
    guard = provider['metadata'].get('trusty_guard')
    if not guard or guard.get('schema') != 'treeforge.trusty-proxy-guard.v1' or guard.get('abi') != 1:
        return None  # Old providers remain bootable; credential validation fails closed.
    values = {}
    for partition, records in properties.items():
        for key, value in records:
            if key in values and values[key] != value:
                raise ValueError('conflicting carrier AVB property: ' + key)
            values[key] = value
    def required(partition, name):
        key = f'com.android.build.{partition}.{name}'
        if key not in values:
            raise ValueError('missing carrier AVB property: ' + key)
        return values[key]
    # The platform SPL is in build.prop, not an AVB property on this carrier.
    # Read the already-selected system image without mounting or editing it.
    if system_image is None:
        raise ValueError('selected system carrier required for public version metadata')
    result = subprocess.run(['debugfs', '-R', 'cat /system/build.prop', str(system_image)],
                            check=True, capture_output=True, text=True, timeout=15)
    if not 0 < len(result.stdout) <= 65536:
        raise ValueError('invalid system build.prop length')
    system = {}
    for line in result.stdout.splitlines():
        if line.startswith(('ro.build.version.release=', 'ro.build.version.security_patch=')):
            key, value = line.split('=', 1)
            if key in system:
                raise ValueError('duplicate system version property')
            system[key] = value
    values['com.android.build.system.security_patch'] = system.get('ro.build.version.security_patch', '')
    os_text = required('boot', 'os_version')
    if system.get('ro.build.version.release') != os_text or required('vendor', 'os_version') != os_text:
        raise ValueError('carrier OS versions disagree')
    if not re.fullmatch(r'[1-9][0-9]?(?:\.[0-9]{1,2}){0,2}', os_text):
        raise ValueError('invalid carrier OS version')
    digits = [int(v) for v in os_text.split('.')]
    digits += [0] * (3 - len(digits))
    os_version = digits[0]*10000 + digits[1]*100 + digits[2]
    patches = []
    for name in ('system', 'vendor', 'boot'):
        value = required(name, 'security_patch')
        if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', value):
            raise ValueError('invalid carrier security patch')
        datetime.date.fromisoformat(value)
        patches.append(int(value.replace('-', '')))
    result = bytearray(256)
    result[:8] = b'TFSEC01\0'
    struct.pack_into('<6I', result, 8, os_version, *patches, EXPECTED_TRUSTY_BUILD, 1)
    result[32:64] = hashlib.sha256(Path(provider['manifest']).read_bytes()).digest()
    return bytes(result)
