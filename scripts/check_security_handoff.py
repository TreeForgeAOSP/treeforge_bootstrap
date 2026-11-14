#!/usr/bin/env python3
"""Two offline checks: exact carrier binding and rejection of unsafe inputs."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from treeforge_bootstrap.security_handoff import carrier_profile
from treeforge_bootstrap.kernel_proof import bind_dispatcher


def main():
    with tempfile.TemporaryDirectory() as directory:
        manifest = Path(directory) / 'module-provider.json'
        manifest.write_text('fixture kernel provider')
        provider = {'manifest': manifest, 'metadata': {'trusty_guard': {
            'schema': 'treeforge.trusty-proxy-guard.v1', 'abi': 1}}}
        properties = {'boot': (('com.android.build.boot.os_version', '15'),
            ('com.android.build.boot.security_patch', '2025-05-05')),
            'vendor': (('com.android.build.vendor.os_version', '15'),
            ('com.android.build.vendor.security_patch', '2025-05-05'))}
        output = SimpleNamespace(stdout='ro.build.version.release=15\nro.build.version.security_patch=2025-05-05\n')
        with patch('treeforge_bootstrap.security_handoff.subprocess.run', return_value=output):
            profile = carrier_profile(properties, provider, Path('fixture-system.img'))
            assert len(profile) == 256 and profile[:8] == b'TFSEC01\0'
            assert struct.unpack_from('<6I', profile, 8) == (150000, 20250505, 20250505, 20250505, 12518823, 1)
            assert profile[32:64] == hashlib.sha256(manifest.read_bytes()).digest()
            body = b'TFRTB001' + struct.pack('<II', 0, 0)
            elf = b'fixture-elf'.ljust(64, b'\0') + body + b'TFRTEND1' + len(body).to_bytes(8, 'little')
            destination = b'/dev/treeforge-bootstrap-runtime/etc/security-profile-v1'
            bound = bind_dispatcher(elf, profile, destination)
            assert destination + profile in bound
            try: bind_dispatcher(bound, profile, destination)
            except ValueError: pass
            else: raise AssertionError('duplicate public profile admitted')
        print('PUBLIC_CARRIER_BINDING=PASS')
        for text in ('ro.build.version.release=14\nro.build.version.security_patch=2025-05-05\n',
                     'ro.build.version.release=15\nro.build.version.security_patch=2025-02-30\n'):
            with patch('treeforge_bootstrap.security_handoff.subprocess.run', return_value=SimpleNamespace(stdout=text)):
                try: carrier_profile(properties, provider, Path('fixture-system.img'))
                except ValueError: pass
                else: raise AssertionError('mismatched/malformed version admitted')
        assert carrier_profile({}, {'metadata': {}}, None) is None
        print('UNSAFE_OR_LEGACY_METADATA=PASS')

if __name__ == '__main__': main()
