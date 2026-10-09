# TreeForge Bootstrap

TreeForge Bootstrap is the first-stage boot environment and boot manager for TreeForge-supported Android devices.

The current supported target is the Google Pixel Tablet (`tangorpro`) using Android 15.

## Versions

- TreeForge Bootstrap: `v1.0b5`
- TreeForge Boot Manager: `v1.0b2`
- TreeForge Runtime ABI: `v1.0b1`

## Supported target

| Component | Value |
| --- | --- |
| Device | Google Pixel Tablet |
| Codename | `tangorpro` |
| SoC | Google Tensor G2 / `gs201` |
| Architecture | `arm64` |
| Platform | Android 15 |

## Building

The default profile is `treeforge-default`.

Check the host environment:

```bash
./treeforge-bootstrap \
    --profile treeforge-default \
    doctor
```

Build and verify:

```bash
./treeforge-bootstrap \
    --profile treeforge-default \
    build

./treeforge-bootstrap \
    --profile treeforge-default \
    verify
```

Verify the frozen release runtime:

```bash
./treeforge-bootstrap \
    --profile treeforge-default \
    verify-frozen-runtime
```

Package and verify the runtime provider:

```bash
./treeforge-bootstrap \
    --profile treeforge-default \
    package

./treeforge-bootstrap \
    --profile treeforge-default \
    verify-provider
```

Use `./treeforge-bootstrap --help` for the complete command-line interface.

## Release artifacts

TreeForge Bootstrap releases reusable provider artifacts rather than an installation-specific `init_boot.img`.

The `v1.0b5` release provides:

```text
provider-contract.json
SHA256SUMS

treeforge-bootstrap-tangorpro-android15-runtime.tar.xz
treeforge-bootstrap-tangorpro-android15-runtime.tar.xz.sha256

treeforge-bootstrap-tangorpro-android15-runtime-update-manifest.json
treeforge-bootstrap-tangorpro-android15-runtime-update-manifest.json.sha256

treeforge-bootstrap-tangorpro-android15-realizer.tar.xz
treeforge-bootstrap-tangorpro-android15-realizer.tar.xz.sha256
```

The update manifest provides the machine-readable Bootstrap update contract used by TreeForge Manager.

## Kernel dependency

Bootstrap `v1.0b5` uses TreeForge Kernel `r0.94-v1.0b2`.

The matching kernel artifact is acquired and verified by the Bootstrap kernel provider.

## Repository layout

```text
profiles/                   Bootstrap profiles
runtime/initramfs/          early-userspace runtime
src/treeforge_bootstrap/    Bootstrap implementation
VERSION                     component versions
provider-contract.json      provider/release contract
treeforge-bootstrap         command-line entry point
```

Generated output, caches, device images, and private signing material are not source.

## Status

TreeForge Bootstrap is beta software.
