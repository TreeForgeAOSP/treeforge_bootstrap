# TreeForge Bootstrap — v1.0b7

First-stage boot environment for TreeForge on Pixel Tablet (`tangorpro`).

## Build

```bash
./treeforge-bootstrap --profile treeforge-default doctor
./treeforge-bootstrap --profile treeforge-default build
./treeforge-bootstrap --profile treeforge-default verify
```

Published component providers resolve through their owning repositories. Unreleased work can be selected explicitly with `--framebuffer-provider PATH` or `--menu-provider PATH`.

## Release

Bootstrap releases provider and realizer artifacts. Installation-specific signed images are reconstructed downstream with the existing Owner AVB identity.

## Source

- `VERSION` — Bootstrap-owned version and runtime ABI
- `profiles/` — build profiles
- `runtime/initramfs/` — early userspace
- `src/treeforge_bootstrap/` — build and realization tooling

Generated output, caches, device images, and private signing material are not source.
