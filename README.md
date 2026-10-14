# TreeForge Bootstrap — v1.0b7

First-stage boot environment for TreeForge on Pixel Tablet (`tangorpro`).

## Build

    ./treeforge-bootstrap --profile treeforge-default build

Successful default builds publish `out/development-provider/current` and retain the newest five successful runs.

Kernel, Framebuffer, and Menu development providers use the corresponding `--dev-provider-* [PATH]` arguments.

## Verify

    ./treeforge-bootstrap --profile treeforge-default verify

## Release

    ./release prepare

Release promotes the exact clean runtime and realizer from `out/development-provider/current` into `out/releases/<version>/assets`. It generates release metadata but does not rebuild either artifact.

Installation-specific signed images are reconstructed downstream with the existing Owner AVB identity.

`VERSION` is authoritative.
