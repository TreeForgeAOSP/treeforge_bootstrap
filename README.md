# TreeForge Bootstrap

TreeForge Bootstrap is the persistent on-device bootstrap and boot manager
for supported TreeForge multiboot environments.

## Ownership

TreeForge Bootstrap owns the persistent early-runtime environment,
hardware-facing bootstrap interfaces, menu engine, action dispatch,
handoff machinery, and the default TreeForge Boot Manager.

The active runtime contract includes:

- `/dev/treeforge_bootstrap_fb`
- `TREEFORGE_BOOTSTRAP_FB_CONSUMER_V1`
- `TREEFORGE_BOOTSTRAP_FB_BRIDGE_ONLY_V1`
- `/dev/treeforge-bootstrap-runtime`
- `/init.treeforge-bootstrap-first-stage`
- `treeforge-bootstrap-adbd`
- `treeforge-bootstrap-adb-service`

Consumer projects provide their own menu profile and higher-level workflow
while reusing the TreeForge Bootstrap runtime implementation.

## Signing boundary

TreeForge Bootstrap publishes unsigned runtime provider artifacts.

The downstream consumer owns final device-family image composition,
AVB signing, installation policy, and device writes.

TreeForge Bootstrap does not own downstream signing keys and does not
publish a pre-signed device installation image.

## Current platform

The first v1.0 target is:

- device: `tangorpro`
- platform: Android 15
- architecture: arm64

## Build

The repository-local entry point is:

    ./treeforge-bootstrap doctor

Runtime and provider artifacts are rebuilt and verified before release.

## Menu profiles

TreeForge Bootstrap owns the menu engine, renderer, input handling,
navigation, timeout behavior, action registry, and core action
implementations.

Consumers select the visible interface through a validated schema-v1
menu profile. Profiles define titles, entry order, visibility conditions,
submenus, defaults, timeout policy, and mappings to Bootstrap-supported
actions; they do not reimplement framebuffer, input, reboot, or handoff
logic.

The built-in profile is `profiles/treeforge-default.json`.
