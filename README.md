# TreeForge Bootstrap

TreeForge Bootstrap is an early-boot runtime and graphical boot manager for the Pixel Tablet (`tangorpro`).

The current development target is **Android 15 on `tangorpro`**.

TreeForge Bootstrap is currently in **beta**. The current release line of the redesigned Bootstrap architecture is:

`v1.0b2`

## Current status

The current Bootstrap runtime has been hardware validated on the Pixel Tablet.

Working and accepted in the current beta:

* TreeForge Boot Manager graphical runtime.
* Resume handoff into Android slot A.
* 10-second default Resume behavior when there is no user interaction.
* Touch input.
* Volume Up / Volume Down navigation.
* Power-button selection.
* Bootstrap ADB.
* Manual ADB recovery from the Maintenance menu.
* Reboot controls.
* Device and system information surfaces.
* Read-only Partition Information viewer.
* TreeForge OS partition geometry reporting.
* Deterministic Bootstrap runtime construction.
* Reproducible runtime provider packaging.
* Deterministic host-realizer provider packaging.
* Provider-local realization without a developer Bootstrap or kernel checkout.
* Native realization of the complete 15-image device family.
* AVB graph verification.
* Preserve-compatible-trust AVB policy.
* Hardware-accepted `boot.img` and `init_boot.img`.
* Clean source-plus-pinned-provider reproduction.

The following surfaces intentionally remain incomplete:

* Android slot B handoff.
* Alternate-OS inventory and handoff.
* Dedicated Recovery runtime.
* Root installation and rooted boot workflows.
* Final multiboot operating-system installation workflow.
* Final Pixel Partitioner installation-flow integration.

These incomplete entries remain visible where useful, but are marked as not implemented rather than pretending to be functional.

## Architecture

TreeForge Bootstrap owns the boot runtime and realization of a coherent bootable device family.

Its responsibilities include:

* TreeForge Boot Manager runtime.
* Bootstrap ADB runtime integration.
* Runtime verification.
* Provider packaging.
* `boot.img` / `init_boot.img` realization.
* AVB signing and graph realization.
* AVB chain and descriptor verification.
* Complete 15-image realized-family validation.
* Preservation of compatible existing AVB trust identities.

TreeForge Bootstrap does **not** own final device re-partitioning or installation policy.

Those responsibilities belong to Pixel Partitioner.

The intended split is:

```text
Pixel Partitioner
    |
    |-- acquires and validates the device backup
    |-- persists installation/signing keysets
    |
    v
TreeForge Bootstrap
    |
    |-- consumes the complete source image family
    |-- supplies the Bootstrap runtime
    |-- realizes boot/init_boot
    |-- realizes and verifies the AVB graph
    |-- returns a verified 15-image family
    |
    v
Pixel Partitioner
    |
    |-- derives the install plan
    |-- controls authorized partition writes
    |-- controls slot state
    |-- performs final installation
```

This keeps boot/runtime implementation inside Bootstrap while keeping storage and destructive device operations inside Pixel Partitioner.

## Supported target

Current supported development target:

```text
Device:            Pixel Tablet
Codename:          tangorpro
Platform:          Android 15
Architecture:      arm64
SoC family:        gs201
Bootstrap slot:    A during current hardware validation
Android handoff:   Slot A
```

Support should not be assumed for another device or Android release unless it has its own validated provider and realization contract.

## Release providers

`v1.0b2` defines two separate TreeForge Bootstrap provider roles.

### Runtime provider

The accepted runtime provider remains:

```text
treeforge-bootstrap-tangorpro-android15-runtime.tar.xz
```

SHA-256:

```text
c22c69a7bbcde289d2d31fbcf4ac4c764939bcc10a1d733158de4a45529998ad
```

The runtime provider contains:

```text
payload/initramfs.cpio
payload/initramfs.lz4
payload/bin/treeforge-menu
metadata/provider.json
SHA256SUMS
```

Accepted payload identities:

```text
initramfs.cpio
b35a6497880950cc0eb28bffc60077f64b7b05621fb8cc42b25773dedbdbce35

initramfs.lz4
ee0deacd5551109330491451034d55b40264483b11b01f4b82eae05155eb6095

treeforge-menu
9e90410312a7f003fef1b3912904f3035cbbd115fba7511beae274e7558dd110
```

The runtime provider is intentionally unsigned at the final device-image boundary. It does not contain private AVB signing keys.

### Host realizer provider

`v1.0b2` adds the host-side realization provider:

```text
treeforge-bootstrap-tangorpro-android15-realizer.tar.xz
```

The host realizer contains the committed Bootstrap host implementation and provider metadata required to run `verify-frozen-runtime` and `realize-family`.

It does **not** bundle:

```text
the Bootstrap runtime payload
the canonical Google init_boot seed
the Bootstrap adbd build provider
private AVB keys
the AOSP AVB test key
a TreeForge Bootstrap development checkout
a TreeForge kernel development checkout
```

The runtime provider remains a separate pinned dependency.

At consumption time, the host realizer receives:

```text
accepted runtime provider
validated device-family backup
consumer-owned AVB keyset
```

and produces the verified 15-image Bootstrap family.

The host-realizer archive SHA-256 is derived only after the final release metadata commit is built. It is therefore published with the release artifacts rather than embedded into this source tree, because the archive itself contains the tracked release contract.

## Reproduction model

TreeForge Bootstrap uses a source-plus-pinned-provider reproduction model.

The accepted runtime is reproduced from:

```text
TreeForge Bootstrap source
        +
pinned external providers
        +
pinned host tools
        =
byte-identical Bootstrap runtime
```

The canonical Google `init_boot` ramdisk seed is an external build input.

It is required when reconstructing and deeply validating the runtime from source, but it is **not tracked or redistributed by TreeForge**.

The released runtime plus host-realizer path does not require that Google seed when realizing an accepted device family.

The accepted canonical seed identity is:

```text
SHA-256:
d9a027e3c06dc096cfb92e15251329c96f1d69e38954c2d0758da520b1f3078f
```

The Bootstrap ADB runtime is also supplied through a pinned external provider.

A clean source checkout therefore does not imply that every external binary required for a from-source runtime reconstruction is stored in this repository.

## Runtime versus realization

There are two related but separate layers.

### Runtime

The runtime provider contains the already-built early-userspace environment used by TreeForge Boot Manager.

It includes the accepted initramfs and menu executable.

### Device-family realization

TreeForge Bootstrap can consume a complete compatible device image family and construct a verified Bootstrap family.

The realization surface is:

```text
treeforge-bootstrap \
    --input-family <device-family> \
    --output-family <output-directory> \
    --avb-keyset <keyset> \
    realize-family
```

The realized family contains exactly 15 images for the current `tangorpro` contract:

```text
boot
init_boot
dtbo
vendor_kernel_boot
pvmfw
vendor_boot
vbmeta
vbmeta_system
vbmeta_vendor
system
system_dlkm
system_ext
product
vendor
vendor_dlkm
```

The current accepted compatible-trust path preserves the 13 unchanged source-family images byte-for-byte while replacing the accepted TreeForge `boot.img` and realized `init_boot.img`.

## AVB policy

TreeForge Bootstrap treats AVB as a graph, not as a collection of unrelated image signatures.

The current compatible-trust realization verifies:

```text
source family completeness
AVB signatures
chain partition identities
rollback-index locations
descriptor bindings
root vbmeta relationships
vbmeta_system relationships
vbmeta_vendor relationships
passthrough image identity
final realized-family completeness
```

For the currently accepted `tangorpro` Android 15 family, the existing compatible AVB identities can be preserved without rewriting root `vbmeta`.

Private key material is not published as part of the Bootstrap runtime provider.

## CLI

Available development commands include:

```text
treeforge-bootstrap doctor
treeforge-bootstrap build
treeforge-bootstrap verify
treeforge-bootstrap package
treeforge-bootstrap verify-provider
treeforge-bootstrap image
treeforge-bootstrap verify-image
treeforge-bootstrap realize-family
treeforge-bootstrap hardware-preflight
```

Use:

```text
treeforge-bootstrap --help
```

for the current command-line surface.

Some commands require pinned external providers or a complete device-family input. `doctor` reports the expected local provider/tool state.

## Pixel Partitioner integration

Pixel Partitioner is the intended consumer of TreeForge Bootstrap for permanent installation.

The accepted production dependency boundary is:

```text
published TreeForge Bootstrap runtime provider
        +
published TreeForge Bootstrap host realizer
        +
validated Pixel Partitioner device backup
        +
Pixel Partitioner AVB keyset
        |
        v
TreeForge Bootstrap realization
        |
        v
verified 15-image Bootstrap family
        |
        v
Pixel Partitioner install plan
        |
        v
authorized device installation
```

The host-side provider boundary is accepted for `v1.0b2`.

It has been verified from independently extracted provider artifacts without a developer `treeforge_bootstrap` checkout, without a developer `treeforge_kernel` checkout, without the Google canonical seed, and without an AOSP checkout.

Pixel Partitioner still owns the remaining installation-side integration: provider acquisition/materialization, install-plan derivation, authorization, partition writes, slot state, and final device verification.

## Host realizer provider status

The self-contained host-side Bootstrap realizer is accepted for the `v1.0b2` release line.

The accepted provider boundary separates runtime payload from host realization logic:

```text
runtime provider
    -> accepted initramfs/menu payload

host realizer provider
    -> frozen-runtime verification
    -> boot/init_boot realization
    -> AVB graph realization and verification
    -> complete 15-image family
```

The realizer consumes the runtime provider as a separate dependency and consumes AVB private keys only from the downstream consumer's supplied keyset.

The accepted isolated-provider test reproduced the hardware-accepted identities:

```text
boot.img
59d9103f7c9e343a96af6d37f9307f4610db7d228976b9d67ac59fab00bcf20b

init_boot.img
be49250687786bea3ac14e0d1744fddb6f3e51ba34d4dd19778eb5900a5def80

manifest.json
0c10b6d8e12a38183129cc64ff57c00eb4794c2f596af5c6b1f93bcd203551c9
```

The provider does not redistribute the Google canonical seed, the adbd build provider, AOSP test signing keys, or consumer AVB private keys.

## Safety model

TreeForge Bootstrap separates construction from final device installation.

Host realization and provider packaging do not themselves authorize destructive partition writes.

Final device-write policy belongs to Pixel Partitioner and should preserve:

```text
explicit write authorization
validated target device
validated target slot
explicit partition plan
readback/verification where supported
no unintended active-slot change
no unintended automatic reboot
```

## Repository layout

Important source areas:

```text
profiles/
    Boot Manager profiles

runtime/initramfs/
    early-userspace runtime source

src/treeforge_bootstrap/
    runtime builder
    Boot Manager dispatcher
    provider packaging
    kernel-provider integration
    image construction
    AVB realization
    AVB keyset validation

provider-contract.json
    publication and reproduction contract
```

Generated output and private provider state are not source and should not be committed.


## Current release

Current beta release line:

```text
v1.0b2
```

Repository:

```text
TreeForgeAOSP/treeforge_bootstrap
```

`v1.0b2` keeps the hardware-accepted runtime unchanged and adds the accepted self-contained host-realizer provider boundary.

The remaining Pixel Partitioner work is installation-side integration of those published providers; broader alternate-OS and multiboot workflows remain active development work.
