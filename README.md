# TreeForge Bootstrap

First-stage boot environment for TreeForge on Pixel Tablet (`tangorpro`).

## Build

    ./treeforge-bootstrap --profile treeforge-default build

Successful default builds publish `out/development-provider/current` and retain the newest five successful runs.

Normal runtime builds resolve the newest published Framebuffer and Menu providers from GitHub and freeze their exact release identities. Kernel is resolved for image-family realization. Local development inputs require explicit `--dev-provider-* [PATH]` overrides.

## Verify

    ./treeforge-bootstrap --profile treeforge-default verify

## Release

    ./release prepare

Release promotes the exact clean runtime and realizer from `out/development-provider/current` into `out/releases/<version>/assets`. It generates release metadata but does not rebuild either artifact.

Installation-specific signed images are reconstructed downstream with the existing Owner AVB identity.

`VERSION` is authoritative.

## Transaction ABI v2

Bootstrap contains the consumer for TreeForge Transaction ABI v2.

The initial operation is `proof`. After Android stages a canonical
`consumer=bootstrap` request under `/metadata/treeforge-bootstrap`, Bootstrap
intercepts it before the normal Boot Manager path, atomically claims
`pending -> running`, publishes an Android continuation as
`running -> result`, and returns directly through the existing Android Slot-A
`selinux_setup` handoff.

A lone `running` state is never replayed. Stale temporary state, malformed
records, mixed ownership, and unsupported Bootstrap operations fail closed.
Android-side transactiond owns continuation reconciliation and the final
terminal result.

The Menu provider is not part of the transaction state machine.
