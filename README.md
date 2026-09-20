# TreeForge Bootstrap

TreeForge Bootstrap is the persistent on-device bootstrap and boot manager
for Pixel Tablet multiboot work.

This repository is a separate source lineage from Pixel Partitioner.

## Ownership

TreeForge Bootstrap owns the persistent boot-time environment and the
TreeForge Menu.

Pixel Partitioner owns device acquisition, storage conversion,
repartitioning, installation orchestration, and its temporary maintenance
runtime.

## Current extraction stage

The initial source split preserves the hardware-proven low-level runtime ABI
from Pixel Partitioner while moving the persistent runtime source into this
independent repository.

The following low-level names intentionally remain unchanged during the
initial split because they are part of the already-proven runtime contract:

- `/dev/pixel_partitioner_fb`
- the Pixel Partitioner framebuffer ABI markers
- the existing first-stage/retained-runtime handoff paths

They can be versioned independently later if needed.

No release/provider asset is published by this extraction patch yet.

## Build scaffold

TreeForge Bootstrap owns the persistent runtime and TreeForge Menu.

The repository-local build entry point is:

    ./treeforge-bootstrap doctor

The provider artifact remains unsigned. Pixel Partitioner owns final
device-family composition, AVB signing, and partition installation.
