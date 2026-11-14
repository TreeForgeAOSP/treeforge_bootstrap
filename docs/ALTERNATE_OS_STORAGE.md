# Alternate OS storage-v1 boot consumer

Source integration only. No build, device operation, installation, formatting or
migration was performed. Legacy raw ext4 boot remains available. This consumer is
not device-qualified. Updated now checks its declared consumer/current-boot contract
before offering native storage actions; actual migration remains separately approved.

## Ownership and fixed inputs

Updated owns the canonical storage/boot-record/health-ack ABI. The independently
vendored fixtures under `contracts/storage-v1` pin the consumed bytes; `SOURCE.json`
records their hashes. No runtime/build dependency on a sibling checkout is added.
Bootstrap's existing dispatcher source assembly includes the owned freestanding
`runtime/initramfs/src/alternate_storage.c`. Compiler, packaging, signing, provider
selection and release commands remain unchanged.
Future runtime build metadata records protocol 1, the frozen fixture contract and
consumer-source SHA-256, deadline, kernel-proof protocol 2 and image admission
protocol 1, while retaining explicit device-unqualified status.
Existing output/provider receipts are not rewritten by this source change.

The consumer reads the live sda GPT and both entry copies, PP's type/name/UUIDv5,
outer geometry and kernel partition mapping. It then validates both inner GPTs,
both immutable descriptors and the highest valid mirrored boot record. A chosen
root also requires its mirrored Owner-signed admission ticket, verified through
Updated's read-only verifier using the retained Android linker before pivot. Equal
generation disagreement refuses selection; one valid boot record is readable.
The fixed 40,000,028,672-byte outer allocation and all Android partitions remain
unchanged. Bootstrap writes only the two bounded 4 KiB boot-control records.

Menu inspection does not mount/replay STATE or change any trial/boot record.
Separately, once-per-boot lifecycle reconciliation runs after starting ADB and
before Menu interaction: it can confirm an already matched prior health receipt
without consuming a trial. This also reconciles health before returning to Android.
Recognized but unusable v1 metadata is presented as recovery, not silently opened
as a legacy root. Metadata/CRC checks establish structure, not publisher authenticity.

## Handoff and boot state

- ROOT is mapped read-only over the selected payload length, hashed with the
  already retained BusyBox SHA-256 applet, and mounted read-only without journal
  replay. The image must be 4 KiB aligned. ROOT capacity stays 4 GiB; the current
  image remains 2 GiB. STATE has its own exact bounded loop mapping and ext4 UUID,
  filesystem-size and encryption-feature checks.
- Bootstrap reads a previous matching health acknowledgement from a read-only,
  no-journal-replay STATE probe. It confirms only that exact generation, root,
  installation, attempt, image, kernel and disk. A stale/missing acknowledgement
  cannot confirm a newer root.
- Immediately before a pending handoff, publish a fresh random attempt ID and
  decrement one trial, backup first then primary, syncing and reading back each.
  Preserve Updated's operation ID. Merely visiting Menu or choosing Android does
  not consume trials. A crash between durable consumption and execution counts
  conservatively as an attempted boot.
- Bad/unmountable pending roots and exhausted trials retain the compatible
  confirmed root. Hash/contract failure never silently selects unverified bytes.
  Shared STATE errors stop for recovery; selecting another root cannot repair
  incompatible STATE or a changed shared kernel.
- A pending trial has a **300-second CLOCK_BOOTTIME userspace deadline**. A small
  retained child observes the exact durable health acknowledgement through its
  STATE directory descriptor. On success it exits; on expiry it requests ordinary
  reboot without touching USB. This covers userspace startup stalls while the
  kernel can schedule it. It is not a qualified hardware/kernel-hang watchdog.
  For an explicitly authorized live diagnostic session, a root-owned private RAM
  file `/dev/treeforge-altos/hold-trial-reboot` containing exactly
  `TREEFORGE_ALTOS_DIAGNOSTIC_HOLD_V1` plus newline defers deadline reboot. It does
  not confirm a root, restore trials or change storage. Removing it resumes an
  already-expired deadline. This keeps the existing ADB available for longer
  startup-failure captures without disabling the ordinary trial policy.

`/dev/treeforge-altos/boot-context-v1` is private root-owned RAM state containing
the frozen codec hash, boot UUID, selected generation/root/trial, STATE schema/UUID,
payload identity and compatibility context. ChromiumOS validates it against actual
loop devices/mounts and the selected boot record. Nothing is written into ROOT.

## ADB continuity

The existing Bootstrap ADB supervisor, adbd binary, dynamic runtime and retained
BusyBox are unchanged. Alternate OS still publishes
`/dev/treeforge-bootstrap-altroot-active`, retains the recursive `/dev` bind and
`/config` gadget mount, and uses the existing PID1 pivot. It never invokes the
Android-only ADB-stop/USB-release cleanup. Preparation failures leave Menu/ADB
alive; later startup failure leaves the running bridge available until a deliberate
reboot/deadline. No gadget reset or replacement daemon is introduced.

The known cable-disconnect recovery issue is separate and unchanged. Runtime ADB
continuity still needs verification with the rebuilt compatible family. A real
kernel crash or reboot necessarily interrupts the connection.

## Remaining integration and qualification

- The current-boot kernel producer is now integrated in source. After ADB
  starts, it validates live GNU notes/ABI and active-slot boot payload against the
  provider contract in the Owner-signed dispatcher trailer. It publishes the
  private `/dev/treeforge-verified-kernel-v1` RAM receipt, shared with Updated
  through existing /dev handoffs. Missing old measurement metadata withholds proof
  without breaking the legacy path or ADB. Build/policy/hardware acceptance remains
  required; rootd does not create a later persistent substitute.
- Native Owner-signature/image/kernel/STATE admission is implemented; qualify the
  early verifier loader/runtime and rejected-signature fallback on hardware. The
  policy is signed exact SHA-256 plus full payload hash on every read-only handoff,
  not dm-verity. Non-4-KiB payloads are refused; tiny fixtures stay parser-only.
- Qualify native code, loop flags/lifetimes, metadata interruption/readback,
  fscrypt and persistent account unlock, deadline/fallback, failure capture and ADB
  continuity. Acknowledged service startup is not account-unlock certification.
- Complete the formatter execution/policy/provider-family pass, then build/test
  compatible components and use an explicitly approved migration window. Until
  then leave the existing device/raw installation alone. PP/Updated/Manager menus,
  manual rollback/STATE reset/removal and hardware watchdog work retain their owners.

ChromiumOS's side is described in its `STORAGE_INTEGRATION_HANDOFF.md`.


See Updated's `docs/STORAGE_ADMISSION_ACTIONS.md` for mirrored admission record
positions, signature ownership and remaining family/ADB/persistent-data acceptance.
The new verifier has a bounded timeout and suppresses SIGPIPE on failed startup;
its failure refuses handoff without touching the existing ADB/USB services.
