# treeforge_bootstrap: repository-local release workflow

Run `./release` for interactive publishing. `./release prepare [--force]`
retains this repository's original component-specific lifecycle and remains
non-building; `./release verify` checks staged checksums; `./release status`
shows local identity; `./release contract` diagnoses the current accepted provider without rebuilding; `./release resume VERSION` can finish the post-publish
version prompt if a verified publication receipt exists.

The publisher **never rebuilds or renames** accepted artifacts. It asks for
version, then channel: Stable, Beta (normal GitHub release, not GitHub
prerelease), or Pre-release (GitHub prerelease). The channel is preserved in
`treeforge-release-channel.json` alongside untouched provider assets. It
requires `skelitonlord` GitHub CLI and SSH authentication, a clean main branch
matching remote main, a genuinely absent tag/release and explicit typed
`PUBLISH OWNER/REPO VERSION` authorization. It fails closed and does not
silently delete published releases or remote tags.

After downloaded assets match the staged assets, and **only then**, the tool
prompts for a new development VERSION. The version change is committed locally;
no automatic push or build occurs. Manager also increments its Android
versionCode. `skip` defers that step; `./release resume VERSION` can complete
it after a verified publication.

Note: modifying this repository's release scripts changes its source commit.
Already-built development artifacts tied to the previous HEAD cannot pass
legacy release-prepare source-equality gates until explicitly reconciled.
Do not disable provider/Owner-AVB/signing verification to work around this.

## Historical Bootstrap v1.0b2 acceptance

`./release accepted-check` verifies the frozen hardware-accepted development
provider against `release-acceptance/v1.0b2.json`, including its source commit
ancestry, original VERSION, exact development manifest digest, all provider
artifact hashes, and the three runtime member hashes/sizes. It does not build
or stage a release. The pinned provider's source identity is distinct from
current release tooling HEAD. The legacy v1.0b1 runtime.py frozen constants
remain unchanged for all other releases.

`./release prepare` continues to copy the verified runtime and realizer bytes
unchanged, then creates the normal release Manager manifest and a checksum file
for the top-level release assets. The Bootstrap asset checksum file is
`ASSET-SHA256SUMS` (not the nested provider `SHA256SUMS`).

There is no implied publication: the normal owner-only interactive publish
command retains its strict GitHub remote-branch and publication checks.
