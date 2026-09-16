# DAE and Tailscale source authority

This repository is the product and downstream-change authority for the native
DAE and Tailscale integrations shipped by the Wigner sing-box release.

## Physical source model

- `third_party/dae` is a pristine exact submodule of `daeuniverse/dae`.
- `third_party/tailscale` is a pristine exact submodule of
  `SagerNet/tailscale` for the embedded library.
- `third_party/tailscale-1.94.2` is a pristine exact submodule of
  `tailscale/tailscale` for the standalone Linux peer build.
- `patches/` contains the only editable downstream DAE and Tailscale changes.
- `vendor/` contains generated ordinary files. It contains no Git metadata,
  gitlinks, submodules, or nested repositories.

The existing `wignerStan/dae` and `wignerStan/tailscale` repositories are patch
extraction and upstream-publication mirrors. A branch in either fork is not a
release dependency after this migration.

## Updating a dependency

1. Advance one exact `third_party/` gitlink in a reviewed commit.
2. Rebase or replace the corresponding ordered patch series without dirtying
   the submodule.
3. Run `python3 tools/vendor/materialize.py`.
4. Run `python3 tools/vendor/verify.py` and the patch/vendor CI matrix.
5. Review the old/new source commit, patch digests, patched Git tree, generated
   vendor tree, and combined product tests as one transition.

A failed patch is a compatibility failure. The materializer never skips or
fuzzily accepts a patch.

## Build and release

The Go module replacements resolve DAE and Tailscale to the checked-in ordinary
files below `vendor/`. Product commands use `GOFLAGS=-mod=mod` so this custom
source-materialization boundary is not confused with Go's package-only vendor
mode.

A release tag builds binaries from the exact sing-box commit and includes
`deps/vendor-lock.json` in each package. The same release publishes the
standalone Tailscale 1.94.2 Linux companion produced from its pristine pin and
patch series. Homebrew consumes release artifacts only.

## Runtime boundary

The macOS runtime remains one native sing-box process. It embeds the Tailscale
endpoint and owns its system-interface routes. No standalone Mac `tailscaled`,
route supervisor, compatibility socket, or deployment-time route mutation is
part of this source model.
