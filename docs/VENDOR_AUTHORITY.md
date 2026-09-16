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
- `.vendor-work/` is an ignored disposable generation area. The materializer
  applies the ordered patch stacks there and dependency-level tests run there.
- `vendor/` is a standard Go vendor projection containing parent-owned ordinary
  package files plus `vendor/modules.txt`. It contains no Git metadata,
  gitlinks, submodules, nested repositories, or editable patch authority.

The existing `wignerStan/dae` and `wignerStan/tailscale` repositories are patch
extraction and upstream-publication mirrors. A branch in either fork is not a
release dependency after this migration.

## Updating a dependency

1. Advance one exact `third_party/` gitlink in a reviewed commit.
2. Rebase or replace the corresponding ordered patch series without dirtying
   the submodule.
3. Run `python3 tools/vendor/materialize.py --keep-work`.
4. Test the patched modules in `.vendor-work/dae/ebpfinbound` and
   `.vendor-work/tailscale`.
5. Run `python3 tools/vendor/verify.py --require-source` and the
   patch/vendor CI matrix.
6. Review the old/new source commit, patch digests, patched Git tree, generated
   Go vendor projection, and combined product tests as one transition.

A failed patch is a compatibility failure. The materializer never skips or
fuzzily accepts a patch. Running the materializer and verifier again must produce
no tracked diff.

## Repository-metadata exclusion

Go's standard vendor projection can copy ordinary `.gitmodules` data files from
module packages. They are not needed by the product and are not allowed below
the parent-owned `vendor/` boundary. The materializer therefore records each
projected file's relative path, byte size, and SHA-256 in
`projection.excluded_repository_metadata`, removes it, and only then computes
the final projection identity.

The exclusion is deliberately narrow: only regular files named `.gitmodules`
are accepted. CI separately proved that removing the four current projected
files from MaxMind, qpack, cronet-go, and netipx leaves the vendor-mode product
tests and full sing-box build unchanged. Any new repository-control file changes
the receipt and requires review.

## Build and release

Normal repository builds use Go's standard vendor mode. The checked-in
`vendor/modules.txt` binds the main module graph to the packages projected from
the patched DAE and Tailscale generation inputs. Product commands and clean
source archives build with `-mod=vendor` and do not require submodule checkout or
network module resolution.

`deps/vendor-lock.json` records exact source commits, ordered patch digests,
patched Git tree identities, the repository-metadata exclusion receipt, and the
generated projection digest. The offline form of `tools/vendor/verify.py` checks
the tracked projection and Go wiring; `--require-source` additionally checks the
pristine gitlinks, patch inventory, and deterministic regeneration.

A release tag builds binaries from the exact sing-box commit and includes the
vendor lock in each package. The same release publishes the standalone
Tailscale 1.94.2 Linux companion produced from its pristine pin and patch series.
Homebrew consumes immutable release artifacts only; it does not apply DAE or
Tailscale patches and does not initialize submodules.

## Runtime boundary

The macOS runtime remains one native sing-box process. It embeds the Tailscale
endpoint and owns its system-interface routes. No standalone Mac `tailscaled`,
route supervisor, compatibility socket, or deployment-time route mutation is
part of this source model.
