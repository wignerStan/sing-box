# Homebrew release formula

`Formula/sing-box-wigner.rb` is the canonical Homebrew packaging source for the
Wigner build. Version `1.14.0-wigner.2` consumes the immutable source commit
`9b472cfd6731db200886b7a010d053a235290ac6`, which includes native UDP bind recovery,
and builds only from the tracked standard Go vendor projection. This is a pinned
fix build; it does not imply that a `v1.14.0-wigner.2` release tag exists.

The build deliberately does not:

- read DAE or Tailscale submodules as build inputs;
- apply downstream patches;
- use the DAE or Tailscale forks as build inputs;
- contact the Go module proxy;
- implement route, daemon, or deployment behavior.

The Git URL and full revision bind the formula to that exact commit. A Git source
pin allows an existing local clone to seed Homebrew's source cache instead of
re-downloading the large all-platform archive. Homebrew may fetch submodules,
but compilation remains strictly `-mod=vendor`, with the Go proxy disabled. A
future update changes the version and immutable revision together after product
acceptance. `version_scheme 1` lets the numbered version upgrade older
commit-stamped local builds such as `1.14.0-wigner-5469a0ac`.

A dedicated `wignerStan/homebrew-tap` repository is currently absent. Modern
Homebrew requires formulas to live inside a tap, so test the reviewed formula by
staging it in a local tap:

```sh
brew tap-new wignerStan/release-local
tap_dir="$(brew --repository wignerStan/release-local)"
cp packaging/homebrew/Formula/sing-box-wigner.rb \
  "$tap_dir/Formula/sing-box-wigner.rb"
brew install wignerStan/release-local/sing-box-wigner
brew test wignerStan/release-local/sing-box-wigner
```

If `wignerStan/tap` already exists locally, use that existing tap instead of
creating another. Stage this canonical formula there and run
`HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade wignerStan/tap/sing-box-wigner`.
The no-auto-update flag avoids fetching the absent tap remote; it does not change
the pinned source revision. Homebrew installs the executable only. The existing
native service installer must explicitly activate the new artifact; no second
service or runtime recovery wrapper is installed by this formula.

When a remote tap is restored, publish this exact reviewed formula there. The
tap is a release-distribution surface, not another editable source or patch
authority.
