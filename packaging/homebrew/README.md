# Homebrew release formula

`Formula/sing-box-wigner.rb` is the canonical Homebrew packaging source for the
Wigner release. It consumes the immutable `v1.14.0-wigner.1` source archive and
builds only from the tracked standard Go vendor projection.

The formula deliberately does not:

- initialize DAE or Tailscale submodules;
- apply downstream patches;
- use the DAE or Tailscale forks as build inputs;
- contact the Go module proxy;
- implement route, daemon, or deployment behavior.

The source URL and SHA-256 bind the formula to the accepted sing-box merge and
its release assets. A future update changes the version, immutable release URL,
and digest together after the product acceptance and release workflows pass.

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

When a remote tap is restored, publish this exact reviewed formula there. The
tap is a release-distribution surface, not another editable source or patch
authority.
