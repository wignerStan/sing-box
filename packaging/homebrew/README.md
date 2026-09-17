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

A dedicated `wignerStan/homebrew-tap` repository is currently absent. Until a
tap repository is re-established, this file remains the reviewed packaging
authority and can be tested directly:

```sh
brew install --formula ./packaging/homebrew/Formula/sing-box-wigner.rb
```

When a tap is restored, publish this exact reviewed formula there. The tap is a
release-distribution surface, not another editable source or patch authority.
