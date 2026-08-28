# qpack compatibility module

This directory is a source-compatible bridge for the temporary dependency
conflict introduced by the dae root-module capture provider.

sing-box uses the qpack v0.6 iterator API, while the QUIC implementation pulled
by the current dae provider still compiles against qpack v0.5's callback and
`DecodeFull` APIs. The bridge keeps the v0.6 encoder and decoder behavior and
adds only the older decoder entry points needed by that transitive dependency.

The code is derived from `github.com/quic-go/qpack` v0.6.0 under its MIT
license. Remove this module and the root `replace` directive when dae's eBPF
capture runtime no longer imports dae's policy/control dependency graph.
