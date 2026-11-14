# Nowhere's mimalloc 3.6.1 patch

This directory vendors `libmimalloc-sys` 0.1.49 from crates.io, with its v3 C
implementation updated to the official Microsoft mimalloc **3.6.1** release.
The crates.io `mimalloc` 0.1.52 Rust wrapper is unchanged. The root Cargo manifest
selects this directory using `[patch.crates-io]`; `Cargo.lock` records the local
package as `0.1.49+mi3.6.1`.

## Provenance

| Component | Source | SHA-256 |
| --- | --- | --- |
| Rust sys crate | https://static.crates.io/crates/libmimalloc-sys/libmimalloc-sys-0.1.49.crate | `6a45a52f43e1c16f667ccfe4dd8c85b7f7c204fd5e3bf46c5b0db9a5c3c0b8e9` |
| mimalloc C source | https://github.com/microsoft/mimalloc/releases/download/v3.6.1/mimalloc-v3.6.1-source.tar.gz | `7321fbe8e3d2bb447cba127603c44450db0d8ef35e8240bb4a56a7455eba0a68` |

The Microsoft release archive corresponds to source revision
`56dc5eb80145f9a3ba7ca23d47c6a248b9d8586c`. Both archive hashes were verified
before copying the source. `LICENSE.txt` covers the Rust bindings;
`c_src/mimalloc/v3/LICENSE` covers the C implementation. Both use the MIT license.

## Local changes

- Replaced `c_src/mimalloc/v3` with 3.6.1 sources, retaining the packaging
  exclusions for `bin`, `cmake`, `doc`, `docs`, `ide` and `test` directories.
- Added version metadata `+mi3.6.1` to the sys crate's Cargo manifest.
- For musl, defined `MI_LIBC_MUSL=1` and selected local-dynamic TLS, matching
  upstream's static-library CMake configuration. Other targets retain the sys
  crate's existing compiler and platform handling.
- Removed the published crate's `Cargo.lock` and `.cargo_vcs_info.json`.

The Rust FFI declarations are unchanged. The v2 sources remain unchanged for
compatibility with the sys crate's optional `v2` feature; Nowhere uses v3.
The allocator is selected for the executable and library unit tests. Applications
embedding Nowhere's Rust library retain control of their global allocator.
The `override` feature is not enabled, so native libraries retain their allocation APIs.

## Updating

Verify a new upstream release archive and its hash, replace the v3 source tree,
update the package metadata and this note, and regenerate `Cargo.lock`. Check
that the Rust wrapper still resolves to this local sys crate and review upstream
compiler/platform changes. Run formatting, strict Clippy, all Rust tests and a
release build with one build job on memory-constrained hosts. Verify TLS and QUIC
forwarding with the final executable. Cross-builds do not replace native execution
on each supported platform.
