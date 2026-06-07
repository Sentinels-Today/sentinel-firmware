# sentinel-firmware

**Reference TPM 2.0 measured-boot data model + quote verification.** `no_std`-friendly Rust crate that firmware authors can drop into a controller bring-up to get spec-correct PCR extension and Ed25519-signed quote handling.

[![ci](https://github.com/Sentinels-Today/sentinel-firmware/actions/workflows/ci.yml/badge.svg)](https://github.com/Sentinels-Today/sentinel-firmware/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![rust](https://img.shields.io/badge/rust-1.75%2B-orange)

## What's here

- `pcr::Pcr` / `PcrBank` — 24 SHA-256 PCRs with `extend(old, m) = SHA256(old || m)`
- `quote::Quote` + `verify_quote` — Ed25519-signed snapshot of `(digest || nonce)`
- `no_std` by default — enable the `std` Cargo feature for host builds and tests

## Snippet

```rust
use sentinel_firmware::{verify_quote, PcrBank, Quote};

let mut bank = PcrBank::new();
bank.extend(0, b"bootloader")?;
bank.extend(7, b"kernel")?;

let digest = bank.selection_digest(&[0, 7])?;
// `digest` and a 32-byte nonce are signed by the TPM-attached Ed25519 key.
// The resulting `Quote` is verified off-device with `verify_quote`.

verify_quote(&quote, &public_key)?;
```

## Build

```sh
cargo build                         # host build with `std`
cargo build --no-default-features   # bare-metal / no_std
cargo test                          # 8 unit tests
```

CI runs fmt + clippy + a `--no-default-features` build + tests on ubuntu/macos/windows.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
