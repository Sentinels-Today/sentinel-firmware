//! `sentinel-firmware` — reference TPM 2.0 measured-boot data model and quote
//! verification for Sentinel Labs.
//!
//! The crate is `no_std`-friendly (enable the default `std` feature for the
//! host build / tests). Real TPM hardware integration lives behind the
//! [`Tpm`] trait — implementors plug in their controller's command interface.
//!
//! ## What's in here
//!
//! - [`Pcr`] / [`PcrBank`]: SHA-256 platform configuration registers with the
//!   standard `extend(old, measurement) = SHA256(old || measurement)` operation
//! - [`Quote`]: signed snapshot of selected PCRs + a verifier nonce
//! - [`verify_quote`]: Ed25519 verification helper

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod pcr;
pub mod quote;

pub use pcr::{Pcr, PcrBank, PcrError};
pub use quote::{verify_quote, Quote, QuoteError};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
