//! TPM quote = signed assertion that "these PCRs had these values at this moment."

use alloc::vec::Vec;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quote {
    /// Sorted, deduped list of PCR indices included in this quote.
    pub selection: Vec<u8>,
    /// Selection digest from [`crate::pcr::PcrBank::selection_digest`].
    pub digest: [u8; 32],
    /// 32-byte verifier-supplied nonce.
    pub nonce: [u8; 32],
    /// Detached Ed25519 signature over `digest || nonce`.
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuoteError {
    InvalidPublicKey,
    SignatureVerificationFailed,
}

impl core::fmt::Display for QuoteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            QuoteError::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
            QuoteError::SignatureVerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for QuoteError {}

pub fn quote_message(quote: &Quote) -> [u8; 64] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&quote.digest);
    buf[32..].copy_from_slice(&quote.nonce);
    buf
}

pub fn verify_quote(quote: &Quote, public_key_bytes: &[u8; 32]) -> Result<(), QuoteError> {
    let vk =
        VerifyingKey::from_bytes(public_key_bytes).map_err(|_| QuoteError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(&quote.signature);
    vk.verify(&quote_message(quote), &sig)
        .map_err(|_| QuoteError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcr::PcrBank;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn signed_quote(
        secret: &SigningKey,
        bank: &PcrBank,
        selection: &[u8],
        nonce: [u8; 32],
    ) -> Quote {
        let digest = bank.selection_digest(selection).unwrap();
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&digest);
        msg[32..].copy_from_slice(&nonce);
        let sig = secret.sign(&msg);
        let mut sel: Vec<u8> = selection.to_vec();
        sel.sort_unstable();
        sel.dedup();
        Quote {
            selection: sel,
            digest,
            nonce,
            signature: sig.to_bytes(),
        }
    }

    #[test]
    fn quote_verifies_with_correct_key() {
        let signing = SigningKey::generate(&mut OsRng);
        let mut bank = PcrBank::new();
        bank.extend(0, b"bootloader").unwrap();
        bank.extend(7, b"kernel").unwrap();
        let q = signed_quote(&signing, &bank, &[0, 7], [42u8; 32]);
        verify_quote(&q, signing.verifying_key().as_bytes()).unwrap();
    }

    #[test]
    fn quote_fails_on_tampered_digest() {
        let signing = SigningKey::generate(&mut OsRng);
        let mut bank = PcrBank::new();
        bank.extend(0, b"bootloader").unwrap();
        let mut q = signed_quote(&signing, &bank, &[0], [1u8; 32]);
        q.digest[0] ^= 0xff;
        assert_eq!(
            verify_quote(&q, signing.verifying_key().as_bytes()),
            Err(QuoteError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn quote_fails_with_wrong_key() {
        let signing = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let mut bank = PcrBank::new();
        bank.extend(0, b"x").unwrap();
        let q = signed_quote(&signing, &bank, &[0], [0u8; 32]);
        assert_eq!(
            verify_quote(&q, other.verifying_key().as_bytes()),
            Err(QuoteError::SignatureVerificationFailed)
        );
    }
}
