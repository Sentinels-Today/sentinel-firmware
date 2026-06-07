//! SHA-256 platform configuration registers.

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

/// One PCR is the SHA-256 hash of all measurements extended into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pcr(pub [u8; 32]);

impl Pcr {
    pub const fn new() -> Self {
        Self([0u8; 32])
    }

    /// Extend the PCR with a measurement: `pcr <- SHA256(pcr || measurement)`.
    pub fn extend(&mut self, measurement: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        hasher.update(measurement);
        let out = hasher.finalize();
        self.0.copy_from_slice(&out);
    }
}

impl Default for Pcr {
    fn default() -> Self {
        Self::new()
    }
}

/// A bank holds 24 PCRs (TPM 2.0 conventional layout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrBank {
    pcrs: [Pcr; 24],
}

impl PcrBank {
    pub fn new() -> Self {
        Self {
            pcrs: [Pcr::new(); 24],
        }
    }

    pub fn read(&self, index: u8) -> Result<&Pcr, PcrError> {
        usize::from(index)
            .checked_sub(0)
            .and_then(|i| self.pcrs.get(i))
            .ok_or(PcrError::OutOfRange(index))
    }

    pub fn extend(&mut self, index: u8, measurement: &[u8]) -> Result<(), PcrError> {
        let i = usize::from(index);
        let pcr = self.pcrs.get_mut(i).ok_or(PcrError::OutOfRange(index))?;
        pcr.extend(measurement);
        Ok(())
    }

    /// Concatenated `selection_bitmap || hash(pcr[i]) for i in selection`
    /// — the typical input to a quote signature.
    pub fn selection_digest(&self, selection: &[u8]) -> Result<[u8; 32], PcrError> {
        let mut hasher = Sha256::new();
        // Hash the sorted selection set so the digest is canonical.
        let mut sel: Vec<u8> = selection.to_vec();
        sel.sort_unstable();
        sel.dedup();
        hasher.update(&sel);
        for idx in &sel {
            let pcr = self.read(*idx)?;
            hasher.update(pcr.0);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        Ok(out)
    }
}

impl Default for PcrBank {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcrError {
    OutOfRange(u8),
}

impl core::fmt::Display for PcrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PcrError::OutOfRange(i) => write!(f, "pcr index {} is out of range (0..24)", i),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PcrError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_is_deterministic() {
        let mut a = Pcr::new();
        let mut b = Pcr::new();
        a.extend(b"bootloader");
        a.extend(b"kernel");
        b.extend(b"bootloader");
        b.extend(b"kernel");
        assert_eq!(a, b);
    }

    #[test]
    fn order_matters() {
        let mut a = Pcr::new();
        let mut b = Pcr::new();
        a.extend(b"x");
        a.extend(b"y");
        b.extend(b"y");
        b.extend(b"x");
        assert_ne!(a, b);
    }

    #[test]
    fn bank_extends_individual_pcrs() {
        let mut bank = PcrBank::new();
        bank.extend(0, b"a").unwrap();
        bank.extend(7, b"b").unwrap();
        assert_ne!(bank.read(0).unwrap(), bank.read(1).unwrap());
        assert_ne!(bank.read(7).unwrap(), bank.read(0).unwrap());
    }

    #[test]
    fn bank_rejects_out_of_range_index() {
        let bank = PcrBank::new();
        assert!(matches!(bank.read(24), Err(PcrError::OutOfRange(24))));
    }

    #[test]
    fn selection_digest_is_canonical_across_order() {
        let mut bank = PcrBank::new();
        bank.extend(0, b"a").unwrap();
        bank.extend(7, b"b").unwrap();
        let d1 = bank.selection_digest(&[0, 7]).unwrap();
        let d2 = bank.selection_digest(&[7, 0]).unwrap();
        assert_eq!(d1, d2);
        let d3 = bank.selection_digest(&[7, 7, 0, 0]).unwrap();
        assert_eq!(d1, d3);
    }
}
