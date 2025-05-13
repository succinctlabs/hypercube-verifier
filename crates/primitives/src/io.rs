use crate::types::Buffer;
use serde::{Deserialize, Serialize};

/// The number of 32 bit words in the SP1 proof's committed value digest.
pub const PV_DIGEST_NUM_WORDS: usize = 8;

/// The number of field elements in the poseidon2 digest.
pub const POSEIDON_NUM_WORDS: usize = 8;

/// Public values for the prover.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SP1PublicValues {
    buffer: Buffer,
}

impl SP1PublicValues {
    pub fn as_byte_slice(&self) -> &[u8] {
        &self.buffer.data
    }
}
