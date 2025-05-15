use crate::types::Buffer;
use num_bigint::BigUint;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Public values for the prover.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SP1PublicValues {
    buffer: Buffer,
}

impl SP1PublicValues {
    /// Create a new `SP1PublicValues`.
    pub const fn new() -> Self {
        Self { buffer: Buffer::new() }
    }

    pub fn raw(&self) -> String {
        format!("0x{}", hex::encode(self.as_slice()))
    }

    /// Create a `SP1PublicValues` from a slice of bytes.
    pub fn from(data: &[u8]) -> Self {
        Self { buffer: Buffer::from(data) }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.buffer.data.as_slice()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer.data.clone()
    }

    /// Read a value from the buffer.    
    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        self.buffer.read()
    }

    /// Read a slice of bytes from the buffer.
    pub fn read_slice(&mut self, slice: &mut [u8]) {
        self.buffer.read_slice(slice);
    }

    /// Write a value to the buffer.
    pub fn write<T: Serialize>(&mut self, data: &T) {
        self.buffer.write(data);
    }

    /// Write a slice of bytes to the buffer.
    pub fn write_slice(&mut self, slice: &[u8]) {
        self.buffer.write_slice(slice);
    }

    /// Hash the public values using SHA256.
    pub fn hash(&self) -> Vec<u8> {
        sha256_hash(self.buffer.data.as_slice())
    }

    /// Hash the public values using Blake3.
    pub fn blake3_hash(&self) -> Vec<u8> {
        blake3_hash(self.buffer.data.as_slice())
    }

    /// Hash the public values using SHA256, mask the top 3 bits and return a BigUint.
    /// Matches the implementation of `hashPublicValues` in the Solidity verifier.
    ///
    /// ```solidity
    /// sha256(publicValues) & bytes32(uint256((1 << 253) - 1));
    /// ```
    pub fn hash_bn254(&self) -> BigUint {
        self.hash_bn254_with_fn(sha256_hash)
    }

    /// Hash the public values using the provided `hasher` function, mask the top 3 bits and
    /// return a BigUint.
    pub fn hash_bn254_with_fn<F>(&self, hasher: F) -> BigUint
    where
        F: Fn(&[u8]) -> Vec<u8>,
    {
        // Hash the public values.
        let mut hash = hasher(self.buffer.data.as_slice());

        // Mask the top 3 bits.
        hash[0] &= 0b00011111;

        // Return the masked hash as a BigUint.
        BigUint::from_bytes_be(hash.as_slice())
    }
}

impl AsRef<[u8]> for SP1PublicValues {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.data
    }
}

/// Hash the input using SHA256.
pub fn sha256_hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

/// Hash the input using Blake3.
pub fn blake3_hash(input: &[u8]) -> Vec<u8> {
    blake3::hash(input).as_bytes().to_vec()
}
