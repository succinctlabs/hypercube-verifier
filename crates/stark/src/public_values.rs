use std::borrow::Borrow;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_primitives::io::{POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS};

use crate::Word;
/// A septic extension with an irreducible polynomial `z^7 - 2z - 5`.
///
/// The field can be constructed as `F_{p^7} = F_p[z]/(z^7 - 2z - 5)`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SepticExtension<F>(pub [F; 7]);

/// A septic elliptic curve point on y^2 = x^3 + 2x + 26z^5 over field `F_{p^7} = F_p[z]/(z^7 - 2z -
/// 5)`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SepticCurve<F> {
    /// The x-coordinate of an elliptic curve point.
    pub x: SepticExtension<F>,
    /// The y-coordinate of an elliptic curve point.
    pub y: SepticExtension<F>,
}

/// A global cumulative sum digest, a point on the elliptic curve that `SepticCurve<F>` represents.
/// As these digests start with the `CURVE_CUMULATIVE_SUM_START` point, they require special summing
/// logic.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SepticDigest<F>(pub SepticCurve<F>);

/// Stores all of a shard proof's public values.
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct PublicValues<W1, W2, T> {
    /// The hash of all the bytes that the guest program has written to public values.
    pub committed_value_digest: [W1; PV_DIGEST_NUM_WORDS],

    /// The hash of all deferred proofs that have been witnessed in the VM. It will be rebuilt in
    /// recursive verification as the proofs get verified. The hash itself is a rolling poseidon2
    /// hash of each proof+vkey hash and the previous hash which is initially zero.
    pub deferred_proofs_digest: [T; POSEIDON_NUM_WORDS],

    /// The shard's start program counter.
    pub start_pc: T,

    /// The expected start program counter for the next shard.
    pub next_pc: T,

    /// The exit code of the program.  Only valid if halt has been executed.
    pub exit_code: T,

    /// The shard number.
    pub shard: T,

    /// The execution shard number.
    pub execution_shard: T,

    /// The next execution shard number.
    pub next_execution_shard: T,

    /// The largest address that is witnessed for initialization in the previous shard.
    pub previous_init_addr_word: W2,

    /// The largest address that is witnessed for initialization in the current shard.
    pub last_init_addr_word: W2,

    /// The largest address that is witnessed for finalization in the previous shard.
    pub previous_finalize_addr_word: W2,

    /// The largest address that is witnessed for finalization in the current shard.
    pub last_finalize_addr_word: W2,

    /// The last timestamp of the shard.
    pub last_timestamp: T,

    /// The inverse of the last timestamp of the shard.
    pub last_timestamp_inv: T,

    /// The number of global memory initializations in the shard.
    pub global_init_count: T,

    /// The number of global memory finalizations in the shard.
    pub global_finalize_count: T,

    /// The number of global interactions in the shard.
    pub global_count: T,

    /// The global cumulative sum of the shard.
    pub global_cumulative_sum: SepticDigest<T>,

    /// The empty values to ensure the size of the public values struct is a multiple of 8.
    pub empty: [T; 7],
}

impl<T: Clone> Borrow<PublicValues<[T; 4], Word<T>, T>> for [T] {
    fn borrow(&self) -> &PublicValues<[T; 4], Word<T>, T> {
        let size = std::mem::size_of::<PublicValues<[u8; 4], Word<u8>, u8>>();
        debug_assert!(self.len() >= size);
        let slice = &self[0..size];
        let (prefix, shorts, _suffix) =
            unsafe { slice.align_to::<PublicValues<[T; 4], Word<T>, T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

/// Hash the input using SHA256.
#[must_use]
pub fn sha256_hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

/// Hash the input using Blake3.
#[must_use]
pub fn blake3_hash(input: &[u8]) -> Vec<u8> {
    blake3::hash(input).as_bytes().to_vec()
}
