// use core::{fmt::Debug, mem::size_of};
// use std::borrow::{Borrow, BorrowMut};

// use itertools::Itertools;
// use p3_field::{AbstractField, PrimeField32};
// use serde::{Deserialize, Serialize};

// use crate::{septic_curve::SepticCurve, septic_digest::SepticDigest, Word, PROOF_MAX_NUM_PVS};

// /// The number of non padded elements in the SP1 proofs public values vec.
// pub const SP1_PROOF_NUM_PV_ELTS: usize = size_of::<PublicValues<[u8; 4], Word<u8>, u8>>();

/// The number of 32 bit words in the SP1 proof's committed value digest.
pub const PV_DIGEST_NUM_WORDS: usize = 8;

/// The number of field elements in the poseidon2 digest.
pub const POSEIDON_NUM_WORDS: usize = 8;

use std::borrow::{Borrow, BorrowMut};

use itertools::Itertools;
use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};

use crate::{septic_digest::SepticDigest, Word};

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

// impl PublicValues<u32, u32, u32> {
//     /// Convert the public values into a vector of field elements.  This function will pad the
//     /// vector to the maximum number of public values.
//     #[must_use]
//     pub fn to_vec<F: AbstractField>(&self) -> Vec<F> {
//         let mut ret = vec![F::zero(); PROOF_MAX_NUM_PVS];

//         let field_values = PublicValues::<[F; 4], Word<F>, F>::from(*self);
//         let ret_ref_mut: &mut PublicValues<[F; 4], Word<F>, F> = ret.as_mut_slice().borrow_mut();
//         *ret_ref_mut = field_values;
//         ret
//     }

//     /// Resets the public values to zero.
//     #[must_use]
//     pub fn reset(&self) -> Self {
//         let mut copy = *self;
//         copy.shard = 0;
//         copy.execution_shard = 0;
//         copy.start_pc = 0;
//         copy.next_pc = 0;
//         copy.previous_init_addr_word = 0;
//         copy.last_init_addr_word = 0;
//         copy.previous_finalize_addr_word = 0;
//         copy.last_finalize_addr_word = 0;
//         copy
//     }
// }

impl<F: PrimeField32> PublicValues<[F; 4], Word<F>, F> {
    /// Returns the commit digest as a vector of little-endian bytes.
    pub fn commit_digest_bytes(&self) -> Vec<u8> {
        self.committed_value_digest
            .iter()
            .flat_map(|w| w.iter().map(|f| f.as_canonical_u32() as u8))
            .collect_vec()
    }
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

impl<T: Clone> BorrowMut<PublicValues<[T; 4], Word<T>, T>> for [T] {
    fn borrow_mut(&mut self) -> &mut PublicValues<[T; 4], Word<T>, T> {
        let size = std::mem::size_of::<PublicValues<[u8; 4], Word<u8>, u8>>();
        debug_assert!(self.len() >= size);
        let slice = &mut self[0..size];
        let (prefix, shorts, _suffix) =
            unsafe { slice.align_to_mut::<PublicValues<[T; 4], Word<T>, T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

// impl<F: AbstractField> From<PublicValues<u32, u32, u32>> for PublicValues<[F; 4], Word<F>, F> {
//     fn from(value: PublicValues<u32, u32, u32>) -> Self {
//         let PublicValues {
//             committed_value_digest,
//             deferred_proofs_digest,
//             start_pc,
//             next_pc,
//             exit_code,
//             shard,
//             execution_shard,
//             next_execution_shard,
//             previous_init_addr_word,
//             last_init_addr_word,
//             previous_finalize_addr_word,
//             last_finalize_addr_word,
//             last_timestamp,
//             last_timestamp_inv,
//             global_init_count,
//             global_finalize_count,
//             global_count,
//             global_cumulative_sum,
//             ..
//         } = value;

//         let committed_value_digest: [_; PV_DIGEST_NUM_WORDS] = core::array::from_fn(|i| {
//             [
//                 F::from_canonical_u32(committed_value_digest[i] & 0xFF),
//                 F::from_canonical_u32((committed_value_digest[i] >> 8) & 0xFF),
//                 F::from_canonical_u32((committed_value_digest[i] >> 16) & 0xFF),
//                 F::from_canonical_u32((committed_value_digest[i] >> 24) & 0xFF),
//             ]
//         });

//         let deferred_proofs_digest: [_; POSEIDON_NUM_WORDS] =
//             core::array::from_fn(|i| F::from_canonical_u32(deferred_proofs_digest[i]));

//         let start_pc = F::from_canonical_u32(start_pc);
//         let next_pc = F::from_canonical_u32(next_pc);
//         let exit_code = F::from_canonical_u32(exit_code);
//         let shard = F::from_canonical_u32(shard);
//         let execution_shard = F::from_canonical_u32(execution_shard);
//         let next_execution_shard = F::from_canonical_u32(next_execution_shard);
//         let previous_init_addr_word = Word::from(previous_init_addr_word);
//         let last_init_addr_word = Word::from(last_init_addr_word);
//         let previous_finalize_addr_word = Word::from(previous_finalize_addr_word);
//         let last_finalize_addr_word = Word::from(last_finalize_addr_word);
//         let last_timestamp = F::from_canonical_u32(last_timestamp);
//         let last_timestamp_inv = F::from_canonical_u32(last_timestamp_inv);
//         let global_init_count = F::from_canonical_u32(global_init_count);
//         let global_finalize_count = F::from_canonical_u32(global_finalize_count);
//         let global_count = F::from_canonical_u32(global_count);
//         let global_cumulative_sum =
//             SepticDigest(SepticCurve::convert(global_cumulative_sum.0, F::from_canonical_u32));

//         Self {
//             committed_value_digest,
//             deferred_proofs_digest,
//             start_pc,
//             next_pc,
//             exit_code,
//             shard,
//             execution_shard,
//             next_execution_shard,
//             previous_init_addr_word,
//             last_init_addr_word,
//             previous_finalize_addr_word,
//             last_finalize_addr_word,
//             last_timestamp,
//             last_timestamp_inv,
//             global_init_count,
//             global_finalize_count,
//             global_count,
//             global_cumulative_sum,
//             empty: core::array::from_fn(|_| F::zero()),
//         }
//     }
// }
