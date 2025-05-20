use core::fmt::Debug;
use hypercube_stark::{septic_digest::SepticDigest, Word, PROOF_MAX_NUM_PVS};
use hypercube_utils::indices_arr;
use p3_challenger::DuplexChallenger;
use p3_field::PrimeField32;
use p3_symmetric::CryptographicPermutation;
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;
use static_assertions::const_assert_eq;
use std::{
    borrow::BorrowMut,
    mem::{size_of, transmute, MaybeUninit},
};

use crate::{DIGEST_SIZE, HASH_RATE, PERMUTATION_WIDTH};

pub const PV_DIGEST_NUM_WORDS: usize = 8;

pub const CHALLENGER_STATE_NUM_ELTS: usize = size_of::<ChallengerPublicValues<u8>>();

pub const RECURSIVE_PROOF_NUM_PV_ELTS: usize = size_of::<RecursionPublicValues<u8>>();

const fn make_col_map() -> RecursionPublicValues<usize> {
    let indices_arr = indices_arr::<RECURSIVE_PROOF_NUM_PV_ELTS>();
    unsafe {
        transmute::<[usize; RECURSIVE_PROOF_NUM_PV_ELTS], RecursionPublicValues<usize>>(indices_arr)
    }
}

pub const RECURSION_PUBLIC_VALUES_COL_MAP: RecursionPublicValues<usize> = make_col_map();
pub const POSEIDON_NUM_WORDS: usize = 8;

// All the fields before `digest` are hashed to produce the digest.
pub const NUM_PV_ELMS_TO_HASH: usize = RECURSION_PUBLIC_VALUES_COL_MAP.digest[0];

// Recursive proof has more public values than core proof, so the max number constant defined in
// sp1_core should be set to `RECURSIVE_PROOF_NUM_PV_ELTS`.
const_assert_eq!(RECURSIVE_PROOF_NUM_PV_ELTS, PROOF_MAX_NUM_PVS);

#[derive(AlignedBorrow, Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct ChallengerPublicValues<T> {
    pub sponge_state: [T; PERMUTATION_WIDTH],
    pub num_inputs: T,
    pub input_buffer: [T; PERMUTATION_WIDTH],
    pub num_outputs: T,
    pub output_buffer: [T; PERMUTATION_WIDTH],
}

impl<T: Clone> ChallengerPublicValues<T> {
    pub fn set_challenger<P: CryptographicPermutation<[T; PERMUTATION_WIDTH]>>(
        &self,
        challenger: &mut DuplexChallenger<T, P, PERMUTATION_WIDTH, HASH_RATE>,
    ) where
        T: PrimeField32,
    {
        challenger.sponge_state = self.sponge_state;
        let num_inputs = self.num_inputs.as_canonical_u32() as usize;
        challenger.input_buffer = self.input_buffer[..num_inputs].to_vec();
        let num_outputs = self.num_outputs.as_canonical_u32() as usize;
        challenger.output_buffer = self.output_buffer[..num_outputs].to_vec();
    }

    pub fn as_array(&self) -> [T; CHALLENGER_STATE_NUM_ELTS]
    where
        T: Copy,
    {
        unsafe {
            let mut ret = [MaybeUninit::<T>::zeroed().assume_init(); CHALLENGER_STATE_NUM_ELTS];
            let pv: &mut ChallengerPublicValues<T> = ret.as_mut_slice().borrow_mut();
            *pv = *self;
            ret
        }
    }
}

/// The PublicValues struct is used to store all of a reduce proof's public values.
#[derive(AlignedBorrow, Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct RecursionPublicValues<T> {
    /// The hash of all the bytes that the program has written to public values.
    pub committed_value_digest: [[T; 4]; PV_DIGEST_NUM_WORDS],

    /// The hash of all deferred proofs that have been witnessed in the VM.
    pub deferred_proofs_digest: [T; POSEIDON_NUM_WORDS],

    /// The start pc of shards being proven.
    pub start_pc: T,

    /// The expected start pc for the next shard.
    pub next_pc: T,

    /// First shard being proven.
    pub start_shard: T,

    /// Next shard that should be proven.
    pub next_shard: T,

    /// First execution shard being proven.
    pub start_execution_shard: T,

    /// Next execution shard that should be proven.
    pub next_execution_shard: T,

    /// Previous MemoryInit address word.
    pub previous_init_addr_word: Word<T>,

    /// Last MemoryInit address word.
    pub last_init_addr_word: Word<T>,

    /// Previous MemoryFinalize address word.
    pub previous_finalize_addr_word: Word<T>,

    /// Last MemoryFinalize address word.
    pub last_finalize_addr_word: Word<T>,

    /// Start state of reconstruct_deferred_digest.
    pub start_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// End state of reconstruct_deferred_digest.
    pub end_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// The commitment to the sp1 program being proven.
    pub sp1_vk_digest: [T; DIGEST_SIZE],

    /// The root of the vk merkle tree.
    pub vk_root: [T; DIGEST_SIZE],

    /// Current cumulative sum of lookup bus. Note that for recursive proofs for core proofs, this
    /// contains the global cumulative sum.  
    pub global_cumulative_sum: SepticDigest<T>,

    /// Whether the proof completely proves the program execution.
    pub is_complete: T,

    /// The exit code of the program.
    pub exit_code: T,

    /// The digest of all the previous public values elements.
    pub digest: [T; DIGEST_SIZE],
}

/// Converts the public values to an array of elements.
impl<F: Copy> RecursionPublicValues<F> {
    pub fn as_array(&self) -> [F; RECURSIVE_PROOF_NUM_PV_ELTS] {
        unsafe {
            let mut ret = [MaybeUninit::<F>::zeroed().assume_init(); RECURSIVE_PROOF_NUM_PV_ELTS];
            let pv: &mut RecursionPublicValues<F> = ret.as_mut_slice().borrow_mut();
            *pv = *self;
            ret
        }
    }
}

impl<T: Copy> IntoIterator for RecursionPublicValues<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, RECURSIVE_PROOF_NUM_PV_ELTS>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_array().into_iter()
    }
}

impl<T: Copy> IntoIterator for ChallengerPublicValues<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, CHALLENGER_STATE_NUM_ELTS>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_array().into_iter()
    }
}
