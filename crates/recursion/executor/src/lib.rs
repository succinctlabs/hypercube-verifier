pub mod analyzed;
mod block;
pub mod instruction;
mod opcode;
mod program;
mod public_values;
mod record;
pub mod shape;

pub use public_values::PV_DIGEST_NUM_WORDS;

// Avoid triggering annoying branch of thiserror derive macro.
pub use block::Block;
pub use opcode::*;
use p3_field::PrimeField64;
pub use public_values::{
    RecursionPublicValues, NUM_PV_ELMS_TO_HASH, POSEIDON_NUM_WORDS, RECURSIVE_PROOF_NUM_PV_ELTS,
};
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;
use std::fmt::Debug;

/// The width of the Poseidon2 permutation.
pub const PERMUTATION_WIDTH: usize = 16;
pub const POSEIDON2_SBOX_DEGREE: u64 = 7;
pub const HASH_RATE: usize = 8;

/// The current verifier implementation assumes that we are using a 256-bit hash with 32-bit
/// elements.
pub const DIGEST_SIZE: usize = 8;

pub const NUM_BITS: usize = 31;

pub const D: usize = 4;

#[derive(
    AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default,
)]
#[repr(transparent)]
pub struct Address<F>(pub F);

impl<F: PrimeField64> Address<F> {
    #[inline]
    pub fn as_usize(&self) -> usize {
        self.0.as_canonical_u64() as usize
    }
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to an operation of the base field ALU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BaseAluIo<V> {
    pub out: V,
    pub in1: V,
    pub in2: V,
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to an operation of the extension field ALU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct ExtAluIo<V> {
    pub out: V,
    pub in1: V,
    pub in2: V,
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to the manual memory management/memory initialization table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct MemIo<V> {
    pub inner: V,
}

// -------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemAccessKind {
    Read,
    Write,
}

/// The inputs and outputs to a Poseidon2 permutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Poseidon2Io<V> {
    pub input: [V; PERMUTATION_WIDTH],
    pub output: [V; PERMUTATION_WIDTH],
}

/// The inputs and outputs to a select operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct SelectIo<V> {
    pub bit: V,
    pub out1: V,
    pub out2: V,
    pub in1: V,
    pub in2: V,
}

/// The inputs and outputs to the operations for prefix sum checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixSumChecksIo<V> {
    pub zero: V,
    pub one: V,
    pub x1: Vec<V>,
    pub x2: Vec<V>,
    pub accs: Vec<V>,
    pub field_accs: Vec<V>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFRIIo<V> {
    pub ext_single: BatchFRIExtSingleIo<Block<V>>,
    pub ext_vec: BatchFRIExtVecIo<Vec<Block<V>>>,
    pub base_vec: BatchFRIBaseVecIo<V>,
}

/// The extension-field-valued single inputs to the batch FRI operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIExtSingleIo<V> {
    pub acc: V,
}

/// The extension-field-valued vector inputs to the batch FRI operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIExtVecIo<V> {
    pub p_at_z: V,
    pub alpha_pow: V,
}

/// The base-field-valued vector inputs to the batch FRI operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIBaseVecIo<V> {
    pub p_at_x: V,
}
