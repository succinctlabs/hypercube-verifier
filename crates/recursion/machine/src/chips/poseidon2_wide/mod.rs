use std::{borrow::Borrow, ops::Deref};

use hypercube_recursion_executor::Address;
use hypercube_stark::air::MachineAir;
use p3_air::BaseAir;
use p3_field::PrimeField32;
use permutation::{Poseidon2Cols, Poseidon2Degree3Cols, NUM_POSEIDON2_DEGREE3_COLS};
use sp1_derive::AlignedBorrow;

use super::mem::MemoryAccessColsChips;

pub mod air;
pub mod permutation;
pub mod trace;

/// The width of the permutation.
pub const WIDTH: usize = 16;

/// The rate of the permutation.
pub const RATE: usize = WIDTH / 2;

/// The number of external rounds.
pub const NUM_EXTERNAL_ROUNDS: usize = 8;

/// The number of internal rounds.
pub const NUM_INTERNAL_ROUNDS: usize = 13;

/// The total number of rounds.
pub const NUM_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;

/// The number of columns in the Poseidon2 operation.
pub const NUM_POSEIDON2_OPERATION_COLUMNS: usize = std::mem::size_of::<Poseidon2Operation<u8>>();

/// A column layout for the preprocessed Poseidon2 AIR.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedColsWide<T: Copy> {
    pub input: [Address<T>; WIDTH],
    pub output: [MemoryAccessColsChips<T>; WIDTH],
    pub is_real_neg: T,
}

const PREPROCESSED_POSEIDON2_WIDTH: usize = size_of::<Poseidon2PreprocessedColsWide<u8>>();

/// A chip that implements addition for the opcode Poseidon2Wide.
#[derive(Default, Debug, Clone, Copy)]
pub struct Poseidon2WideChip<const DEGREE: usize>;

impl<'a, const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    /// Transmute a row it to an immutable [`Poseidon2Cols`] instance.
    pub fn convert<T>(row: impl Deref<Target = [T]>) -> Box<dyn Poseidon2Cols<T> + 'a>
    where
        T: Copy + 'a,
    {
        if DEGREE == 3 {
            let convert: &Poseidon2Degree3Cols<T> = (*row).borrow();
            Box::new(*convert)
        } else {
            panic!("Unsupported degree");
        }
    }
}

/// A set of columns needed to compute the Poseidon2 operation.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Operation<T: Copy> {
    /// The permutation.
    pub permutation: Poseidon2Degree3Cols<T>,
}

impl<F, const DEGREE: usize> BaseAir<F> for Poseidon2WideChip<DEGREE> {
    fn width(&self) -> usize {
        if DEGREE == 3 {
            NUM_POSEIDON2_DEGREE3_COLS
        } else {
            panic!("Unsupported degree: {}", DEGREE);
        }
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2WideChip<DEGREE> {
    fn name(&self) -> String {
        format!("Poseidon2WideDeg{}", DEGREE)
    }

    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_POSEIDON2_WIDTH
    }
}
