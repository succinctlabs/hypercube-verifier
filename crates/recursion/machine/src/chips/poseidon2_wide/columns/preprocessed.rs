use hypercube_recursion_executor::Address;
use sp1_core_machine::operations::poseidon2::WIDTH;
use sp1_derive::AlignedBorrow;

use crate::chips::mem::MemoryAccessColsChips;

/// A column layout for the preprocessed Poseidon2 AIR.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedColsWide<T: Copy> {
    pub input: [Address<T>; WIDTH],
    pub output: [MemoryAccessColsChips<T>; WIDTH],
    pub is_real_neg: T,
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2WideChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2WideDeg{}", DEGREE)
    }
}
