use sp1_derive::AlignedBorrow;
use sp1_hypercube::operations::poseidon2::WIDTH;
use sp1_recursion_executor::Address;

use crate::chips::mem::MemoryAccessColsChips;

/// A column layout for the preprocessed Poseidon2 AIR.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedColsWide<T: Copy> {
    pub input: [Address<T>; WIDTH],
    pub output: [MemoryAccessColsChips<T>; WIDTH],
    pub is_real: T,
}
