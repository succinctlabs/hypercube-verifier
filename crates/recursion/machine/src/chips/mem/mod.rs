pub mod constant;
pub mod variable;

pub use constant::MemoryConstChip;
use sp1_recursion_executor::Address;
pub use variable::MemoryVarChip;

use sp1_derive::AlignedBorrow;

pub const NUM_MEM_ACCESS_COLS: usize = core::mem::size_of::<MemoryAccessCols<u8>>();

/// Data describing in what manner to access a particular memory block.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessColsChips<F: Copy> {
    /// The address to access.
    pub addr: Address<F>,
    /// The multiplicity which to read/write.
    /// "Positive" values indicate a write, and "negative" values indicate a read.
    pub mult: F,
}

/// Avoids cbindgen naming collisions.
pub type MemoryAccessCols<F> = MemoryAccessColsChips<F>;
