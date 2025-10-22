use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::{
    memory::MemoryAccessCols,
    operations::{
        Add4Operation, AddrAddOperation, ClkOperation, FixedRotateRightOperation,
        FixedShiftRightOperation, XorU32Operation,
    },
};

pub const NUM_SHA_EXTEND_COLS: usize = size_of::<ShaExtendCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaExtendCols<T> {
    /// Inputs.
    pub clk_high: T,
    pub clk_low: T,
    pub next_clk: ClkOperation<T>,
    pub w_ptr: [T; 3],
    pub w_i_minus_15_ptr: AddrAddOperation<T>,
    pub w_i_minus_2_ptr: AddrAddOperation<T>,
    pub w_i_minus_16_ptr: AddrAddOperation<T>,
    pub w_i_minus_7_ptr: AddrAddOperation<T>,
    pub w_i_ptr: AddrAddOperation<T>,

    /// Control flags.
    pub i: T,

    /// Inputs to `s0`.
    pub w_i_minus_15: MemoryAccessCols<T>,
    pub w_i_minus_15_rr_7: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rr_18: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rs_3: FixedShiftRightOperation<T>,
    pub s0_intermediate: XorU32Operation<T>,

    /// `s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)`.
    pub s0: XorU32Operation<T>,

    /// Inputs to `s1`.
    pub w_i_minus_2: MemoryAccessCols<T>,
    pub w_i_minus_2_rr_17: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rr_19: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rs_10: FixedShiftRightOperation<T>,
    pub s1_intermediate: XorU32Operation<T>,

    /// `s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)`.
    pub s1: XorU32Operation<T>,

    /// Inputs to `s2`.
    pub w_i_minus_16: MemoryAccessCols<T>,
    pub w_i_minus_7: MemoryAccessCols<T>,

    /// `w[i] := w[i-16] + s0 + w[i-7] + s1`.
    pub s2: Add4Operation<T>,

    /// Result.
    pub w_i: MemoryAccessCols<T>,

    /// Selector.
    pub is_real: T,
}
