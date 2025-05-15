use core::borrow::Borrow;
use hypercube_recursion_executor::Block;
use hypercube_stark::air::MachineAir;
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::Matrix;
use sp1_derive::AlignedBorrow;
use std::marker::PhantomData;

use crate::builder::SP1RecursionAirBuilder;

use super::MemoryAccessCols;

pub const NUM_CONST_MEM_ENTRIES_PER_ROW: usize = 2;

#[derive(Default)]
pub struct MemoryConstChip<F> {
    _marker: PhantomData<F>,
}

pub const NUM_MEM_INIT_COLS: usize = core::mem::size_of::<MemoryConstCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryConstCols<F: Copy> {
    // At least one column is required, otherwise a bunch of things break.
    _nothing: F,
}

pub const NUM_MEM_PREPROCESSED_INIT_COLS: usize =
    core::mem::size_of::<MemoryConstPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryConstPreprocessedCols<F: Copy> {
    values_and_accesses: [(Block<F>, MemoryAccessCols<F>); NUM_CONST_MEM_ENTRIES_PER_ROW],
}
impl<F: Send + Sync> BaseAir<F> for MemoryConstChip<F> {
    fn width(&self) -> usize {
        NUM_MEM_INIT_COLS
    }
}

impl<AB> Air<AB> for MemoryConstChip<AB::F>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &MemoryConstPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (value, access) in prep_local.values_and_accesses {
            builder.send_block(access.addr, value, access.mult);
        }
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryConstChip<F> {
    fn name(&self) -> String {
        "MemoryConst".to_string()
    }
    fn preprocessed_width(&self) -> usize {
        NUM_MEM_PREPROCESSED_INIT_COLS
    }
}
