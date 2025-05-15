use core::borrow::Borrow;
use hypercube_recursion_executor::Block;
use hypercube_stark::air::MachineAir;
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::Matrix;
use sp1_derive::AlignedBorrow;
use std::{iter::zip, marker::PhantomData};

use crate::builder::SP1RecursionAirBuilder;

use super::MemoryAccessCols;

pub const NUM_VAR_MEM_ENTRIES_PER_ROW: usize = 2;

#[derive(Default)]
pub struct MemoryVarChip<F> {
    _marker: PhantomData<F>,
}

pub const NUM_MEM_INIT_COLS: usize = core::mem::size_of::<MemoryVarCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryVarCols<F: Copy> {
    values: [Block<F>; NUM_VAR_MEM_ENTRIES_PER_ROW],
}

pub const NUM_MEM_PREPROCESSED_INIT_COLS: usize =
    core::mem::size_of::<MemoryVarPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryVarPreprocessedCols<F: Copy> {
    accesses: [MemoryAccessCols<F>; NUM_VAR_MEM_ENTRIES_PER_ROW],
}

impl<F: Send + Sync> BaseAir<F> for MemoryVarChip<F> {
    fn width(&self) -> usize {
        NUM_MEM_INIT_COLS
    }
}

impl<AB> Air<AB> for MemoryVarChip<AB::F>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryVarCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &MemoryVarPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (value, access) in zip(local.values, prep_local.accesses) {
            builder.send_block(access.addr, value, access.mult);
        }
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryVarChip<F> {
    fn name(&self) -> String {
        "MemoryVar".to_string()
    }
    fn preprocessed_width(&self) -> usize {
        NUM_MEM_PREPROCESSED_INIT_COLS
    }
}
