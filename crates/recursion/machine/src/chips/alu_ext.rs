use core::borrow::Borrow;
use hypercube_recursion_executor::{Address, Block, ExtAluIo, D};
use hypercube_stark::air::{ExtensionAirBuilder, MachineAir};
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::{extension::BinomiallyExtendable, Field, PrimeField32};
use p3_matrix::Matrix;
use sp1_derive::AlignedBorrow;
use std::iter::zip;

use crate::builder::SP1RecursionAirBuilder;

pub const NUM_EXT_ALU_ENTRIES_PER_ROW: usize = 4;

#[derive(Default)]
pub struct ExtAluChip;

pub const NUM_EXT_ALU_COLS: usize = core::mem::size_of::<ExtAluCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluCols<F: Copy> {
    pub values: [ExtAluValueCols<F>; NUM_EXT_ALU_ENTRIES_PER_ROW],
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluValueCols<F: Copy> {
    pub vals: ExtAluIo<Block<F>>,
}

pub const NUM_EXT_ALU_PREPROCESSED_COLS: usize = core::mem::size_of::<ExtAluPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluPreprocessedCols<F: Copy> {
    pub accesses: [ExtAluAccessCols<F>; NUM_EXT_ALU_ENTRIES_PER_ROW],
}

pub const NUM_EXT_ALU_ACCESS_COLS: usize = core::mem::size_of::<ExtAluAccessCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluAccessCols<F: Copy> {
    pub addrs: ExtAluIo<Address<F>>,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub is_div: F,
    pub mult: F,
}

impl<F: Field> BaseAir<F> for ExtAluChip {
    fn width(&self) -> usize {
        NUM_EXT_ALU_COLS
    }
}

impl<AB> Air<AB> for ExtAluChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ExtAluCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &ExtAluPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (
            ExtAluValueCols { vals },
            ExtAluAccessCols { addrs, is_add, is_sub, is_mul, is_div, mult },
        ) in zip(local.values, prep_local.accesses)
        {
            let in1 = vals.in1.as_extension::<AB>();
            let in2 = vals.in2.as_extension::<AB>();
            let out = vals.out.as_extension::<AB>();

            // Check exactly one flag is enabled.
            let is_real = is_add + is_sub + is_mul + is_div;
            builder.assert_bool(is_real.clone());

            builder.when(is_add).assert_ext_eq(in1.clone() + in2.clone(), out.clone());
            builder.when(is_sub).assert_ext_eq(in1.clone(), in2.clone() + out.clone());
            builder.when(is_mul).assert_ext_eq(in1.clone() * in2.clone(), out.clone());
            builder.when(is_div).assert_ext_eq(in1, in2 * out);

            // Read the inputs from memory.
            builder.receive_block(addrs.in1, vals.in1, is_real.clone());

            builder.receive_block(addrs.in2, vals.in2, is_real);

            // Write the output to memory.
            builder.send_block(addrs.out, vals.out, mult);
        }
    }
}
impl<F: PrimeField32 + BinomiallyExtendable<D>> MachineAir<F> for ExtAluChip {
    fn name(&self) -> String {
        "ExtAlu".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXT_ALU_PREPROCESSED_COLS
    }
}
