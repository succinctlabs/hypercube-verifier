use core::borrow::Borrow;
use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::{extension::BinomiallyExtendable, AbstractField, Field, PrimeField32};
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use slop_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::MachineAir, next_multiple_of_32};
use sp1_primitives::SP1Field;
use sp1_recursion_executor::{
    Address, Block, ExecutionRecord, ExtFeltEvent, ExtFeltInstr, Instruction, RecursionProgram, D,
};
use std::{borrow::BorrowMut, iter::zip};

use crate::builder::SP1RecursionAirBuilder;

pub const NUM_CONVERT_ENTRIES_PER_ROW: usize = 1;

#[derive(Default, Clone)]
pub struct ConvertChip;

pub const NUM_CONVERT_COLS: usize = core::mem::size_of::<ConvertCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ConvertCols<F: Copy> {
    pub values: [ConvertValueCols<F>; NUM_CONVERT_ENTRIES_PER_ROW],
}
const NUM_CONVERT_VALUE_COLS: usize = core::mem::size_of::<ConvertValueCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ConvertValueCols<F: Copy> {
    pub input: Block<F>,
}

pub const NUM_CONVERT_PREPROCESSED_COLS: usize =
    core::mem::size_of::<ConvertPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ConvertPreprocessedCols<F: Copy> {
    pub accesses: [ConvertAccessCols<F>; NUM_CONVERT_ENTRIES_PER_ROW],
}

pub const NUM_CONVERT_ACCESS_COLS: usize = core::mem::size_of::<ConvertAccessCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ConvertAccessCols<F: Copy> {
    pub addrs: [Address<F>; 5],
    pub mults: [F; 5],
}

impl<F: Field> BaseAir<F> for ConvertChip {
    fn width(&self) -> usize {
        NUM_CONVERT_COLS
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> MachineAir<F> for ConvertChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "ExtFeltConvert".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_CONVERT_PREPROCESSED_COLS
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        let height = program.shape.as_ref().and_then(|shape| shape.height(self));

        let nb_rows = instrs_len.div_ceil(NUM_CONVERT_ENTRIES_PER_ROW);
        Some(next_multiple_of_32(nb_rows, height))
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<SP1Field>(),
            "generate_preprocessed_trace only supports SP1Field field"
        );

        let instrs = unsafe {
            std::mem::transmute::<Vec<&ExtFeltInstr<F>>, Vec<&ExtFeltInstr<SP1Field>>>(
                program
                    .inner
                    .iter()
                    .filter_map(|instruction| match instruction.inner() {
                        Instruction::ExtFelt(x) => Some(x),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let padded_nb_rows = self.preprocessed_num_rows(program, instrs.len()).unwrap();
        let mut values = vec![SP1Field::zero(); padded_nb_rows * NUM_CONVERT_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * NUM_CONVERT_ACCESS_COLS;
        values[..populate_len].par_chunks_mut(NUM_CONVERT_ACCESS_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let ExtFeltInstr { addrs, mults, ext2felt } = instr;
                let access: &mut ConvertAccessCols<_> = row.borrow_mut();
                access.addrs = addrs.to_owned();
                if *ext2felt {
                    access.mults[0] = SP1Field::one();
                    access.mults[1] = mults[1];
                    access.mults[2] = mults[2];
                    access.mults[3] = mults[3];
                    access.mults[4] = mults[4];
                } else {
                    access.mults[0] = -mults[0];
                    access.mults[1] = -SP1Field::one();
                    access.mults[2] = -SP1Field::one();
                    access.mults[3] = -SP1Field::one();
                    access.mults[4] = -SP1Field::one();
                }
            },
        );

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<SP1Field>, Vec<F>>(values) },
            NUM_CONVERT_PREPROCESSED_COLS,
        ))
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let height = input.program.shape.as_ref().and_then(|shape| shape.height(self));
        let events = &input.ext_felt_conversion_events;
        let nb_rows = events.len().div_ceil(NUM_CONVERT_ENTRIES_PER_ROW);
        Some(next_multiple_of_32(nb_rows, height))
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<SP1Field>(),
            "generate_trace only supports SP1Field field"
        );

        let events = unsafe {
            std::mem::transmute::<&Vec<ExtFeltEvent<F>>, &Vec<ExtFeltEvent<SP1Field>>>(
                &input.ext_felt_conversion_events,
            )
        };
        let padded_nb_rows = self.num_rows(input).unwrap();
        let mut values = vec![SP1Field::zero(); padded_nb_rows * NUM_CONVERT_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * NUM_CONVERT_VALUE_COLS;
        values[..populate_len].par_chunks_mut(NUM_CONVERT_VALUE_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut ConvertValueCols<_> = row.borrow_mut();
                cols.input = vals.input.to_owned();
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<SP1Field>, Vec<F>>(values) },
            NUM_CONVERT_COLS,
        )
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for ConvertChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ConvertCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &ConvertPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (ConvertValueCols { input }, ConvertAccessCols { addrs, mults }) in
            zip(local.values, prep_local.accesses)
        {
            // First handle the read/write of the extension element.
            // If it's converting extension element to `D` field elements, this is a read.
            // If it's converting `D` field elements to an extension element, this is a write.
            builder.receive_block(addrs[0], input, mults[0]);

            // Handle the read/write of the field element.
            // If it's converting extension element to `D` field elements, this is a write.
            // If it's converting `D` field elements to an extension element, this is a read.
            for i in 0..D {
                builder.send_single(addrs[i + 1], input[i], mults[i + 1]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use slop_matrix::Matrix;
    use sp1_hypercube::air::MachineAir;
    use sp1_recursion_executor::ExecutionRecord;

    use super::ConvertChip;

    use crate::chips::test_fixtures;

    #[tokio::test]
    async fn generate_trace() {
        let shard = test_fixtures::shard().await;
        let trace = ConvertChip.generate_trace(shard, &mut ExecutionRecord::default());
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }

    #[tokio::test]
    async fn generate_preprocessed_trace() {
        let program = &test_fixtures::program_with_input().await.0;
        let trace = ConvertChip.generate_preprocessed_trace(program).unwrap();
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }
}
