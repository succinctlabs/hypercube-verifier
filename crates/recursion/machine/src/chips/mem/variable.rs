use core::borrow::Borrow;
use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use slop_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::MachineAir, next_multiple_of_32, pad_rows_fixed};
use sp1_recursion_executor::{
    instruction::{HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr},
    Block, ExecutionRecord, Instruction, RecursionProgram,
};
use std::{borrow::BorrowMut, iter::zip, marker::PhantomData};

use crate::builder::SP1RecursionAirBuilder;

use super::{MemoryAccessCols, NUM_MEM_ACCESS_COLS};

#[derive(Default, Clone)]
pub struct MemoryVarChip<F, const VAR_EVENTS_PER_ROW: usize> {
    _marker: PhantomData<F>,
}

pub const NUM_MEM_INIT_COLS: usize = core::mem::size_of::<MemoryVarCols<u8, 1>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryVarCols<F: Copy, const VAR_EVENTS_PER_ROW: usize> {
    values: [Block<F>; VAR_EVENTS_PER_ROW],
}

pub const NUM_MEM_PREPROCESSED_INIT_COLS: usize =
    core::mem::size_of::<MemoryVarPreprocessedCols<u8, 1>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryVarPreprocessedCols<F: Copy, const VAR_EVENTS_PER_ROW: usize> {
    accesses: [MemoryAccessCols<F>; VAR_EVENTS_PER_ROW],
}

impl<F: Send + Sync, const VAR_EVENTS_PER_ROW: usize> BaseAir<F>
    for MemoryVarChip<F, VAR_EVENTS_PER_ROW>
{
    fn width(&self) -> usize {
        NUM_MEM_INIT_COLS * VAR_EVENTS_PER_ROW
    }
}

impl<F: PrimeField32, const VAR_EVENTS_PER_ROW: usize> MachineAir<F>
    for MemoryVarChip<F, VAR_EVENTS_PER_ROW>
{
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "MemoryVar".to_string()
    }
    fn preprocessed_width(&self) -> usize {
        NUM_MEM_PREPROCESSED_INIT_COLS * VAR_EVENTS_PER_ROW
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        let height = program.shape.as_ref().and_then(|shape| shape.height(self));
        Some(next_multiple_of_32(instrs_len, height))
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // Allocating an intermediate `Vec` is faster.
        let accesses = program
            .inner
            .iter()
            // .par_bridge() // Using `rayon` here provides a big speedup. TODO put rayon back
            .flat_map(|instruction| match instruction.inner() {
                Instruction::Hint(HintInstr { output_addrs_mults })
                | Instruction::HintBits(HintBitsInstr {
                    output_addrs_mults,
                    input_addr: _, // No receive interaction for the hint operation
                }) => output_addrs_mults.iter().collect(),
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults,
                    input_addr: _, // No receive interaction for the hint operation
                }) => output_addrs_mults.iter().collect(),
                Instruction::HintAddCurve(instr) => {
                    let HintAddCurveInstr {
                        output_x_addrs_mults,
                        output_y_addrs_mults, .. // No receive interaction for the hint operation
                    } = instr.as_ref();
                    output_x_addrs_mults.iter().chain(output_y_addrs_mults.iter()).collect()
                }
                _ => vec![],
            })
            .collect::<Vec<_>>();

        let nb_rows = accesses.len().div_ceil(VAR_EVENTS_PER_ROW);
        let padded_nb_rows = self.preprocessed_num_rows(program, nb_rows).unwrap();
        let mut values =
            vec![F::zero(); padded_nb_rows * NUM_MEM_PREPROCESSED_INIT_COLS * VAR_EVENTS_PER_ROW];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = accesses.len() * NUM_MEM_ACCESS_COLS;
        values[..populate_len]
            .par_chunks_mut(NUM_MEM_ACCESS_COLS)
            .zip_eq(accesses)
            .for_each(|(row, &(addr, mult))| *row.borrow_mut() = MemoryAccessCols { addr, mult });

        Some(RowMajorMatrix::new(values, NUM_MEM_PREPROCESSED_INIT_COLS * VAR_EVENTS_PER_ROW))
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let height = input.program.shape.as_ref().and_then(|shape| shape.height(self));
        let nb_rows = input.mem_var_events.len().div_ceil(VAR_EVENTS_PER_ROW);
        let padded_nb_rows = next_multiple_of_32(nb_rows, height);
        Some(padded_nb_rows)
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let mut rows = input
            .mem_var_events
            .chunks(VAR_EVENTS_PER_ROW)
            .map(|row_events| {
                let mut row = vec![F::zero(); NUM_MEM_INIT_COLS * VAR_EVENTS_PER_ROW];
                let cols: &mut MemoryVarCols<_, VAR_EVENTS_PER_ROW> =
                    row.as_mut_slice().borrow_mut();
                for (cell, vals) in zip(&mut cols.values, row_events) {
                    *cell = vals.inner;
                }
                row
            })
            .collect::<Vec<_>>();

        let height = input.program.shape.as_ref().and_then(|shape| shape.height(self));
        // Pad the rows to the next multiple of 32.
        pad_rows_fixed(
            &mut rows,
            || vec![F::zero(); NUM_MEM_INIT_COLS * VAR_EVENTS_PER_ROW],
            height,
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEM_INIT_COLS * VAR_EVENTS_PER_ROW,
        )
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB, const VAR_EVENTS_PER_ROW: usize> Air<AB> for MemoryVarChip<AB::F, VAR_EVENTS_PER_ROW>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryVarCols<AB::Var, VAR_EVENTS_PER_ROW> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &MemoryVarPreprocessedCols<AB::Var, VAR_EVENTS_PER_ROW> =
            (*prep_local).borrow();

        for (value, access) in zip(local.values, prep_local.accesses) {
            builder.send_block(access.addr, value, access.mult);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use slop_algebra::AbstractField;

    use slop_matrix::dense::RowMajorMatrix;
    use sp1_primitives::SP1Field;
    use sp1_recursion_executor::MemEvent;

    use crate::chips::test_fixtures;

    use super::*;

    #[tokio::test]
    async fn generate_trace() {
        let shard = test_fixtures::shard().await;
        let chip = MemoryVarChip::<_, 2>::default();
        let trace = chip.generate_trace(shard, &mut ExecutionRecord::default());
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }

    #[tokio::test]
    async fn generate_preprocessed_trace() {
        let program = &test_fixtures::program_with_input().await.0;
        let chip = MemoryVarChip::<_, 2>::default();
        let trace = chip.generate_preprocessed_trace(program).unwrap();
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }

    #[test]
    pub fn generate_trace_simple() {
        let shard = ExecutionRecord::<SP1Field> {
            mem_var_events: vec![
                MemEvent { inner: SP1Field::one().into() },
                MemEvent { inner: SP1Field::one().into() },
            ],
            ..Default::default()
        };
        let chip = MemoryVarChip::<_, 2>::default();
        let trace: RowMajorMatrix<SP1Field> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
