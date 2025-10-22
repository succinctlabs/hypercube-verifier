use crate::builder::SP1RecursionAirBuilder;
use core::borrow::Borrow;
use slop_air::{Air, AirBuilder, BaseAir, PairBuilder};
use slop_algebra::{AbstractField, Field, PrimeField32};
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use slop_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::MachineAir, next_multiple_of_32};
use sp1_primitives::SP1Field;
use sp1_recursion_executor::{
    Address, BaseAluInstr, BaseAluIo, BaseAluOpcode, ExecutionRecord, Instruction, RecursionProgram,
};
use std::{borrow::BorrowMut, iter::zip};

pub const NUM_BASE_ALU_ENTRIES_PER_ROW: usize = 1;

#[derive(Default, Clone)]
pub struct BaseAluChip;

pub const NUM_BASE_ALU_COLS: usize = core::mem::size_of::<BaseAluCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluCols<F: Copy> {
    pub values: [BaseAluValueCols<F>; NUM_BASE_ALU_ENTRIES_PER_ROW],
}

pub const NUM_BASE_ALU_VALUE_COLS: usize = core::mem::size_of::<BaseAluValueCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluValueCols<F: Copy> {
    pub vals: BaseAluIo<F>,
}

pub const NUM_BASE_ALU_PREPROCESSED_COLS: usize =
    core::mem::size_of::<BaseAluPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluPreprocessedCols<F: Copy> {
    pub accesses: [BaseAluAccessCols<F>; NUM_BASE_ALU_ENTRIES_PER_ROW],
}

pub const NUM_BASE_ALU_ACCESS_COLS: usize = core::mem::size_of::<BaseAluAccessCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluAccessCols<F: Copy> {
    pub addrs: BaseAluIo<Address<F>>,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub is_div: F,
    pub mult: F,
}

impl<F: Field> BaseAir<F> for BaseAluChip {
    fn width(&self) -> usize {
        NUM_BASE_ALU_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for BaseAluChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "BaseAlu".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BASE_ALU_PREPROCESSED_COLS
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        let height = program.shape.as_ref().and_then(|shape| shape.height(self));
        let nb_rows = instrs_len.div_ceil(NUM_BASE_ALU_ENTRIES_PER_ROW);
        Some(next_multiple_of_32(nb_rows, height))
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<SP1Field>(),
            "generate_preprocessed_trace only supports SP1Field field"
        );

        let instrs = unsafe {
            std::mem::transmute::<Vec<&BaseAluInstr<F>>, Vec<&BaseAluInstr<SP1Field>>>(
                program
                    .inner
                    .iter()
                    .filter_map(|instruction| match instruction.inner() {
                        Instruction::BaseAlu(x) => Some(x),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let padded_nb_rows = self.preprocessed_num_rows(program, instrs.len()).unwrap();
        let mut values = vec![SP1Field::zero(); padded_nb_rows * NUM_BASE_ALU_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * NUM_BASE_ALU_ACCESS_COLS;
        values[..populate_len].par_chunks_mut(NUM_BASE_ALU_ACCESS_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let BaseAluInstr { opcode, mult, addrs } = instr;
                let access: &mut BaseAluAccessCols<_> = row.borrow_mut();
                *access = BaseAluAccessCols {
                    addrs: addrs.to_owned(),
                    is_add: SP1Field::from_bool(false),
                    is_sub: SP1Field::from_bool(false),
                    is_mul: SP1Field::from_bool(false),
                    is_div: SP1Field::from_bool(false),
                    mult: mult.to_owned(),
                };
                let target_flag = match opcode {
                    BaseAluOpcode::AddF => &mut access.is_add,
                    BaseAluOpcode::SubF => &mut access.is_sub,
                    BaseAluOpcode::MulF => &mut access.is_mul,
                    BaseAluOpcode::DivF => &mut access.is_div,
                };
                *target_flag = SP1Field::from_bool(true);
            },
        );

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<SP1Field>, Vec<F>>(values) },
            NUM_BASE_ALU_PREPROCESSED_COLS,
        ))
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let height = input.program.shape.as_ref().and_then(|shape| shape.height(self));
        let nb_rows = input.base_alu_events.len().div_ceil(NUM_BASE_ALU_ENTRIES_PER_ROW);
        Some(next_multiple_of_32(nb_rows, height))
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<SP1Field>(),
            "generate_trace only supports SP1Field field"
        );

        let events = unsafe {
            std::mem::transmute::<&Vec<BaseAluIo<F>>, &Vec<BaseAluIo<SP1Field>>>(
                &input.base_alu_events,
            )
        };
        let padded_nb_rows = self.num_rows(input).unwrap();
        let mut values = vec![SP1Field::zero(); padded_nb_rows * NUM_BASE_ALU_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * NUM_BASE_ALU_VALUE_COLS;
        values[..populate_len].par_chunks_mut(NUM_BASE_ALU_VALUE_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut BaseAluValueCols<_> = row.borrow_mut();
                *cols = BaseAluValueCols { vals };
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<SP1Field>, Vec<F>>(values) },
            NUM_BASE_ALU_COLS,
        )
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for BaseAluChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BaseAluCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &BaseAluPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (
            BaseAluValueCols { vals: BaseAluIo { out, in1, in2 } },
            BaseAluAccessCols { addrs, is_add, is_sub, is_mul, is_div, mult },
        ) in zip(local.values, prep_local.accesses)
        {
            // Check exactly one flag is enabled.
            let is_real = is_add + is_sub + is_mul + is_div;
            builder.assert_bool(is_real.clone());

            builder.when(is_add).assert_eq(in1 + in2, out);
            builder.when(is_sub).assert_eq(in1, in2 + out);
            builder.when(is_mul).assert_eq(out, in1 * in2);
            builder.when(is_div).assert_eq(in2 * out, in1);

            // Read the inputs from memory.
            builder.receive_single(addrs.in1, in1, is_real.clone());
            builder.receive_single(addrs.in2, in2, is_real);

            // Write the output to memory.
            builder.send_single(addrs.out, out, mult);
        }
    }
}

#[cfg(test)]
mod tests {

    use rand::prelude::*;
    use sp1_recursion_executor::{instruction as instr, BaseAluOpcode, MemAccessKind};

    use crate::{chips::test_fixtures, test::test_recursion_linear_program};

    use super::*;

    #[tokio::test]
    async fn generate_trace() {
        let shard = test_fixtures::shard().await;
        let trace = BaseAluChip.generate_trace(shard, &mut ExecutionRecord::default());
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }

    #[tokio::test]
    async fn generate_preprocessed_trace() {
        let program = &test_fixtures::program_with_input().await.0;
        let trace = BaseAluChip.generate_preprocessed_trace(program).unwrap();
        assert!(trace.height() > test_fixtures::MIN_ROWS);
    }

    #[tokio::test]
    pub async fn four_ops() {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> SP1Field { rng.sample(rand::distributions::Standard) };
        let mut addr = 0;

        let instructions = (0..1000)
            .flat_map(|_| {
                let quot = random_felt();
                let in2 = random_felt();
                let in1 = in2 * quot;
                let alloc_size = 6;
                let a = (0..alloc_size).map(|x| x + addr).collect::<Vec<_>>();
                addr += alloc_size;
                [
                    instr::mem_single(MemAccessKind::Write, 4, a[0], in1),
                    instr::mem_single(MemAccessKind::Write, 4, a[1], in2),
                    instr::base_alu(BaseAluOpcode::AddF, 1, a[2], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[2], in1 + in2),
                    instr::base_alu(BaseAluOpcode::SubF, 1, a[3], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[3], in1 - in2),
                    instr::base_alu(BaseAluOpcode::MulF, 1, a[4], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[4], in1 * in2),
                    instr::base_alu(BaseAluOpcode::DivF, 1, a[5], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[5], quot),
                ]
            })
            .collect::<Vec<Instruction<SP1Field>>>();

        test_recursion_linear_program(instructions).await;
    }
}
