use crate::builder::SP1RecursionAirBuilder;
use core::borrow::Borrow;
use hypercube_recursion_executor::{Address, BaseAluIo};
use hypercube_stark::air::MachineAir;
use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::{Field, PrimeField32};
use p3_matrix::Matrix;
use sp1_derive::AlignedBorrow;
use std::iter::zip;

pub const NUM_BASE_ALU_ENTRIES_PER_ROW: usize = 4;

#[derive(Default)]
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
    fn name(&self) -> String {
        "BaseAlu".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BASE_ALU_PREPROCESSED_COLS
    }
}

//     fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
//         let height = program.shape.as_ref().and_then(|shape| shape.height(self));
//         let nb_rows = instrs_len.div_ceil(NUM_BASE_ALU_ENTRIES_PER_ROW);
//         Some(next_multiple_of_32(nb_rows, height))
//     }

//     fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
//         assert_eq!(
//             std::any::TypeId::of::<F>(),
//             std::any::TypeId::of::<BabyBear>(),
//             "generate_preprocessed_trace only supports BabyBear field"
//         );

//         let instrs = unsafe {
//             std::mem::transmute::<Vec<&BaseAluInstr<F>>, Vec<&BaseAluInstr<BabyBear>>>(
//                 program
//                     .inner
//                     .iter()
//                     .filter_map(|instruction| match instruction.inner() {
//                         Instruction::BaseAlu(x) => Some(x),
//                         _ => None,
//                     })
//                     .collect::<Vec<_>>(),
//             )
//         };
//         let padded_nb_rows = self.preprocessed_num_rows(program, instrs.len()).unwrap();
//         let mut values = vec![BabyBear::zero(); padded_nb_rows * NUM_BASE_ALU_PREPROCESSED_COLS];

//         // Generate the trace rows & corresponding records for each chunk of events in parallel.
//         let populate_len = instrs.len() * NUM_BASE_ALU_ACCESS_COLS;
//         values[..populate_len].par_chunks_mut(NUM_BASE_ALU_ACCESS_COLS).zip_eq(instrs).for_each(
//             |(row, instr)| {
//                 let access: &mut BaseAluAccessCols<_> = row.borrow_mut();
//                 unsafe {
//                     crate::sys::alu_base_instr_to_row_babybear(instr, access);
//                 }
//             },
//         );

//         // Convert the trace to a row major matrix.
//         Some(RowMajorMatrix::new(
//             unsafe { std::mem::transmute::<Vec<BabyBear>, Vec<F>>(values) },
//             NUM_BASE_ALU_PREPROCESSED_COLS,
//         ))
//     }

//     fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
//         // This is a no-op.
//     }

//     fn num_rows(&self, input: &Self::Record) -> Option<usize> {
//         let height = input.program.shape.as_ref().and_then(|shape| shape.height(self));
//         let nb_rows = input.base_alu_events.len().div_ceil(NUM_BASE_ALU_ENTRIES_PER_ROW);
//         Some(next_multiple_of_32(nb_rows, height))
//     }

//     fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
//         assert_eq!(
//             std::any::TypeId::of::<F>(),
//             std::any::TypeId::of::<BabyBear>(),
//             "generate_trace only supports BabyBear field"
//         );

//         let events = unsafe {
//             std::mem::transmute::<&Vec<BaseAluIo<F>>, &Vec<BaseAluIo<BabyBear>>>(
//                 &input.base_alu_events,
//             )
//         };
//         let padded_nb_rows = self.num_rows(input).unwrap();
//         let mut values = vec![BabyBear::zero(); padded_nb_rows * NUM_BASE_ALU_COLS];

//         // Generate the trace rows & corresponding records for each chunk of events in parallel.
//         let populate_len = events.len() * NUM_BASE_ALU_VALUE_COLS;
//         values[..populate_len].par_chunks_mut(NUM_BASE_ALU_VALUE_COLS).zip_eq(events).for_each(
//             |(row, &vals)| {
//                 let cols: &mut BaseAluValueCols<_> = row.borrow_mut();
//                 unsafe {
//                     crate::sys::alu_base_event_to_row_babybear(&vals, cols);
//                 }
//             },
//         );

//         // Convert the trace to a row major matrix.
//         RowMajorMatrix::new(
//             unsafe { std::mem::transmute::<Vec<BabyBear>, Vec<F>>(values) },
//             NUM_BASE_ALU_COLS,
//         )
//     }

//     fn included(&self, _record: &Self::Record) -> bool {
//         true
//     }

//     fn local_only(&self) -> bool {
//         true
//     }
// }

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

            builder.receive_single(addrs.in1, in1, is_real.clone());

            builder.receive_single(addrs.in2, in2, is_real);

            builder.send_single(addrs.out, out, mult);
        }
    }
}
