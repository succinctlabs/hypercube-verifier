use crate::builder::SP1RecursionAirBuilder;
use hypercube_recursion_executor::{
    RecursionPublicValues, DIGEST_SIZE, RECURSIVE_PROOF_NUM_PV_ELTS,
};
use hypercube_stark::air::MachineAir;
use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::Matrix;
use sp1_derive::AlignedBorrow;
use std::borrow::Borrow;

use super::mem::MemoryAccessColsChips;

pub const NUM_PUBLIC_VALUES_COLS: usize = core::mem::size_of::<PublicValuesCols<u8>>();
pub const NUM_PUBLIC_VALUES_PREPROCESSED_COLS: usize =
    core::mem::size_of::<PublicValuesPreprocessedCols<u8>>();

pub const PUB_VALUES_LOG_HEIGHT: usize = 4;

#[derive(Default)]
pub struct PublicValuesChip;

/// The preprocessed columns for the CommitPVHash instruction.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PublicValuesPreprocessedCols<T: Copy> {
    pub pv_idx: [T; DIGEST_SIZE],
    pub pv_mem: MemoryAccessColsChips<T>,
}

/// The cols for a CommitPVHash invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PublicValuesCols<T: Copy> {
    pub pv_element: T,
}

impl<F> BaseAir<F> for PublicValuesChip {
    fn width(&self) -> usize {
        NUM_PUBLIC_VALUES_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for PublicValuesChip {
    fn name(&self) -> String {
        "PublicValues".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PUBLIC_VALUES_PREPROCESSED_COLS
    }
}

//     fn num_rows(&self, _: &Self::Record) -> Option<usize> {
//         Some(1 << PUB_VALUES_LOG_HEIGHT)
//     }

//     fn preprocessed_num_rows(&self, _program: &Self::Program, _instrs_len: usize) -> Option<usize> {
//         Some(1 << PUB_VALUES_LOG_HEIGHT)
//     }

//     fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
//         assert_eq!(
//             std::any::TypeId::of::<F>(),
//             std::any::TypeId::of::<BabyBear>(),
//             "generate_preprocessed_trace only supports BabyBear field"
//         );

//         let mut rows: Vec<[BabyBear; NUM_PUBLIC_VALUES_PREPROCESSED_COLS]> = Vec::new();
//         let commit_pv_hash_instrs: Vec<&Box<CommitPublicValuesInstr<BabyBear>>> = program
//             .inner
//             .iter()
//             .filter_map(|instruction| {
//                 if let Instruction::CommitPublicValues(instr) = instruction.inner() {
//                     Some(unsafe {
//                         std::mem::transmute::<
//                             &Box<CommitPublicValuesInstr<F>>,
//                             &Box<CommitPublicValuesInstr<BabyBear>>,
//                         >(instr)
//                     })
//                 } else {
//                     None
//                 }
//             })
//             .collect::<Vec<_>>();

//         if commit_pv_hash_instrs.len() != 1 {
//             tracing::warn!("Expected exactly one CommitPVHash instruction.");
//         }

//         // We only take 1 commit pv hash instruction, since our air only checks for one public
//         // values hash.
//         for instr in commit_pv_hash_instrs.iter().take(1) {
//             for i in 0..DIGEST_SIZE {
//                 let mut row = [BabyBear::zero(); NUM_PUBLIC_VALUES_PREPROCESSED_COLS];
//                 let cols: &mut PublicValuesPreprocessedCols<BabyBear> =
//                     row.as_mut_slice().borrow_mut();
//                 unsafe {
//                     crate::sys::public_values_instr_to_row_babybear(instr, i, cols);
//                 }
//                 rows.push(row);
//             }
//         }

//         // Pad the preprocessed rows to 8 rows.
//         // gpu code breaks for small traces
//         pad_rows_fixed(
//             &mut rows,
//             || [BabyBear::zero(); NUM_PUBLIC_VALUES_PREPROCESSED_COLS],
//             self.preprocessed_num_rows(program, commit_pv_hash_instrs.len()),
//         );

//         let trace = RowMajorMatrix::new(
//             unsafe {
//                 std::mem::transmute::<Vec<BabyBear>, Vec<F>>(
//                     rows.into_iter().flatten().collect::<Vec<BabyBear>>(),
//                 )
//             },
//             NUM_PUBLIC_VALUES_PREPROCESSED_COLS,
//         );
//         Some(trace)
//     }

//     fn generate_trace(
//         &self,
//         input: &ExecutionRecord<F>,
//         _: &mut ExecutionRecord<F>,
//     ) -> RowMajorMatrix<F> {
//         assert_eq!(
//             std::any::TypeId::of::<F>(),
//             std::any::TypeId::of::<BabyBear>(),
//             "generate_trace only supports BabyBear field"
//         );

//         if input.commit_pv_hash_events.len() != 1 {
//             tracing::warn!("Expected exactly one CommitPVHash event.");
//         }

//         let mut rows: Vec<[BabyBear; NUM_PUBLIC_VALUES_COLS]> = Vec::new();

//         // We only take 1 commit pv hash instruction, since our air only checks for one public
//         // values hash.
//         for event in input.commit_pv_hash_events.iter().take(1) {
//             let bb_event = unsafe {
//                 std::mem::transmute::<&CommitPublicValuesEvent<F>, &CommitPublicValuesEvent<BabyBear>>(
//                     event,
//                 )
//             };
//             for i in 0..DIGEST_SIZE {
//                 let mut row = [BabyBear::zero(); NUM_PUBLIC_VALUES_COLS];
//                 let cols: &mut PublicValuesCols<BabyBear> = row.as_mut_slice().borrow_mut();
//                 unsafe {
//                     crate::sys::public_values_event_to_row_babybear(bb_event, i, cols);
//                 }
//                 rows.push(row);
//             }
//         }

//         // Pad the trace to 8 rows.
//         pad_rows_fixed(
//             &mut rows,
//             || [BabyBear::zero(); NUM_PUBLIC_VALUES_COLS],
//             self.num_rows(input),
//         );

//         // Convert the trace to a row major matrix.
//         RowMajorMatrix::new(
//             unsafe {
//                 std::mem::transmute::<Vec<BabyBear>, Vec<F>>(
//                     rows.into_iter().flatten().collect::<Vec<BabyBear>>(),
//                 )
//             },
//             NUM_PUBLIC_VALUES_COLS,
//         )
//     }

//     fn included(&self, _record: &Self::Record) -> bool {
//         true
//     }
// }

impl<AB> Air<AB> for PublicValuesChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &PublicValuesCols<AB::Var> = (*local).borrow();
        let prepr = builder.preprocessed();
        let local_prepr = prepr.row_slice(0);
        let local_prepr: &PublicValuesPreprocessedCols<AB::Var> = (*local_prepr).borrow();
        let pv = builder.public_values();
        let pv_elms: [AB::Expr; RECURSIVE_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| pv[i].into());
        let public_values: &RecursionPublicValues<AB::Expr> = pv_elms.as_slice().borrow();

        // Constrain mem read for the public value element.
        builder.send_single(local_prepr.pv_mem.addr, local.pv_element, local_prepr.pv_mem.mult);

        for (i, pv_elm) in public_values.digest.iter().enumerate() {
            // Ensure that the public value element is the same for all rows within a fri fold
            // invocation.
            builder.when(local_prepr.pv_idx[i]).assert_eq(pv_elm.clone(), local.pv_element);
        }
    }
}
