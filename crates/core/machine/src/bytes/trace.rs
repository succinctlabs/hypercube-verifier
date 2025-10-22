use std::borrow::BorrowMut;

use slop_algebra::PrimeField32;
use slop_matrix::dense::RowMajorMatrix;
use sp1_core_executor::{events::ByteRecord, ByteOpcode, ExecutionRecord, Program};
use sp1_hypercube::air::{MachineAir, PV_DIGEST_NUM_WORDS};

use crate::utils::zeroed_f_vec;

use super::{
    columns::{ByteMultCols, NUM_BYTE_MULT_COLS, NUM_BYTE_PREPROCESSED_COLS},
    ByteChip,
};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: PrimeField32> MachineAir<F> for ByteChip<F> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Byte".to_string()
    }

    fn num_rows(&self, _: &Self::Record) -> Option<usize> {
        Some(1 << 16)
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BYTE_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let trace = Self::trace();
        Some(trace)
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let initial_timestamp_1 = ((input.public_values.initial_timestamp >> 24) & 0xFF) as u8;
        let initial_timestamp_2 = ((input.public_values.initial_timestamp >> 16) & 0xFF) as u8;
        let last_timestamp_1 = ((input.public_values.last_timestamp >> 24) & 0xFF) as u8;
        let last_timestamp_2 = ((input.public_values.last_timestamp >> 16) & 0xFF) as u8;

        output.add_u8_range_check(initial_timestamp_1, initial_timestamp_2);
        output.add_u8_range_check(last_timestamp_1, last_timestamp_2);
        for i in 0..PV_DIGEST_NUM_WORDS {
            output.add_u8_range_checks(&u32::to_le_bytes(
                input.public_values.prev_committed_value_digest[i],
            ));
            output.add_u8_range_checks(&u32::to_le_bytes(
                input.public_values.committed_value_digest[i],
            ));
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut trace =
            RowMajorMatrix::new(zeroed_f_vec(NUM_BYTE_MULT_COLS * NUM_ROWS), NUM_BYTE_MULT_COLS);

        for (lookup, mult) in input.byte_lookups.iter() {
            if lookup.opcode == ByteOpcode::Range {
                continue;
            }
            let row = (((lookup.b as u16) << 8) + lookup.c as u16) as usize;
            let index = lookup.opcode as usize;

            let cols: &mut ByteMultCols<F> = trace.row_mut(row).borrow_mut();
            cols.multiplicities[index] += F::from_canonical_usize(*mult);
        }

        trace
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        true
    }
}
