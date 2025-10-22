use std::borrow::BorrowMut;

use crate::utils::zeroed_f_vec;
use slop_algebra::PrimeField32;
use slop_matrix::dense::RowMajorMatrix;
use sp1_core_executor::{events::ByteRecord, ByteOpcode, ExecutionRecord, Program};
use sp1_hypercube::air::MachineAir;

use super::{
    columns::{RangeMultCols, NUM_RANGE_MULT_COLS, NUM_RANGE_PREPROCESSED_COLS},
    RangeChip,
};

pub const NUM_ROWS: usize = 1 << 17;

impl<F: PrimeField32> MachineAir<F> for RangeChip<F> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Range".to_string()
    }

    fn num_rows(&self, _: &Self::Record) -> Option<usize> {
        Some(NUM_ROWS)
    }

    fn preprocessed_width(&self) -> usize {
        NUM_RANGE_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let trace = Self::trace();
        Some(trace)
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let initial_timestamp_0 = ((input.public_values.initial_timestamp >> 32) & 0xFFFF) as u16;
        let initial_timestamp_3 = (input.public_values.initial_timestamp & 0xFFFF) as u16;
        let last_timestamp_0 = ((input.public_values.last_timestamp >> 32) & 0xFFFF) as u16;
        let last_timestamp_3 = (input.public_values.last_timestamp & 0xFFFF) as u16;

        output.add_bit_range_check(initial_timestamp_0, 16);
        output.add_bit_range_check((initial_timestamp_3 - 1) / 8, 13);
        output.add_bit_range_check(last_timestamp_0, 16);
        output.add_bit_range_check((last_timestamp_3 - 1) / 8, 13);

        for addr in [
            input.public_values.pc_start,
            input.public_values.next_pc,
            input.public_values.previous_init_addr,
            input.public_values.last_init_addr,
            input.public_values.previous_finalize_addr,
            input.public_values.last_finalize_addr,
        ] {
            let limb_0 = (addr & 0xFFFF) as u16;
            let limb_1 = ((addr >> 16) & 0xFFFF) as u16;
            let limb_2 = ((addr >> 32) & 0xFFFF) as u16;
            output.add_bit_range_check(limb_0, 16);
            output.add_bit_range_check(limb_1, 16);
            output.add_bit_range_check(limb_2, 16);
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut trace =
            RowMajorMatrix::new(zeroed_f_vec(NUM_RANGE_MULT_COLS * NUM_ROWS), NUM_RANGE_MULT_COLS);

        for (lookup, mult) in input.byte_lookups.iter() {
            if lookup.opcode != ByteOpcode::Range {
                continue;
            }
            let row = (lookup.a as usize) + (1 << lookup.b);
            let cols: &mut RangeMultCols<F> = trace.row_mut(row).borrow_mut();
            cols.multiplicity += F::from_canonical_usize(*mult);
        }

        trace
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        true
    }
}
