use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use slop_algebra::PrimeField32;
use slop_matrix::dense::RowMajorMatrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, JumpEvent},
    ExecutionRecord, Program,
};
use sp1_hypercube::air::MachineAir;

use crate::utils::{next_multiple_of_32, zeroed_f_vec};

use super::{JalrChip, JalrColumns, NUM_JALR_COLS};

impl<F: PrimeField32> MachineAir<F> for JalrChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Jalr".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows =
            next_multiple_of_32(input.jalr_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.jalr_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows = <JalrChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_JALR_COLS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_JALR_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_JALR_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut JalrColumns<F> = row.borrow_mut();

                    if idx < input.jalr_events.len() {
                        let event = &input.jalr_events[idx];
                        self.event_to_row(&event.0, event.1.op_c, cols, &mut blu);
                        cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut blu, event.1);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_JALR_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.jalr_events.is_empty()
        }
    }
}

impl JalrChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &JumpEvent,
        imm: u64,
        cols: &mut JalrColumns<F>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        // `event.c` is unused, since we ought to use a `JalrEvent` rather than a `JumpEvent`.
        cols.is_real = F::one();
        cols.op_a_value = event.a.into();
        let low_limb = (event.b.wrapping_add(imm) & 0xFFFF) as u16;
        blu.add_bit_range_check(low_limb / 4, 14);
        cols.add_operation.populate(blu, event.b, imm);
        if !event.op_a_0 {
            cols.op_a_operation.populate(blu, event.pc, 4);
        }
    }
}
