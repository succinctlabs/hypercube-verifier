use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use slop_algebra::PrimeField32;
use slop_matrix::dense::RowMajorMatrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ExecutionRecord, Program,
};
use sp1_hypercube::air::MachineAir;

use crate::utils::{next_multiple_of_32, zeroed_f_vec};

use super::{JalChip, JalColumns, NUM_JAL_COLS};

impl<F: PrimeField32> MachineAir<F> for JalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Jal".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows =
            next_multiple_of_32(input.jal_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.jal_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows = <JalChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_JAL_COLS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_JAL_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_JAL_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut JalColumns<F> = row.borrow_mut();

                    if idx < input.jal_events.len() {
                        let event = &input.jal_events[idx];
                        cols.is_real = F::one();
                        let low_limb = (event.0.pc.wrapping_add(event.0.b) & 0xFFFF) as u16;
                        blu.add_bit_range_check(low_limb / 4, 14);
                        cols.add_operation.populate(&mut blu, event.0.pc, event.0.b);
                        if !event.0.op_a_0 {
                            cols.op_a_operation.populate(&mut blu, event.0.pc, 4);
                        }
                        cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut blu, event.1);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_JAL_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.jal_events.is_empty()
        }
    }
}
