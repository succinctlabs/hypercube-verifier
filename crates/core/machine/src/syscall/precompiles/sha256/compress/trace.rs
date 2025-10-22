use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use slop_algebra::PrimeField32;
use slop_matrix::dense::RowMajorMatrix;
use slop_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemoryRecordEnum, PrecompileEvent, ShaCompressEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_hypercube::air::MachineAir;

use super::{
    columns::{ShaCompressCols, NUM_SHA_COMPRESS_COLS},
    ShaCompressChip, SHA_COMPRESS_K,
};
use crate::utils::{next_multiple_of_32, pad_rows_fixed, u32_to_half_word};

impl<F: PrimeField32> MachineAir<F> for ShaCompressChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "ShaCompress".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        // Each compress syscall takes 80 rows.
        let nb_rows = input.get_precompile_events(SyscallCode::SHA_COMPRESS).len() * 80;
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let rows = Vec::new();

        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::SHA_COMPRESS) {
            let event = if let PrecompileEvent::ShaCompress(event) = event {
                event
            } else {
                unreachable!()
            };
            self.event_to_rows(event, &mut wrapped_rows, &mut Vec::new());
        }
        let mut rows = wrapped_rows.unwrap();

        let num_real_rows = rows.len();

        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_SHA_COMPRESS_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Set the octet_num and octet columns for the padded rows.
        let mut octet_num = 0;
        let mut octet = 0;
        for row in rows[num_real_rows..].iter_mut() {
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();
            cols.octet_num[octet_num] = F::one();
            cols.octet[octet] = F::one();
            cols.index = F::from_canonical_u32((8 * octet_num + octet) as u32);

            // If in the compression phase, set the k value.
            if octet_num != 0 && octet_num != 9 {
                let compression_idx = octet_num - 1;
                let k_idx = compression_idx * 8 + octet;
                cols.k = u32_to_half_word(SHA_COMPRESS_K[k_idx]);
            }

            octet = (octet + 1) % 8;
            if octet == 0 {
                octet_num = (octet_num + 1) % 10;
            }
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_SHA_COMPRESS_COLS)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::SHA_COMPRESS);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::ShaCompress(event) = event {
                        event
                    } else {
                        unreachable!()
                    };
                    self.event_to_rows::<F>(event, &mut None, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::SHA_COMPRESS).is_empty()
        }
    }
}

impl ShaCompressChip {
    fn event_to_rows<F: PrimeField32>(
        &self,
        event: &ShaCompressEvent,
        rows: &mut Option<Vec<[F; NUM_SHA_COMPRESS_COLS]>>,
        blu: &mut impl ByteRecord,
    ) {
        let og_h = event.h;

        let mut octet_num_idx = 0;

        // Load a, b, c, d, e, f, g, h.
        for j in 0..8usize {
            let mut row = [F::zero(); NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

            cols.w_ptr = [
                F::from_canonical_u16((event.w_ptr & 0xFFFF) as u16),
                F::from_canonical_u16((event.w_ptr >> 16) as u16),
                F::from_canonical_u16((event.w_ptr >> 32) as u16),
            ];
            cols.h_ptr = [
                F::from_canonical_u16((event.h_ptr & 0xFFFF) as u16),
                F::from_canonical_u16((event.h_ptr >> 16) as u16),
                F::from_canonical_u16((event.h_ptr >> 32) as u16),
            ];

            cols.octet[j] = F::one();
            cols.octet_num[octet_num_idx] = F::one();
            cols.is_initialize = F::one();

            cols.mem_addr_init.populate(blu, event.h_ptr, j as u64 * 8);
            cols.mem.populate(MemoryRecordEnum::Read(event.h_read_records[j]), blu);
            cols.mem_value = u32_to_half_word(event.h_read_records[j].value as u32);
            cols.mem_addr = cols.mem_addr_init.value;

            cols.a = u32_to_half_word(event.h_read_records[0].value as u32);
            cols.b = u32_to_half_word(event.h_read_records[1].value as u32);
            cols.c = u32_to_half_word(event.h_read_records[2].value as u32);
            cols.d = u32_to_half_word(event.h_read_records[3].value as u32);
            cols.e = u32_to_half_word(event.h_read_records[4].value as u32);
            cols.f = u32_to_half_word(event.h_read_records[5].value as u32);
            cols.g = u32_to_half_word(event.h_read_records[6].value as u32);
            cols.h = u32_to_half_word(event.h_read_records[7].value as u32);

            cols.index = F::from_canonical_u32(j as u32);

            cols.is_real = F::one();
            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }

        // Performs the compress operation.
        let mut h_array = event.h;
        for j in 0..64usize {
            if j.is_multiple_of(8) {
                octet_num_idx += 1;
            }
            let mut row = [F::zero(); NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

            cols.w_ptr = [
                F::from_canonical_u16((event.w_ptr & 0xFFFF) as u16),
                F::from_canonical_u16((event.w_ptr >> 16) as u16),
                F::from_canonical_u16((event.w_ptr >> 32) as u16),
            ];
            cols.h_ptr = [
                F::from_canonical_u16((event.h_ptr & 0xFFFF) as u16),
                F::from_canonical_u16((event.h_ptr >> 16) as u16),
                F::from_canonical_u16((event.h_ptr >> 32) as u16),
            ];

            cols.k = u32_to_half_word(SHA_COMPRESS_K[j]);
            cols.octet[j % 8] = F::one();
            cols.octet_num[octet_num_idx] = F::one();
            cols.is_compression = F::one();

            cols.mem_addr_compress.populate(blu, event.w_ptr, j as u64 * 8);
            cols.mem.populate(MemoryRecordEnum::Read(event.w_i_read_records[j]), blu);
            cols.mem_value = u32_to_half_word(event.w_i_read_records[j].value as u32);
            cols.mem_addr = cols.mem_addr_compress.value;
            cols.index = F::from_canonical_u32(j as u32 + 8);

            let a = h_array[0];
            let b = h_array[1];
            let c = h_array[2];
            let d = h_array[3];
            let e = h_array[4];
            let f = h_array[5];
            let g = h_array[6];
            let h = h_array[7];
            cols.a = u32_to_half_word(a);
            cols.b = u32_to_half_word(b);
            cols.c = u32_to_half_word(c);
            cols.d = u32_to_half_word(d);
            cols.e = u32_to_half_word(e);
            cols.f = u32_to_half_word(f);
            cols.g = u32_to_half_word(g);
            cols.h = u32_to_half_word(h);

            let e_rr_6 = cols.e_rr_6.populate(blu, e, 6);
            let e_rr_11 = cols.e_rr_11.populate(blu, e, 11);
            let e_rr_25 = cols.e_rr_25.populate(blu, e, 25);
            let s1_intermediate = cols.s1_intermediate.populate_xor_u32(blu, e_rr_6, e_rr_11);
            let s1 = cols.s1.populate_xor_u32(blu, s1_intermediate, e_rr_25);

            let e_and_f = cols.e_and_f.populate_and_u32(blu, e, f);
            let e_not = cols.e_not.populate(e);
            let e_not_and_g = cols.e_not_and_g.populate_and_u32(blu, e_not as u32, g as u32);
            let ch = cols.ch.populate_xor_u32(blu, e_and_f, e_not_and_g);

            let temp1 = cols.temp1.populate(blu, h, s1, ch, event.w[j], SHA_COMPRESS_K[j]);

            let a_rr_2 = cols.a_rr_2.populate(blu, a, 2);
            let a_rr_13 = cols.a_rr_13.populate(blu, a, 13);
            let a_rr_22 = cols.a_rr_22.populate(blu, a, 22);
            let s0_intermediate = cols.s0_intermediate.populate_xor_u32(blu, a_rr_2, a_rr_13);
            let s0 = cols.s0.populate_xor_u32(blu, s0_intermediate, a_rr_22);

            let a_and_b = cols.a_and_b.populate_and_u32(blu, a, b);
            let a_and_c = cols.a_and_c.populate_and_u32(blu, a, c);
            let b_and_c = cols.b_and_c.populate_and_u32(blu, b, c);
            let maj_intermediate = cols.maj_intermediate.populate_xor_u32(blu, a_and_b, a_and_c);
            let maj = cols.maj.populate_xor_u32(blu, maj_intermediate, b_and_c);

            let temp2 = cols.temp2.populate(blu, s0, maj);

            let d_add_temp1 = cols.d_add_temp1.populate(blu, d, temp1);
            let temp1_add_temp2 = cols.temp1_add_temp2.populate(blu, temp1, temp2);

            h_array[7] = g;
            h_array[6] = f;
            h_array[5] = e;
            h_array[4] = d_add_temp1;
            h_array[3] = c;
            h_array[2] = b;
            h_array[1] = a;
            h_array[0] = temp1_add_temp2;

            cols.is_real = F::one();

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }

        let mut v: [u32; 8] = (0..8).map(|i| h_array[i]).collect::<Vec<_>>().try_into().unwrap();

        octet_num_idx += 1;
        // Store a, b, c, d, e, f, g, h.
        for j in 0..8usize {
            let mut row = [F::zero(); NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

            cols.w_ptr = [
                F::from_canonical_u16((event.w_ptr & 0xFFFF) as u16),
                F::from_canonical_u16((event.w_ptr >> 16) as u16),
                F::from_canonical_u16((event.w_ptr >> 32) as u16),
            ];
            cols.h_ptr = [
                F::from_canonical_u16((event.h_ptr & 0xFFFF) as u16),
                F::from_canonical_u16((event.h_ptr >> 16) as u16),
                F::from_canonical_u16((event.h_ptr >> 32) as u16),
            ];

            cols.octet[j] = F::one();
            cols.octet_num[octet_num_idx] = F::one();
            cols.is_finalize = F::one();

            cols.mem_addr_finalize.populate(blu, event.h_ptr, j as u64 * 8);
            cols.mem.populate(MemoryRecordEnum::Write(event.h_write_records[j]), blu);
            cols.mem_value = u32_to_half_word(event.h_write_records[j].value as u32);
            cols.mem_addr = cols.mem_addr_finalize.value;
            cols.index = F::from_canonical_u32(j as u32 + 72);
            cols.finalize_add.populate(blu, og_h[j], h_array[j]);

            v[j] = h_array[j];
            cols.a = u32_to_half_word(v[0]);
            cols.b = u32_to_half_word(v[1]);
            cols.c = u32_to_half_word(v[2]);
            cols.d = u32_to_half_word(v[3]);
            cols.e = u32_to_half_word(v[4]);
            cols.f = u32_to_half_word(v[5]);
            cols.g = u32_to_half_word(v[6]);
            cols.h = u32_to_half_word(v[7]);

            match j {
                0 => cols.finalized_operand = cols.a,
                1 => cols.finalized_operand = cols.b,
                2 => cols.finalized_operand = cols.c,
                3 => cols.finalized_operand = cols.d,
                4 => cols.finalized_operand = cols.e,
                5 => cols.finalized_operand = cols.f,
                6 => cols.finalized_operand = cols.g,
                7 => cols.finalized_operand = cols.h,
                _ => panic!("unsupported j"),
            };

            cols.is_real = F::one();

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }
    }
}
