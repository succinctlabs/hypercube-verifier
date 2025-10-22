mod air;

use num::{BigUint, One, Zero};
use slop_algebra::PrimeField32;
use slop_matrix::dense::RowMajorMatrix;
use sp1_core_executor::{
    events::{ByteRecord, MemoryRecordEnum, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_curves::{params::NumWords, uint256::U256Field};
use sp1_hypercube::air::MachineAir;
use sp1_primitives::consts::{PROT_READ, PROT_WRITE};
use std::borrow::BorrowMut;

pub use air::{Uint256OpsChip, Uint256OpsCols, NUM_UINT256_OPS_COLS};
use typenum::Unsigned;
type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

use crate::utils::{next_multiple_of_32, pad_rows_fixed};

pub const U256_NUM_WORDS: usize = 4;

impl<F: PrimeField32> MachineAir<F> for Uint256OpsChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Uint256Ops".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.get_precompile_events(SyscallCode::UINT256_ADD_CARRY).len()
            + input.get_precompile_events(SyscallCode::UINT256_MUL_CARRY).len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let mut all_events = Vec::new();
        all_events.extend(input.get_precompile_events(SyscallCode::UINT256_ADD_CARRY).iter());
        all_events.extend(input.get_precompile_events(SyscallCode::UINT256_MUL_CARRY).iter());

        let event_rows = all_events
            .chunks(1)
            .map(|events| {
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|(_, event)| {
                        let event = if let PrecompileEvent::Uint256Ops(event) = event {
                            event
                        } else {
                            unreachable!()
                        };
                        let mut row: [F; NUM_UINT256_OPS_COLS] = [F::zero(); NUM_UINT256_OPS_COLS];
                        let cols: &mut Uint256OpsCols<F> = row.as_mut_slice().borrow_mut();

                        // Set is_real flag
                        cols.is_real = F::one();

                        // Populate clk fields
                        cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
                        cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

                        // Populate address operations
                        cols.a_ptr.populate(&mut new_byte_lookup_events, event.a_ptr, 32);
                        cols.b_ptr.populate(&mut new_byte_lookup_events, event.b_ptr, 32);
                        cols.c_ptr.populate(&mut new_byte_lookup_events, event.c_ptr, 32);
                        cols.d_ptr.populate(&mut new_byte_lookup_events, event.d_ptr, 32);
                        cols.e_ptr.populate(&mut new_byte_lookup_events, event.e_ptr, 32);

                        // Populate memory accesses for pointer reads
                        let c_ptr_memory_record = MemoryRecordEnum::Read(event.c_ptr_memory);
                        let d_ptr_memory_record = MemoryRecordEnum::Read(event.d_ptr_memory);
                        let e_ptr_memory_record = MemoryRecordEnum::Read(event.e_ptr_memory);

                        cols.c_ptr_memory
                            .populate(c_ptr_memory_record, &mut new_byte_lookup_events);
                        cols.d_ptr_memory
                            .populate(d_ptr_memory_record, &mut new_byte_lookup_events);
                        cols.e_ptr_memory
                            .populate(e_ptr_memory_record, &mut new_byte_lookup_events);

                        // Populate memory accesses for value reads/writes
                        for i in 0..WORDS_FIELD_ELEMENT {
                            let a_record = MemoryRecordEnum::Read(event.a_memory_records[i]);
                            let b_record = MemoryRecordEnum::Read(event.b_memory_records[i]);
                            let c_record = MemoryRecordEnum::Read(event.c_memory_records[i]);
                            let d_record = MemoryRecordEnum::Write(event.d_memory_records[i]);
                            let e_record = MemoryRecordEnum::Write(event.e_memory_records[i]);

                            cols.a_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.a_ptr,
                                8 * i as u64,
                            );
                            cols.b_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.b_ptr,
                                8 * i as u64,
                            );
                            cols.c_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.c_ptr,
                                8 * i as u64,
                            );
                            cols.d_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.d_ptr,
                                8 * i as u64,
                            );
                            cols.e_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.e_ptr,
                                8 * i as u64,
                            );
                            cols.a_memory[i].populate(a_record, &mut new_byte_lookup_events);
                            cols.b_memory[i].populate(b_record, &mut new_byte_lookup_events);
                            cols.c_memory[i].populate(c_record, &mut new_byte_lookup_events);
                            cols.d_memory[i].populate(d_record, &mut new_byte_lookup_events);
                            cols.e_memory[i].populate(e_record, &mut new_byte_lookup_events);
                        }

                        // Set operation flags
                        match event.op {
                            sp1_core_executor::events::Uint256Operation::Add => {
                                cols.is_add = F::one();
                                cols.is_mul = F::zero();
                            }
                            sp1_core_executor::events::Uint256Operation::Mul => {
                                cols.is_add = F::zero();
                                cols.is_mul = F::one();
                            }
                        }

                        // Convert values to BigUint for field operations
                        let a = BigUint::from_slice(
                            &event
                                .a
                                .iter()
                                .flat_map(|&x| [x as u32, (x >> 32) as u32])
                                .collect::<Vec<_>>(),
                        );
                        let b = BigUint::from_slice(
                            &event
                                .b
                                .iter()
                                .flat_map(|&x| [x as u32, (x >> 32) as u32])
                                .collect::<Vec<_>>(),
                        );
                        let c = BigUint::from_slice(
                            &event
                                .c
                                .iter()
                                .flat_map(|&x| [x as u32, (x >> 32) as u32])
                                .collect::<Vec<_>>(),
                        );

                        // Populate field operation based on operation type
                        let is_add =
                            matches!(event.op, sp1_core_executor::events::Uint256Operation::Add);
                        let is_mul =
                            matches!(event.op, sp1_core_executor::events::Uint256Operation::Mul);
                        let modulus = BigUint::one() << 256;

                        cols.field_op.populate_conditional_op_and_carry(
                            &mut new_byte_lookup_events,
                            &a,
                            &b,
                            &c,
                            &modulus,
                            is_add,
                            is_mul,
                        );
                        if input.public_values.is_untrusted_programs_enabled == 1 {
                            // Populate page protection operations (once per event, not per word)
                            cols.address_slice_page_prot_access_a.populate(
                                &mut new_byte_lookup_events,
                                event.a_ptr,
                                event.a_ptr + ((WORDS_FIELD_ELEMENT - 1) * 8) as u64,
                                event.clk,
                                PROT_READ,
                                &event.page_prot_records.read_a_page_prot_records[0],
                                &event.page_prot_records.read_a_page_prot_records.get(1).copied(),
                                input.public_values.is_untrusted_programs_enabled,
                            );

                            // Populate page protection operations (once per event, not per word)
                            cols.address_slice_page_prot_access_b.populate(
                                &mut new_byte_lookup_events,
                                event.b_ptr,
                                event.b_ptr + ((WORDS_FIELD_ELEMENT - 1) * 8) as u64,
                                event.clk + 1,
                                PROT_READ,
                                &event.page_prot_records.read_b_page_prot_records[0],
                                &event.page_prot_records.read_b_page_prot_records.get(1).copied(),
                                input.public_values.is_untrusted_programs_enabled,
                            );

                            // Populate page protection operations (once per event, not per word)
                            cols.address_slice_page_prot_access_c.populate(
                                &mut new_byte_lookup_events,
                                event.c_ptr,
                                event.c_ptr + ((WORDS_FIELD_ELEMENT - 1) * 8) as u64,
                                event.clk + 2,
                                PROT_READ,
                                &event.page_prot_records.read_c_page_prot_records[0],
                                &event.page_prot_records.read_c_page_prot_records.get(1).copied(),
                                input.public_values.is_untrusted_programs_enabled,
                            );

                            // Populate page protection operations (once per event, not per word)
                            cols.address_slice_page_prot_access_d.populate(
                                &mut new_byte_lookup_events,
                                event.d_ptr,
                                event.d_ptr + ((WORDS_FIELD_ELEMENT - 1) * 8) as u64,
                                event.clk + 3,
                                PROT_WRITE,
                                &event.page_prot_records.write_d_page_prot_records[0],
                                &event.page_prot_records.write_d_page_prot_records.get(1).copied(),
                                input.public_values.is_untrusted_programs_enabled,
                            );

                            // Populate page protection operations (once per event, not per word)
                            cols.address_slice_page_prot_access_e.populate(
                                &mut new_byte_lookup_events,
                                event.e_ptr,
                                event.e_ptr + ((WORDS_FIELD_ELEMENT - 1) * 8) as u64,
                                event.clk + 4,
                                PROT_WRITE,
                                &event.page_prot_records.write_e_page_prot_records[0],
                                &event.page_prot_records.write_e_page_prot_records.get(1).copied(),
                                input.public_values.is_untrusted_programs_enabled,
                            );
                        }

                        row
                    })
                    .collect::<Vec<_>>();

                // records.add_byte_lookup_events(new_byte_lookup_events);
                output.add_byte_lookup_events(new_byte_lookup_events);
                rows
            })
            .collect::<Vec<_>>();

        // Generate the trace rows for each event.
        let mut rows = Vec::new();
        for row in event_rows {
            rows.extend(row);
        }

        // Pad rows to the required size
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row: [F; NUM_UINT256_OPS_COLS] = [F::zero(); NUM_UINT256_OPS_COLS];
                let cols: &mut Uint256OpsCols<F> = row.as_mut_slice().borrow_mut();

                // Initialize with zero values for padding rows
                let zero = BigUint::zero();
                cols.field_op.populate_conditional_op_and_carry(
                    &mut vec![],
                    &zero,
                    &zero,
                    &zero,
                    &(BigUint::one() << 256),
                    true,
                    false,
                );

                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_UINT256_OPS_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.get_precompile_events(SyscallCode::UINT256_ADD_CARRY).is_empty()
            || !shard.get_precompile_events(SyscallCode::UINT256_MUL_CARRY).is_empty()
    }
}
