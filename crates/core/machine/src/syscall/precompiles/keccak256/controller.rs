use crate::{
    air::SP1CoreAirBuilder,
    memory::MemoryAccessCols,
    operations::{AddrAddOperation, AddressSlicePageProtOperation, SyscallAddrOperation},
    utils::next_multiple_of_32,
};

use super::{KeccakPermuteControlChip, STATE_NUM_WORDS};
use core::borrow::Borrow;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{ByteRecord, MemoryRecordEnum, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir},
    InteractionKind, Word,
};
use sp1_primitives::consts::{PROT_READ, PROT_WRITE};
use std::{borrow::BorrowMut, iter::once};

impl KeccakPermuteControlChip {
    pub const fn new() -> Self {
        Self {}
    }
}

pub const NUM_KECCAK_PERMUTE_CONTROL_COLS: usize = size_of::<KeccakPermuteControlCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct KeccakPermuteControlCols<T> {
    pub clk_high: T,
    pub clk_low: T,
    pub state_addr: SyscallAddrOperation<T>,
    pub addrs: [AddrAddOperation<T>; 25],
    pub is_real: T,
    pub initial_memory_access: [MemoryAccessCols<T>; 25],
    pub final_memory_access: [MemoryAccessCols<T>; 25],
    pub final_value: [Word<T>; 25],

    /// Array Slice Page Prot Access.
    pub read_state_slice_page_prot_access: AddressSlicePageProtOperation<T>,
    pub write_state_slice_page_prot_access: AddressSlicePageProtOperation<T>,
}

impl<F> BaseAir<F> for KeccakPermuteControlChip {
    fn width(&self) -> usize {
        NUM_KECCAK_PERMUTE_CONTROL_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for KeccakPermuteControlChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "KeccakPermuteControl".to_string()
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let mut blu_events = vec![];
        for (_, event) in input.get_precompile_events(SyscallCode::KECCAK_PERMUTE).iter() {
            let event = if let PrecompileEvent::KeccakPermute(event) = event {
                event
            } else {
                unreachable!()
            };
            let mut row = [F::zero(); NUM_KECCAK_PERMUTE_CONTROL_COLS];
            let cols: &mut KeccakPermuteControlCols<F> = row.as_mut_slice().borrow_mut();
            cols.state_addr.populate(&mut blu_events, event.state_addr, 200);
            for (j, read_record) in event.state_read_records.iter().enumerate() {
                cols.initial_memory_access[j]
                    .populate(MemoryRecordEnum::Read(*read_record), &mut blu_events);
                cols.addrs[j].populate(&mut blu_events, event.state_addr, 8 * j as u64);
            }
            for (j, write_record) in event.state_write_records.iter().enumerate() {
                cols.final_memory_access[j]
                    .populate(MemoryRecordEnum::Write(*write_record), &mut blu_events);
                cols.final_value[j] = Word::from(write_record.value);
            }
            if input.public_values.is_untrusted_programs_enabled == 1 {
                cols.read_state_slice_page_prot_access.populate(
                    &mut blu_events,
                    event.state_addr,
                    event.state_addr + 8 * (STATE_NUM_WORDS - 1) as u64,
                    event.clk,
                    PROT_READ,
                    &event.page_prot_records.read_pre_state_page_prot_records[0],
                    &event.page_prot_records.read_pre_state_page_prot_records.get(1).copied(),
                    input.public_values.is_untrusted_programs_enabled,
                );
                cols.write_state_slice_page_prot_access.populate(
                    &mut blu_events,
                    event.state_addr,
                    event.state_addr + 8 * (STATE_NUM_WORDS - 1) as u64,
                    event.clk + 1,
                    PROT_WRITE,
                    &event.page_prot_records.write_post_state_page_prot_records[0],
                    &event.page_prot_records.write_post_state_page_prot_records.get(1).copied(),
                    input.public_values.is_untrusted_programs_enabled,
                );
            }
        }
        output.add_byte_lookup_events(blu_events);
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.get_precompile_events(SyscallCode::KECCAK_PERMUTE).len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();
        let mut blu_events = vec![];
        for (_, event) in input.get_precompile_events(SyscallCode::KECCAK_PERMUTE).iter() {
            let event = if let PrecompileEvent::KeccakPermute(event) = event {
                event
            } else {
                unreachable!()
            };
            let mut row = [F::zero(); NUM_KECCAK_PERMUTE_CONTROL_COLS];
            let cols: &mut KeccakPermuteControlCols<F> = row.as_mut_slice().borrow_mut();
            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
            cols.state_addr.populate(&mut blu_events, event.state_addr, 200);
            cols.is_real = F::one();
            for (j, read_record) in event.state_read_records.iter().enumerate() {
                cols.initial_memory_access[j]
                    .populate(MemoryRecordEnum::Read(*read_record), &mut blu_events);
                cols.addrs[j].populate(&mut blu_events, event.state_addr, 8 * j as u64);
            }
            for (j, write_record) in event.state_write_records.iter().enumerate() {
                cols.final_memory_access[j]
                    .populate(MemoryRecordEnum::Write(*write_record), &mut blu_events);
                cols.final_value[j] = Word::from(write_record.value);
            }
            if input.public_values.is_untrusted_programs_enabled == 1 {
                cols.read_state_slice_page_prot_access.populate(
                    &mut blu_events,
                    event.state_addr,
                    event.state_addr + 8 * (STATE_NUM_WORDS - 1) as u64,
                    event.clk,
                    PROT_READ,
                    &event.page_prot_records.read_pre_state_page_prot_records[0],
                    &event.page_prot_records.read_pre_state_page_prot_records.get(1).copied(),
                    input.public_values.is_untrusted_programs_enabled,
                );
                cols.write_state_slice_page_prot_access.populate(
                    &mut blu_events,
                    event.state_addr,
                    event.state_addr + 8 * (STATE_NUM_WORDS - 1) as u64,
                    event.clk + 1,
                    PROT_WRITE,
                    &event.page_prot_records.write_post_state_page_prot_records[0],
                    &event.page_prot_records.write_post_state_page_prot_records.get(1).copied(),
                    input.public_values.is_untrusted_programs_enabled,
                );
            }
            rows.push(row);
        }

        let nb_rows = rows.len();
        let mut padded_nb_rows = nb_rows.next_multiple_of(32);
        if padded_nb_rows == 2 || padded_nb_rows == 1 {
            padded_nb_rows = 4;
        }
        for _ in nb_rows..padded_nb_rows {
            let row = [F::zero(); NUM_KECCAK_PERMUTE_CONTROL_COLS];
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_KECCAK_PERMUTE_CONTROL_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::KECCAK_PERMUTE).is_empty()
        }
    }
}

impl<AB> Air<AB> for KeccakPermuteControlChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Initialize columns.
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &KeccakPermuteControlCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        let state_addr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            200,
            local.state_addr,
            local.is_real.into(),
        );

        // Receive the syscall.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::KECCAK_PERMUTE.syscall_id()),
            state_addr.map(Into::into),
            [AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()],
            local.is_real,
            InteractionScope::Local,
        );

        let send_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(state_addr.map(Into::into))
            .chain(once(AB::Expr::zero()))
            .chain(
                local
                    .initial_memory_access
                    .into_iter()
                    .flat_map(|access| access.prev_value.into_iter())
                    .map(Into::into),
            )
            .collect::<Vec<_>>();

        // Send the initial state.
        builder.send(
            AirInteraction::new(send_values, local.is_real.into(), InteractionKind::Keccak),
            InteractionScope::Local,
        );

        let receive_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(state_addr.map(Into::into))
            .chain(once(AB::Expr::from_canonical_u32(24)))
            .chain(local.final_value.into_iter().flat_map(|word| word.into_iter()).map(Into::into))
            .collect::<Vec<_>>();

        // Receive the final state.
        builder.receive(
            AirInteraction::new(receive_values, local.is_real.into(), InteractionKind::Keccak),
            InteractionScope::Local,
        );

        // addrs[i] = state_addr + 8 * i
        for i in 0..local.addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([
                    state_addr[0].into(),
                    state_addr[1].into(),
                    state_addr[2].into(),
                    AB::Expr::zero(),
                ]),
                Word::from(8 * i as u64),
                local.addrs[i],
                local.is_real.into(),
            );
        }

        // Evaluate the memory accesses.
        for i in 0..STATE_NUM_WORDS {
            builder.eval_memory_access_read(
                local.clk_high,
                local.clk_low,
                &local.addrs[i].value.map(Into::into),
                local.initial_memory_access[i],
                local.is_real,
            );
            builder.eval_memory_access_write(
                local.clk_high,
                local.clk_low + AB::Expr::one(),
                &local.addrs[i].value.map(Into::into),
                local.final_memory_access[i],
                local.final_value[i],
                local.is_real,
            );
        }

        // Evaluate the page prot accesses.
        AddressSlicePageProtOperation::<AB::F>::eval(
            builder,
            local.clk_high.into(),
            local.clk_low.into(),
            &local.state_addr.addr.map(Into::into),
            &local.addrs[STATE_NUM_WORDS - 1].value.map(Into::into),
            AB::Expr::from_canonical_u8(PROT_READ),
            &local.read_state_slice_page_prot_access,
            local.is_real.into(),
        );

        AddressSlicePageProtOperation::<AB::F>::eval(
            builder,
            local.clk_high.into(),
            local.clk_low.into() + AB::Expr::one(),
            &local.state_addr.addr.map(Into::into),
            &local.addrs[STATE_NUM_WORDS - 1].value.map(Into::into),
            AB::Expr::from_canonical_u8(PROT_WRITE),
            &local.write_state_slice_page_prot_access,
            local.is_real.into(),
        );
    }
}
