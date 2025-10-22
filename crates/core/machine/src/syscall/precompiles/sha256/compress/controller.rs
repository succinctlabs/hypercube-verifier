use crate::{
    air::SP1CoreAirBuilder,
    operations::{AddrAddOperation, AddressSlicePageProtOperation, SyscallAddrOperation},
    utils::next_multiple_of_32,
};

use super::ShaCompressControlChip;
use crate::utils::u32_to_half_word;
use core::borrow::Borrow;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{ByteRecord, PrecompileEvent},
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

impl ShaCompressControlChip {
    pub const fn new() -> Self {
        Self {}
    }
}

pub const NUM_SHA_COMPRESS_CONTROL_COLS: usize = size_of::<ShaCompressControlCols<u8>>();

// W has 64 elements of 4 byte. w_ptr + 63 * 8 gives the last address of W
const OFFSET_LAST_ELEM_W: u64 = 63;
// H has 8 elements of 4 bytes. h_ptr + 7 * 8 gives the last address of H
const OFFSET_LAST_ELEM_H: u64 = 7;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaCompressControlCols<T> {
    pub clk_high: T,
    pub clk_low: T,
    pub w_ptr: SyscallAddrOperation<T>,
    pub h_ptr: SyscallAddrOperation<T>,
    pub w_slice_end: AddrAddOperation<T>,
    pub h_slice_end: AddrAddOperation<T>,
    pub is_real: T,
    pub initial_state: [[T; 2]; 8],
    pub final_state: [[T; 2]; 8],
    pub h_read_page_prot_access: AddressSlicePageProtOperation<T>,
    pub w_read_page_prot_access: AddressSlicePageProtOperation<T>,
    pub h_write_page_prot_access: AddressSlicePageProtOperation<T>,
}

impl<F> BaseAir<F> for ShaCompressControlChip {
    fn width(&self) -> usize {
        NUM_SHA_COMPRESS_CONTROL_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for ShaCompressControlChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "ShaCompressControl".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.get_precompile_events(SyscallCode::SHA_COMPRESS).len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();
        let mut blu_events = vec![];
        for (_, event) in input.get_precompile_events(SyscallCode::SHA_COMPRESS).iter() {
            let event = if let PrecompileEvent::ShaCompress(event) = event {
                event
            } else {
                unreachable!()
            };
            let mut row = [F::zero(); NUM_SHA_COMPRESS_CONTROL_COLS];
            let cols: &mut ShaCompressControlCols<F> = row.as_mut_slice().borrow_mut();
            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
            // `w_ptr` has 64 words, so 512 bytes - but only 256 bytes are actually used.
            cols.w_ptr.populate(&mut blu_events, event.w_ptr, 512);
            // `h_ptr` has 8 words, so 64 bytes - but only 32 bytes are actually used.
            cols.h_ptr.populate(&mut blu_events, event.h_ptr, 64);
            cols.w_slice_end.populate(&mut blu_events, event.w_ptr, OFFSET_LAST_ELEM_W * 8);
            cols.h_slice_end.populate(&mut blu_events, event.h_ptr, OFFSET_LAST_ELEM_H * 8);
            cols.is_real = F::one();
            for i in 0..8 {
                let prev_value = event.h[i];
                let value = event.h_write_records[i].value;
                // The state is the `a, b, c, d, e, f, g, h` values.
                cols.initial_state[i] = u32_to_half_word(prev_value);
                // The `value` here is the resulting hash values, which are incremented by
                // `a, b, c, d, e, f, g, h` values - therefore, we do a subtraction here.
                cols.final_state[i] = u32_to_half_word((value as u32).wrapping_sub(prev_value));
            }
            if input.public_values.is_untrusted_programs_enabled == 1 {
                // Constrain page prot access for reading initial h state
                cols.h_read_page_prot_access.populate(
                    &mut blu_events,
                    event.h_ptr,
                    event.h_ptr + OFFSET_LAST_ELEM_H * 8,
                    event.clk,
                    PROT_READ,
                    &event.page_prot_access.h_read_page_prot_records[0],
                    &event.page_prot_access.h_read_page_prot_records.get(1).copied(),
                    input.public_values.is_untrusted_programs_enabled,
                );

                // Constrain page prot access for reading w state to feed into compress
                cols.w_read_page_prot_access.populate(
                    &mut blu_events,
                    event.w_ptr,
                    event.w_ptr + OFFSET_LAST_ELEM_W * 8,
                    event.clk + 1,
                    PROT_READ,
                    &event.page_prot_access.w_read_page_prot_records[0],
                    &event.page_prot_access.w_read_page_prot_records.get(1).copied(),
                    input.public_values.is_untrusted_programs_enabled,
                );

                // Constrain page prot access for writing final h after compress completed
                cols.h_write_page_prot_access.populate(
                    &mut blu_events,
                    event.h_ptr,
                    event.h_ptr + OFFSET_LAST_ELEM_H * 8,
                    event.clk + 2,
                    PROT_WRITE,
                    &event.page_prot_access.h_write_page_prot_records[0],
                    &event.page_prot_access.h_write_page_prot_records.get(1).copied(),
                    input.public_values.is_untrusted_programs_enabled,
                );
            }

            rows.push(row);
        }

        let nb_rows = rows.len();
        let padded_nb_rows = nb_rows.next_multiple_of(32);
        for _ in nb_rows..padded_nb_rows {
            let row = [F::zero(); NUM_SHA_COMPRESS_CONTROL_COLS];
            rows.push(row);
        }
        output.add_byte_lookup_events(blu_events);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_COMPRESS_CONTROL_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::SHA_COMPRESS).is_empty()
        }
    }
}

impl<AB> Air<AB> for ShaCompressControlChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Initialize columns.
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShaCompressControlCols<AB::Var> = (*local).borrow();

        // Constrain that `is_real` is boolean.
        builder.assert_bool(local.is_real);

        // Constrain the two pointers.
        // SAFETY: `w_ptr, h_ptr` are with valid u16 limbs, as they are received from the syscall.
        let w_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 512, local.w_ptr, local.is_real.into());
        let h_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 64, local.h_ptr, local.is_real.into());

        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([w_ptr[0].into(), w_ptr[1].into(), w_ptr[2].into(), AB::Expr::zero()]),
            Word::from(OFFSET_LAST_ELEM_W * 8 as u64),
            local.w_slice_end,
            local.is_real.into(),
        );

        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([h_ptr[0].into(), h_ptr[1].into(), h_ptr[2].into(), AB::Expr::zero()]),
            Word::from(OFFSET_LAST_ELEM_H * 8 as u64),
            local.h_slice_end,
            local.is_real.into(),
        );

        // Receive the syscall.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::SHA_COMPRESS.syscall_id()),
            w_ptr.map(Into::into),
            h_ptr.map(Into::into),
            local.is_real,
            InteractionScope::Local,
        );

        // Send the initial state. The initial index is 0.
        // The initial state will be constrained by the `ShaCompressChip`.
        let send_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(w_ptr.map(Into::into))
            .chain(h_ptr.map(Into::into))
            .chain(once(AB::Expr::from_canonical_u32(0)))
            .chain(
                local.initial_state.into_iter().flat_map(|word| word.into_iter()).map(Into::into),
            )
            .collect::<Vec<_>>();
        builder.send(
            AirInteraction::new(send_values, local.is_real.into(), InteractionKind::ShaCompress),
            InteractionScope::Local,
        );

        // Receive the final state. The final index is 80.
        // The final state will be constrained by the `ShaCompressChip`.
        let receive_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(w_ptr.map(Into::into))
            .chain(h_ptr.map(Into::into))
            .chain(once(AB::Expr::from_canonical_u32(80)))
            .chain(local.final_state.into_iter().flat_map(|word| word.into_iter()).map(Into::into))
            .collect::<Vec<_>>();
        builder.receive(
            AirInteraction::new(receive_values, local.is_real.into(), InteractionKind::ShaCompress),
            InteractionScope::Local,
        );

        AddressSlicePageProtOperation::<AB::F>::eval(
            builder,
            local.clk_high.into(),
            local.clk_low.into(),
            &local.h_ptr.addr.map(Into::into),
            &local.h_slice_end.value.map(Into::into),
            AB::Expr::from_canonical_u8(PROT_READ),
            &local.h_read_page_prot_access,
            local.is_real.into(),
        );

        AddressSlicePageProtOperation::<AB::F>::eval(
            builder,
            local.clk_high.into(),
            local.clk_low.into() + AB::Expr::one(),
            &local.w_ptr.addr.map(Into::into),
            &local.w_slice_end.value.map(Into::into),
            AB::Expr::from_canonical_u8(PROT_READ),
            &local.w_read_page_prot_access,
            local.is_real.into(),
        );

        AddressSlicePageProtOperation::<AB::F>::eval(
            builder,
            local.clk_high.into(),
            local.clk_low.into() + AB::Expr::from_canonical_u32(2),
            &local.h_ptr.addr.map(Into::into),
            &local.h_slice_end.value.map(Into::into),
            AB::Expr::from_canonical_u8(PROT_WRITE),
            &local.h_write_page_prot_access,
            local.is_real.into(),
        );
    }
}
