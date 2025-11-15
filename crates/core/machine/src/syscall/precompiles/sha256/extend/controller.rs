use super::ShaExtendControlChip;
use crate::{
    air::SP1CoreAirBuilder,
    operations::{AddrAddOperation, SyscallAddrOperation},
    utils::next_multiple_of_32,
};
use core::borrow::Borrow;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
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
use std::{borrow::BorrowMut, iter::once, mem::MaybeUninit};

impl ShaExtendControlChip {
    pub const fn new() -> Self {
        Self {}
    }
}

pub const NUM_SHA_EXTEND_CONTROL_COLS: usize = size_of::<ShaExtendControlCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaExtendControlCols<T> {
    pub clk_high: T,
    pub clk_low: T,
    pub w_ptr: SyscallAddrOperation<T>,
    pub w_16th_addr: AddrAddOperation<T>,
    pub w_17th_addr: AddrAddOperation<T>,
    pub w_64th_addr: AddrAddOperation<T>,

    pub is_real: T,
}

impl<F> BaseAir<F> for ShaExtendControlChip {
    fn width(&self) -> usize {
        NUM_SHA_EXTEND_CONTROL_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for ShaExtendControlChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "ShaExtendControl".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.get_precompile_events(SyscallCode::SHA_EXTEND).len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows =
            <ShaExtendControlChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::SHA_EXTEND);
        let num_event_rows = events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_SHA_EXTEND_CONTROL_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_SHA_EXTEND_CONTROL_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(
                buffer_ptr,
                num_event_rows * NUM_SHA_EXTEND_CONTROL_COLS,
            )
        };

        let mut blu_events = Vec::new();

        values.chunks_mut(NUM_SHA_EXTEND_CONTROL_COLS).enumerate().for_each(|(idx, row)| {
            let event = &events[idx].1;
            let event =
                if let PrecompileEvent::ShaExtend(event) = event { event } else { unreachable!() };

            let cols: &mut ShaExtendControlCols<F> = row.borrow_mut();
            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
            // This precompile accesses 64 words, which is 512 bytes.
            cols.w_ptr.populate(&mut blu_events, event.w_ptr, 512);
            // Address of 16th element of W, last read only element
            cols.w_16th_addr.populate(&mut blu_events, event.w_ptr, 15 * 8);
            // Address of 17th element of W, first written element
            cols.w_17th_addr.populate(&mut blu_events, event.w_ptr, 16 * 8);
            // Address of 64th element of W, last written element
            cols.w_64th_addr.populate(&mut blu_events, event.w_ptr, 63 * 8);
            cols.is_real = F::one();
        });

        output.add_byte_lookup_events(blu_events);
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::SHA_EXTEND).is_empty()
        }
    }
}

impl<AB> Air<AB> for ShaExtendControlChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Initialize columns.
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShaExtendControlCols<AB::Var> = (*local).borrow();

        // Check that `is_real` is boolean.
        builder.assert_bool(local.is_real);

        // Check that `w_ptr` is within bounds.
        // SAFETY: `w_ptr` is with 3 u16 limbs, as it is received from the syscall.
        let w_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 512, local.w_ptr, local.is_real.into());

        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([w_ptr[0].into(), w_ptr[1].into(), w_ptr[2].into(), AB::Expr::zero()]),
            Word([
                AB::Expr::from_canonical_u32(15 * 8),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
            ]),
            local.w_16th_addr,
            local.is_real.into(),
        );

        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([w_ptr[0].into(), w_ptr[1].into(), w_ptr[2].into(), AB::Expr::zero()]),
            Word([
                AB::Expr::from_canonical_u32(16 * 8),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
            ]),
            local.w_17th_addr,
            local.is_real.into(),
        );

        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([w_ptr[0].into(), w_ptr[1].into(), w_ptr[2].into(), AB::Expr::zero()]),
            Word([
                AB::Expr::from_canonical_u32(63 * 8),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
            ]),
            local.w_64th_addr,
            local.is_real.into(),
        );

        // Receive the syscall.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::SHA_EXTEND.syscall_id()),
            w_ptr.map(Into::into),
            [AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()],
            local.is_real,
            InteractionScope::Local,
        );

        // Send the initial state, with the starting index being 16.
        let send_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into() + AB::Expr::one()))
            .chain(w_ptr.map(Into::into))
            .chain(once(AB::Expr::from_canonical_u32(16)))
            .collect::<Vec<_>>();
        builder.send(
            AirInteraction::new(send_values, local.is_real.into(), InteractionKind::ShaExtend),
            InteractionScope::Local,
        );

        // Receive the final state, with the final index being 64.
        let receive_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into() + AB::Expr::one()))
            .chain(w_ptr.map(Into::into))
            .chain(once(AB::Expr::from_canonical_u32(64)))
            .collect::<Vec<_>>();
        builder.receive(
            AirInteraction::new(receive_values, local.is_real.into(), InteractionKind::ShaExtend),
            InteractionScope::Local,
        );
    }
}
