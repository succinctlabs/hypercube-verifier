use slop_air::{Air, BaseAir};
use slop_algebra::AbstractField;
use slop_matrix::Matrix;
use sp1_core_executor::ByteOpcode;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope},
    InteractionKind, Word,
};

use super::{ShaExtendChip, ShaExtendCols, NUM_SHA_EXTEND_COLS};
use crate::{
    air::SP1CoreAirBuilder,
    operations::{
        Add4Operation, AddrAddOperation, ClkOperation, FixedRotateRightOperation,
        FixedShiftRightOperation, XorU32Operation,
    },
};

use core::borrow::Borrow;
use std::iter::once;

impl<F> BaseAir<F> for ShaExtendChip {
    fn width(&self) -> usize {
        NUM_SHA_EXTEND_COLS
    }
}

impl<AB> Air<AB> for ShaExtendChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Initialize columns.
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShaExtendCols<AB::Var> = (*local).borrow();

        // Assert that `is_real` is a bool.
        builder.assert_bool(local.is_real);

        // Receive the state.
        let receive_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(local.w_ptr.map(Into::into))
            .chain(once(local.i.into()))
            .collect::<Vec<_>>();
        builder.receive(
            AirInteraction::new(receive_values, local.is_real.into(), InteractionKind::ShaExtend),
            InteractionScope::Local,
        );

        // Send the next state, with incremented `local.i`.
        let send_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(local.w_ptr.map(Into::into))
            .chain(once(local.i + AB::Expr::one()))
            .collect::<Vec<_>>();
        builder.send(
            AirInteraction::new(send_values, local.is_real.into(), InteractionKind::ShaExtend),
            InteractionScope::Local,
        );

        // Check that `16 <= local.i < 64` holds.
        // This makes all the `AddrAddOperation`s below safe, as the increments will be bounded.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::LTU as u32),
            AB::Expr::one(),
            local.i - AB::Expr::from_canonical_u32(16),
            AB::Expr::from_canonical_u32(48),
            local.is_real,
        );

        // First, evaluate `clk_low + (i - 16)` to check for overflows.
        // SAFETY: `(i - 16)` is known to be less than `48`.
        // `local.clk_low` is sent from the syscall, so is within 24 bits.
        ClkOperation::<AB::F>::eval(
            builder,
            local.clk_low.into(),
            local.i - AB::Expr::from_canonical_u32(16),
            local.next_clk,
            local.is_real.into(),
        );

        let ptr = Word([
            local.w_ptr[0].into(),
            local.w_ptr[1].into(),
            local.w_ptr[2].into(),
            AB::Expr::zero(),
        ]);

        // Evaluate the pointer `ptr + (i - 15) * 8`.
        AddrAddOperation::<AB::F>::eval(
            builder,
            ptr.clone(),
            Word::extend_expr::<AB>(
                (local.i - AB::F::from_canonical_u32(15)) * AB::F::from_canonical_u32(8),
            ),
            local.w_i_minus_15_ptr,
            local.is_real.into(),
        );

        // Read `w[i - 15]`.
        builder.eval_memory_access_read(
            local.next_clk.next_clk_high::<AB>(local.clk_high),
            local.next_clk.next_clk_low::<AB>(),
            &local.w_i_minus_15_ptr.value.map(Into::into),
            local.w_i_minus_15,
            local.is_real,
        );

        // Check that `w[i - 15]` is an u32 value.
        let w_i_minus_15_prev_value_half_word =
            [local.w_i_minus_15.prev_value[0], local.w_i_minus_15.prev_value[1]];
        builder.assert_zero(local.w_i_minus_15.prev_value[2]);
        builder.assert_zero(local.w_i_minus_15.prev_value[3]);

        // Evaluate the pointer `ptr + (i - 2) * 8`.
        AddrAddOperation::<AB::F>::eval(
            builder,
            ptr.clone(),
            Word::extend_expr::<AB>(
                (local.i - AB::F::from_canonical_u32(2)) * AB::F::from_canonical_u32(8),
            ),
            local.w_i_minus_2_ptr,
            local.is_real.into(),
        );

        // Read `w[i - 2]`.
        builder.eval_memory_access_read(
            local.next_clk.next_clk_high::<AB>(local.clk_high),
            local.next_clk.next_clk_low::<AB>(),
            &local.w_i_minus_2_ptr.value.map(Into::into),
            local.w_i_minus_2,
            local.is_real,
        );

        // Check that `w[i - 2]` is an u32 value.
        let w_i_minus_2_prev_value_half_word =
            [local.w_i_minus_2.prev_value[0], local.w_i_minus_2.prev_value[1]];
        builder.assert_zero(local.w_i_minus_2.prev_value[2]);
        builder.assert_zero(local.w_i_minus_2.prev_value[3]);

        // Evaluate the pointer `ptr + (i - 16) * 8`.
        AddrAddOperation::<AB::F>::eval(
            builder,
            ptr.clone(),
            Word::extend_expr::<AB>(
                (local.i - AB::F::from_canonical_u32(16)) * AB::F::from_canonical_u32(8),
            ),
            local.w_i_minus_16_ptr,
            local.is_real.into(),
        );

        // Read `w[i - 16]`.
        builder.eval_memory_access_read(
            local.next_clk.next_clk_high::<AB>(local.clk_high),
            local.next_clk.next_clk_low::<AB>(),
            &local.w_i_minus_16_ptr.value.map(Into::into),
            local.w_i_minus_16,
            local.is_real,
        );

        // Check that `w[i - 16]` is an u32 value.
        let w_i_minus_16_prev_value_half_word =
            [local.w_i_minus_16.prev_value[0], local.w_i_minus_16.prev_value[1]];
        builder.assert_zero(local.w_i_minus_16.prev_value[2]);
        builder.assert_zero(local.w_i_minus_16.prev_value[3]);

        // Evaluate the pointer `ptr + (i - 7) * 8`.
        AddrAddOperation::<AB::F>::eval(
            builder,
            ptr.clone(),
            Word::extend_expr::<AB>(
                (local.i - AB::F::from_canonical_u32(7)) * AB::F::from_canonical_u32(8),
            ),
            local.w_i_minus_7_ptr,
            local.is_real.into(),
        );

        // Read `w[i - 7]`.
        builder.eval_memory_access_read(
            local.next_clk.next_clk_high::<AB>(local.clk_high),
            local.next_clk.next_clk_low::<AB>(),
            &local.w_i_minus_7_ptr.value.map(Into::into),
            local.w_i_minus_7,
            local.is_real,
        );

        // Check that `w[i - 7]` is an u32 value.
        let w_i_minus_7_prev_value_half_word =
            [local.w_i_minus_7.prev_value[0], local.w_i_minus_7.prev_value[1]];
        builder.assert_zero(local.w_i_minus_7.prev_value[2]);
        builder.assert_zero(local.w_i_minus_7.prev_value[3]);

        // Compute `s0`.
        // w[i-15] rightrotate 7.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            w_i_minus_15_prev_value_half_word,
            7,
            local.w_i_minus_15_rr_7,
            local.is_real,
        );
        // w[i-15] rightrotate 18.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            w_i_minus_15_prev_value_half_word,
            18,
            local.w_i_minus_15_rr_18,
            local.is_real,
        );
        // w[i-15] rightshift 3.
        FixedShiftRightOperation::<AB::F>::eval(
            builder,
            w_i_minus_15_prev_value_half_word,
            3,
            local.w_i_minus_15_rs_3,
            local.is_real,
        );
        // (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18)
        let s0_intermediate_result = XorU32Operation::<AB::F>::eval_xor_u32(
            builder,
            local.w_i_minus_15_rr_7.value.map(Into::into),
            local.w_i_minus_15_rr_18.value.map(Into::into),
            local.s0_intermediate,
            local.is_real,
        );
        // s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
        let s0_result = XorU32Operation::<AB::F>::eval_xor_u32(
            builder,
            s0_intermediate_result,
            local.w_i_minus_15_rs_3.value.map(Into::into),
            local.s0,
            local.is_real,
        );

        // Compute `s1`.
        // w[i-2] rightrotate 17.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            w_i_minus_2_prev_value_half_word,
            17,
            local.w_i_minus_2_rr_17,
            local.is_real,
        );
        // w[i-2] rightrotate 19.
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            w_i_minus_2_prev_value_half_word,
            19,
            local.w_i_minus_2_rr_19,
            local.is_real,
        );
        // w[i-2] rightshift 10.
        FixedShiftRightOperation::<AB::F>::eval(
            builder,
            w_i_minus_2_prev_value_half_word,
            10,
            local.w_i_minus_2_rs_10,
            local.is_real,
        );
        // (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19)
        let s1_intermediate_result = XorU32Operation::<AB::F>::eval_xor_u32(
            builder,
            local.w_i_minus_2_rr_17.value.map(Into::into),
            local.w_i_minus_2_rr_19.value.map(Into::into),
            local.s1_intermediate,
            local.is_real,
        );
        // s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
        let s1_result = XorU32Operation::<AB::F>::eval_xor_u32(
            builder,
            s1_intermediate_result,
            local.w_i_minus_2_rs_10.value.map(Into::into),
            local.s1,
            local.is_real,
        );

        // s2 := w[i-16] + s0 + w[i-7] + s1.
        Add4Operation::<AB::F>::eval(
            builder,
            w_i_minus_16_prev_value_half_word.map(Into::into),
            s0_result,
            w_i_minus_7_prev_value_half_word.map(Into::into),
            s1_result,
            local.is_real,
            local.s2,
        );

        // The `s2_value_word` is the value to be written.
        let s2_value_word = Word([
            local.s2.value[0].into(),
            local.s2.value[1].into(),
            AB::Expr::zero(),
            AB::Expr::zero(),
        ]);

        // Evaluate the pointer `ptr + i * 8`.
        AddrAddOperation::<AB::F>::eval(
            builder,
            ptr.clone(),
            Word::extend_expr::<AB>(local.i * AB::F::from_canonical_u32(8)),
            local.w_i_ptr,
            local.is_real.into(),
        );

        // Write `s2_value_word` into `w[i]`.
        builder.eval_memory_access_write(
            local.next_clk.next_clk_high::<AB>(local.clk_high),
            local.next_clk.next_clk_low::<AB>(),
            &local.w_i_ptr.value.map(Into::into),
            local.w_i,
            s2_value_word,
            local.is_real,
        );
    }
}
