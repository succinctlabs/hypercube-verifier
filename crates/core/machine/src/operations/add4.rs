use slop_algebra::{AbstractField, Field};
use sp1_derive::AlignedBorrow;

use sp1_core_executor::events::ByteRecord;
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::consts::u32_to_u16_limbs;

use crate::{air::WordAirBuilder, utils::u32_to_half_word};

/// A set of columns needed to compute the add of four u32s as u32.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Add4Operation<T> {
    /// The result of `a + b + c + d`.
    pub value: [T; 2],
}

impl<F: Field> Add4Operation<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        a_u32: u32,
        b_u32: u32,
        c_u32: u32,
        d_u32: u32,
    ) -> u32 {
        let expected = a_u32.wrapping_add(b_u32).wrapping_add(c_u32).wrapping_add(d_u32);
        let expected_limbs = u32_to_u16_limbs(expected);
        self.value = u32_to_half_word(expected);
        let a = u32_to_u16_limbs(a_u32);
        let b = u32_to_u16_limbs(b_u32);
        let c = u32_to_u16_limbs(c_u32);
        let d = u32_to_u16_limbs(d_u32);

        let base = 1u32 << 16;
        let mut carry_limbs = [0u8; 2];
        let mut carry = 0;
        for i in 0..2 {
            carry = ((a[i] as u32) + (b[i] as u32) + (c[i] as u32) + (d[i] as u32) + carry
                - expected_limbs[i] as u32)
                / base;
            carry_limbs[i] = carry as u8;
        }

        // Range check.
        record.add_u16_range_checks(&expected_limbs);
        record.add_u8_range_checks(&carry_limbs);
        expected
    }

    /// Evaluate the add4 operation.
    /// Assumes that `a`, `b`, `c`, `d` are valid u32s of two u16 limbs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real == 1` , the `value` is constrained to a valid u32 representing `a + b + c + d`.
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: [AB::Expr; 2],
        b: [AB::Expr; 2],
        c: [AB::Expr; 2],
        d: [AB::Expr; 2],
        is_real: AB::Var,
        cols: Add4Operation<AB::Var>,
    ) {
        builder.assert_bool(is_real);

        let base = AB::F::from_canonical_u32(1 << 16);
        let mut carry_limbs = [AB::Expr::zero(), AB::Expr::zero()];
        let mut carry = AB::Expr::zero(); // Initialize carry to zero

        // The set of constraints are
        //  - carry is initialized to zero
        //  - 2^16 * carry_next + value[i] = a[i] + b[i] + c[i] + d[i] + carry
        //  - 0 <= carry < 2^8
        //  - 0 <= value[i] < 2^16
        // Since the carries are bounded by 2^8, no SP1Field overflows are possible.
        // The maximum carry possible is less than 2^8, so the circuit is complete.
        for i in 0..2 {
            carry = (a[i].clone() + b[i].clone() + c[i].clone() + d[i].clone() - cols.value[i]
                + carry)
                * base.inverse();
            carry_limbs[i] = carry.clone();
        }
        // Range check each limb.
        builder.slice_range_check_u16(&cols.value, is_real);
        builder.slice_range_check_u8(&carry_limbs, is_real);
    }
}
