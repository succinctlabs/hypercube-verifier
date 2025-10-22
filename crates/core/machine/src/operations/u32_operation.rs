use slop_algebra::{AbstractField, Field};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::consts::u32_to_u16_limbs;

/// A set of columns to convert a u32 with u16 limbs into u8 limbs.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct U32toU8Operation<T> {
    low_bytes: [T; 2],
}

impl<F: Field> U32toU8Operation<F> {
    pub fn populate_u32_to_u8_unsafe(&mut self, a_u32: u32) {
        let a_limbs = u32_to_u16_limbs(a_u32);
        self.low_bytes[0] = F::from_canonical_u8((a_limbs[0] & 0xFF) as u8);
        self.low_bytes[1] = F::from_canonical_u8((a_limbs[1] & 0xFF) as u8);
    }

    /// Converts two u16 limbs into four u8 limbs.
    /// This function assumes that the u8 limbs will be range checked.
    pub fn eval_u32_to_u8_unsafe<AB: SP1AirBuilder>(
        _: &mut AB,
        u32_values: [AB::Expr; 2],
        cols: U32toU8Operation<AB::Var>,
    ) -> [AB::Expr; 4] {
        let mut ret = core::array::from_fn(|_| AB::Expr::zero());
        let divisor = AB::F::from_canonical_u32(1 << 8).inverse();

        for i in 0..2 {
            ret[i * 2] = cols.low_bytes[i].into();
            ret[i * 2 + 1] = (u32_values[i].clone() - ret[i * 2].clone()) * divisor;
        }

        ret
    }
}
