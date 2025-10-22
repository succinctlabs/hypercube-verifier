use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_derive::AlignedBorrow;

use sp1_core_executor::{events::ByteRecord, ByteOpcode};
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::consts::u64_to_u16_limbs;

use super::{IsZeroOperation, IsZeroOperationInput};
use crate::air::{SP1Operation, SP1OperationBuilder};

/// A set of columns needed to validate the address and return the aligned address.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SyscallAddrOperation<T> {
    /// The address itself.
    pub addr: [T; 3],

    /// This is used to check if the top two limbs of the address is not both zero.
    pub top_two_limb_min: T,

    /// This is used to check if the top two limbs of the address is u16::MAX.
    pub top_two_limb_max: IsZeroOperation<T>,
}

impl<F: PrimeField32> SyscallAddrOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, addr: u64, len: u64) {
        let addr_limbs = u64_to_u16_limbs(addr);
        let sum_top_two_limb =
            F::from_canonical_u16(addr_limbs[1]) + F::from_canonical_u16(addr_limbs[2]);
        self.addr[0] = F::from_canonical_u16(addr_limbs[0]);
        self.addr[1] = F::from_canonical_u16(addr_limbs[1]);
        self.addr[2] = F::from_canonical_u16(addr_limbs[2]);
        self.top_two_limb_min = sum_top_two_limb.inverse();
        let is_max = self.top_two_limb_max.populate_from_field_element(
            sum_top_two_limb - F::from_canonical_u16(u16::MAX) * F::two(),
        );
        if is_max == 1 {
            record.add_bit_range_check((addr_limbs[0] + (len as u16)) / 8, 13);
        } else {
            record.add_bit_range_check(addr_limbs[0] / 8, 13);
        }
    }
}

impl<F: Field> SyscallAddrOperation<F> {
    /// The memory address is constrained to be aligned, `>= 2^16` and less than `2^48 - len`.
    /// The `cols.addr` is assumed to be composed of valid 3 u16 limbs.
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder + SP1OperationBuilder<IsZeroOperation<<AB as AirBuilder>::F>>>(
        builder: &mut AB,
        len: u32,
        cols: SyscallAddrOperation<AB::Var>,
        is_real: AB::Expr,
    ) -> [AB::Var; 3] {
        // This is not a constraint, but a sanity check
        assert!(len.is_multiple_of(8));

        // Check that `is_real` and offset bits are boolean.
        builder.assert_bool(is_real.clone());

        let sum_top_two_limb = cols.addr[1] + cols.addr[2];

        // Check that `addr >= 2^16`, so it doesn't touch registers.
        // This implements a stack guard of size 2^16 bytes = 64KB.
        // If `is_real = 1`, then `addr.0[1] + addr.0[2] != 0`, so `addr >= 2^16`.
        builder.assert_eq(cols.top_two_limb_min * sum_top_two_limb.clone(), is_real.clone());

        IsZeroOperation::<AB::F>::eval(
            builder,
            IsZeroOperationInput::new(
                sum_top_two_limb.clone() - AB::Expr::from_canonical_u16(u16::MAX) * AB::Expr::two(),
                cols.top_two_limb_max,
                is_real.clone(),
            ),
        );

        // Check `0 <= (addr[0] + len * top_two_limb_max.result) / 8 < 2^13`.
        // If `addr[1] == addr[2] == u16::MAX`, this shows `addr + len < 2^48`.
        // This also shows that `addr[0]` is a multiple of 8 in all cases.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            (cols.addr[0] + cols.top_two_limb_max.result * AB::Expr::from_canonical_u32(len))
                * AB::F::from_canonical_u32(8).inverse(),
            AB::Expr::from_canonical_u32(13),
            AB::Expr::zero(),
            is_real.clone(),
        );

        [cols.addr[0], cols.addr[1], cols.addr[2]]
    }
}
