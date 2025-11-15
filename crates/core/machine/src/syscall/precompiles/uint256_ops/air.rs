use std::borrow::Borrow;

use crate::{
    air::SP1CoreAirBuilder,
    memory::{MemoryAccessCols, MemoryAccessColsU8},
    operations::{field::field_op::FieldOpCols, AddrAddOperation},
    utils::limbs_to_words,
};
use itertools::Itertools;
use slop_air::{Air, BaseAir};
use slop_algebra::AbstractField;
use slop_matrix::Matrix;
use sp1_core_executor::syscalls::SyscallCode;
use sp1_curves::{
    params::{Limbs, NumLimbs, NumWords},
    uint256::U256Field,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::InteractionScope, Word};
use sp1_primitives::polynomial::Polynomial;
use typenum::Unsigned;

use crate::operations::SyscallAddrOperation;

/// The number of main trace columns for `Uint256OpsChip`.
pub const NUM_UINT256_OPS_COLS: usize = size_of::<Uint256OpsCols<u8>>();

/// A chip that implements uint256 operations for the SP1 RISC-V zkVM.
#[derive(Default)]
pub struct Uint256OpsChip;
type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

/// The column layout for the chip.
#[derive(AlignedBorrow, Debug, Clone)]
#[repr(C)]
pub struct Uint256OpsCols<T> {
    /// The high bits of the clk of the syscall.
    pub clk_high: T,

    /// The low bits of the clk of the syscall.
    pub clk_low: T,

    /// The pointer to the a value.
    pub a_ptr: SyscallAddrOperation<T>,
    pub a_addrs: [AddrAddOperation<T>; 4],

    /// The pointer to the b value.
    pub b_ptr: SyscallAddrOperation<T>,
    pub b_addrs: [AddrAddOperation<T>; 4],

    /// The pointer to the c value.
    pub c_ptr: SyscallAddrOperation<T>,
    pub c_ptr_memory: MemoryAccessCols<T>,
    pub c_addrs: [AddrAddOperation<T>; 4],

    /// The pointer to the d value (result low).
    pub d_ptr: SyscallAddrOperation<T>,
    pub d_ptr_memory: MemoryAccessCols<T>,
    pub d_addrs: [AddrAddOperation<T>; 4],

    /// The pointer to the e value (result high).
    pub e_ptr: SyscallAddrOperation<T>,
    pub e_ptr_memory: MemoryAccessCols<T>,
    pub e_addrs: [AddrAddOperation<T>; 4],

    pub a_memory: [MemoryAccessColsU8<T>; WORDS_FIELD_ELEMENT],
    pub b_memory: [MemoryAccessColsU8<T>; WORDS_FIELD_ELEMENT],
    pub c_memory: [MemoryAccessColsU8<T>; WORDS_FIELD_ELEMENT],
    pub d_memory: [MemoryAccessCols<T>; WORDS_FIELD_ELEMENT],
    pub e_memory: [MemoryAccessCols<T>; WORDS_FIELD_ELEMENT],

    pub field_op: FieldOpCols<T, U256Field>,

    /// 1 if this is an add operation, 0 otherwise.
    pub is_add: T,

    /// 1 if this is a mul operation, 0 otherwise.
    pub is_mul: T,

    /// 1 if this is a real operation, 0 otherwise.
    pub is_real: T,
}

impl<F> BaseAir<F> for Uint256OpsChip {
    fn width(&self) -> usize {
        NUM_UINT256_OPS_COLS
    }
}

impl<AB> Air<AB> for Uint256OpsChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Uint256OpsCols<AB::Var> = (*local).borrow();

        // Check that this row is enabled.
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_mul);
        builder.assert_bool(local.is_real);
        builder.assert_eq(local.is_real, local.is_add + local.is_mul);

        let a_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 32, local.a_ptr, local.is_real.into());
        let b_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 32, local.b_ptr, local.is_real.into());
        let c_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 32, local.c_ptr, local.is_real.into());
        let d_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 32, local.d_ptr, local.is_real.into());
        let e_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 32, local.e_ptr, local.is_real.into());

        let syscall_id = AB::Expr::from_canonical_u32(SyscallCode::UINT256_ADD_CARRY.syscall_id())
            * local.is_add
            + AB::Expr::from_canonical_u32(SyscallCode::UINT256_MUL_CARRY.syscall_id())
                * local.is_mul;

        // Receive the arguments.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            syscall_id,
            a_ptr.map(Into::into),
            b_ptr.map(Into::into),
            local.is_real,
            InteractionScope::Local,
        );

        builder.eval_memory_access_read(
            local.clk_high,
            local.clk_low.into(),
            &[AB::Expr::from_canonical_u32(12), AB::Expr::zero(), AB::Expr::zero()],
            local.c_ptr_memory,
            local.is_real,
        );
        builder.assert_word_eq(
            local.c_ptr_memory.prev_value,
            Word([c_ptr[0].into(), c_ptr[1].into(), c_ptr[2].into(), AB::Expr::zero()]),
        );

        builder.eval_memory_access_read(
            local.clk_high,
            local.clk_low.into(),
            &[AB::Expr::from_canonical_u32(13), AB::Expr::zero(), AB::Expr::zero()],
            local.d_ptr_memory,
            local.is_real,
        );
        builder.assert_word_eq(
            local.d_ptr_memory.prev_value,
            Word([d_ptr[0].into(), d_ptr[1].into(), d_ptr[2].into(), AB::Expr::zero()]),
        );

        builder.eval_memory_access_read(
            local.clk_high,
            local.clk_low.into(),
            &[AB::Expr::from_canonical_u32(14), AB::Expr::zero(), AB::Expr::zero()],
            local.e_ptr_memory,
            local.is_real,
        );
        builder.assert_word_eq(
            local.e_ptr_memory.prev_value,
            Word([e_ptr[0].into(), e_ptr[1].into(), e_ptr[2].into(), AB::Expr::zero()]),
        );

        for i in 0..4 {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([a_ptr[0].into(), a_ptr[1].into(), a_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.a_addrs[i],
                local.is_real.into(),
            );
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([b_ptr[0].into(), b_ptr[1].into(), b_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.b_addrs[i],
                local.is_real.into(),
            );
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([c_ptr[0].into(), c_ptr[1].into(), c_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.c_addrs[i],
                local.is_real.into(),
            );
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([d_ptr[0].into(), d_ptr[1].into(), d_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.d_addrs[i],
                local.is_real.into(),
            );
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([e_ptr[0].into(), e_ptr[1].into(), e_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.e_addrs[i],
                local.is_real.into(),
            );
        }

        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low.into(),
            &local.a_addrs.map(|addr| addr.value.map(Into::into)),
            &local.a_memory.iter().map(|access| access.memory_access).collect_vec(),
            local.is_real,
        );
        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low.into() + AB::Expr::one(),
            &local.b_addrs.map(|addr| addr.value.map(Into::into)),
            &local.b_memory.iter().map(|access| access.memory_access).collect_vec(),
            local.is_real,
        );
        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low.into() + AB::Expr::from_canonical_u8(2),
            &local.c_addrs.map(|addr| addr.value.map(Into::into)),
            &local.c_memory.iter().map(|access| access.memory_access).collect_vec(),
            local.is_real,
        );

        let a_limbs_vec = builder.generate_limbs(&local.a_memory, local.is_real.into());
        let a_limbs: Limbs<AB::Expr, <U256Field as NumLimbs>::Limbs> =
            Limbs(a_limbs_vec.try_into().expect("failed to convert limbs"));
        let b_limbs_vec = builder.generate_limbs(&local.b_memory, local.is_real.into());
        let b_limbs: Limbs<AB::Expr, <U256Field as NumLimbs>::Limbs> =
            Limbs(b_limbs_vec.try_into().expect("failed to convert limbs"));
        let c_limbs_vec = builder.generate_limbs(&local.c_memory, local.is_real.into());
        let c_limbs: Limbs<AB::Expr, <U256Field as NumLimbs>::Limbs> =
            Limbs(c_limbs_vec.try_into().expect("failed to convert limbs"));

        let mut coeff_2_256 = Vec::new();
        coeff_2_256.resize(32, AB::Expr::zero());
        coeff_2_256.push(AB::Expr::one());
        let modulus_polynomial: Polynomial<AB::Expr> = Polynomial::from_coefficients(&coeff_2_256);

        local.field_op.eval_add_mul_and_carry(
            builder,
            local.is_add,
            local.is_mul,
            &a_limbs,
            &b_limbs,
            &c_limbs,
            &modulus_polynomial,
            local.is_real,
        );

        let d_result = limbs_to_words::<AB>(local.field_op.result.0.to_vec());
        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::from_canonical_u8(3),
            &local.d_addrs.map(|addr| addr.value.map(Into::into)),
            &local.d_memory,
            d_result,
            local.is_real,
        );

        let e_result = limbs_to_words::<AB>(local.field_op.carry.0.to_vec());
        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::from_canonical_u8(4),
            &local.e_addrs.map(|addr| addr.value.map(Into::into)),
            &local.e_memory,
            e_result,
            local.is_real,
        );
    }
}
