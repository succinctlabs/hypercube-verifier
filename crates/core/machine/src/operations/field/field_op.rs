use std::fmt::Debug;

use crate::air::WordAirBuilder;
use num::{BigUint, Zero};

use slop_air::AirBuilder;
use slop_algebra::PrimeField32;

use sp1_core_executor::events::{ByteRecord, FieldOperation};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::polynomial::Polynomial;

use super::util_air::eval_field_operation;
use sp1_curves::params::{FieldParameters, Limbs};

/// A set of columns to compute an emulated modular arithmetic operation.
///
/// *Safety* The input operands (a, b) (not included in the operation columns) are assumed to be
/// elements within the range `[0, 2^{P::nb_bits()})`. the result is also assumed to be within the
/// same range. Let `M = P:modulus()`. The constraints of the function [`FieldOpCols::eval`] assert
/// that:
/// * When `op` is `FieldOperation::Add`, then `result = a + b mod M`.
/// * When `op` is `FieldOperation::Mul`, then `result = a * b mod M`.
/// * When `op` is `FieldOperation::Sub`, then `result = a - b mod M`.
/// * When `op` is `FieldOperation::Div`, then `result * b = a mod M`.
///
/// **Warning**: The constraints do not check for division by zero. The caller is responsible for
/// ensuring that the division operation is valid.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldOpCols<T, P: FieldParameters> {
    /// The result of `a op b`, where a, b are field elements
    pub result: Limbs<T, P::Limbs>,
    pub carry: Limbs<T, P::Limbs>,
    pub(crate) witness: Limbs<T, P::Witness>,
}

impl<F: PrimeField32, P: FieldParameters> FieldOpCols<F, P> {
    #[allow(clippy::too_many_arguments)]
    /// Populate result and carry columns from the equation (a*b + c) % modulus
    pub fn populate_mul_and_carry(
        &mut self,
        record: &mut impl ByteRecord,
        a: &BigUint,
        b: &BigUint,
        c: &BigUint,
        modulus: &BigUint,
    ) -> (BigUint, BigUint) {
        let mut p_a: Vec<u8> = a.to_bytes_le();
        p_a.resize(P::NB_LIMBS, 0);
        let mut p_b: Vec<u8> = b.to_bytes_le();
        p_b.resize(P::NB_LIMBS, 0);
        let mut p_c: Vec<u8> = c.to_bytes_le();
        p_c.resize(P::NB_LIMBS, 0);

        let mul_add = a * b + c;
        let result = &mul_add % modulus;
        let carry = (mul_add - &result) / modulus;
        debug_assert!(&result < modulus);
        debug_assert!(&carry < modulus);
        debug_assert_eq!(&carry * modulus, a * b + c - &result);

        let mut p_modulus: Vec<u8> = modulus.to_bytes_le();
        p_modulus.resize(P::MODULUS_LIMBS, 0);
        let mut p_result: Vec<u8> = result.to_bytes_le();
        p_result.resize(P::NB_LIMBS, 0);
        let mut p_carry: Vec<u8> = carry.to_bytes_le();
        p_carry.resize(P::NB_LIMBS, 0);

        let mut p_vanishing_limbs = vec![0i32; P::NB_WITNESS_LIMBS + 1];
        for i in 0..P::NB_LIMBS {
            for j in 0..P::NB_LIMBS {
                p_vanishing_limbs[i + j] += (p_a[i] as u16 * p_b[j] as u16) as i32;
            }
        }
        for i in 0..P::NB_LIMBS {
            p_vanishing_limbs[i] += (p_c[i] as u16) as i32;
            p_vanishing_limbs[i] -= (p_result[i] as u16) as i32;
        }
        for i in 0..P::NB_LIMBS {
            for j in 0..P::MODULUS_LIMBS {
                p_vanishing_limbs[i + j] -= (p_carry[i] as u16 * p_modulus[j] as u16) as i32;
            }
        }

        let len = P::NB_WITNESS_LIMBS + 1;
        let mut pol_carry = p_vanishing_limbs[len - 1];
        for i in (0..len - 1).rev() {
            let ai = p_vanishing_limbs[i];
            p_vanishing_limbs[i] = pol_carry;
            pol_carry = ai + pol_carry * 256;
        }
        debug_assert_eq!(pol_carry, 0);

        for i in 0..P::NB_LIMBS {
            self.result[i] = F::from_canonical_u8(p_result[i]);
            self.carry[i] = F::from_canonical_u8(p_carry[i]);
        }
        for i in 0..P::NB_WITNESS_LIMBS {
            self.witness[i] =
                F::from_canonical_u16((p_vanishing_limbs[i] + P::WITNESS_OFFSET as i32) as u16);
        }

        record.add_u8_range_checks_field(&self.result.0);
        record.add_u8_range_checks_field(&self.carry.0);
        record.add_u16_range_checks_field(&self.witness.0);

        (result, carry)
    }

    /// Populate result and carry columns from the equation (is_add * (a + b) + is_mul * (a * b) +
    /// c) % modulus This function handles conditional operations based on is_add and is_mul
    /// flags.
    #[allow(clippy::too_many_arguments)]
    pub fn populate_conditional_op_and_carry(
        &mut self,
        record: &mut impl ByteRecord,
        a: &BigUint,
        b: &BigUint,
        c: &BigUint,
        modulus: &BigUint,
        is_add: bool,
        _is_mul: bool,
    ) -> (BigUint, BigUint) {
        let mut p_a: Vec<u8> = a.to_bytes_le();
        p_a.resize(P::NB_LIMBS, 0);
        let mut p_b: Vec<u8> = b.to_bytes_le();
        p_b.resize(P::NB_LIMBS, 0);
        let mut p_c: Vec<u8> = c.to_bytes_le();
        p_c.resize(P::NB_LIMBS, 0);

        // Compute (is_add * (a + b) + is_mul * (a * b) + c)
        let intermediate = if is_add { a + b + c } else { a * b + c };

        let result = &intermediate % modulus;
        let carry = (&intermediate - &result) / modulus;
        debug_assert!(&result < modulus);
        debug_assert!(&carry < modulus);
        debug_assert_eq!(&carry * modulus, &intermediate - &result);

        let mut p_modulus: Vec<u8> = modulus.to_bytes_le();
        p_modulus.resize(P::MODULUS_LIMBS, 0);
        let mut p_result: Vec<u8> = result.to_bytes_le();
        p_result.resize(P::NB_LIMBS, 0);
        let mut p_carry: Vec<u8> = carry.to_bytes_le();
        p_carry.resize(P::NB_LIMBS, 0);

        let mut p_vanishing_limbs = vec![0i32; P::NB_WITNESS_LIMBS + 1];

        // Compute the vanishing polynomial based on the operation
        if is_add {
            // For ADD: (a + b + c) - result - carry * modulus = 0
            for i in 0..P::NB_LIMBS {
                p_vanishing_limbs[i] += (p_a[i] as u16 + p_b[i] as u16 + p_c[i] as u16) as i32;
            }
        } else {
            // For MUL: (a * b + c) - result - carry * modulus = 0
            for i in 0..P::NB_LIMBS {
                for j in 0..P::NB_LIMBS {
                    p_vanishing_limbs[i + j] += (p_a[i] as u16 * p_b[j] as u16) as i32;
                }
            }
            for i in 0..P::NB_LIMBS {
                p_vanishing_limbs[i] += (p_c[i] as u16) as i32;
            }
        }

        // Subtract result and carry * modulus
        for i in 0..P::NB_LIMBS {
            p_vanishing_limbs[i] -= (p_result[i] as u16) as i32;
        }
        for i in 0..P::NB_LIMBS {
            for j in 0..P::MODULUS_LIMBS {
                p_vanishing_limbs[i + j] -= (p_carry[i] as u16 * p_modulus[j] as u16) as i32;
            }
        }

        let len = P::NB_WITNESS_LIMBS + 1;
        let mut pol_carry = p_vanishing_limbs[len - 1];
        for i in (0..len - 1).rev() {
            let ai = p_vanishing_limbs[i];
            p_vanishing_limbs[i] = pol_carry;
            pol_carry = ai + pol_carry * 256;
        }
        debug_assert_eq!(pol_carry, 0);

        for i in 0..P::NB_LIMBS {
            self.result[i] = F::from_canonical_u8(p_result[i]);
            self.carry[i] = F::from_canonical_u8(p_carry[i]);
        }
        for i in 0..P::NB_WITNESS_LIMBS {
            self.witness[i] =
                F::from_canonical_u16((p_vanishing_limbs[i] + P::WITNESS_OFFSET as i32) as u16);
        }

        record.add_u8_range_checks_field(&self.result.0);
        record.add_u8_range_checks_field(&self.carry.0);
        record.add_u16_range_checks_field(&self.witness.0);

        (result, carry)
    }

    pub fn populate_carry_and_witness(
        &mut self,
        a: &BigUint,
        b: &BigUint,
        op: FieldOperation,
        modulus: &BigUint,
    ) -> BigUint {
        let mut p_a: Vec<u8> = a.to_bytes_le();
        p_a.resize(P::NB_LIMBS, 0);
        let mut p_b: Vec<u8> = b.to_bytes_le();
        p_b.resize(P::NB_LIMBS, 0);
        let (result, carry) = match op {
            FieldOperation::Add => ((a + b) % modulus, (a + b - (a + b) % modulus) / modulus),
            FieldOperation::Mul => ((a * b) % modulus, (a * b - (a * b) % modulus) / modulus),
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        };
        debug_assert!(&result < modulus);
        debug_assert!(&carry < modulus);
        match op {
            FieldOperation::Add => debug_assert_eq!(&carry * modulus, a + b - &result),
            FieldOperation::Mul => debug_assert_eq!(&carry * modulus, a * b - &result),
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        }

        // Here we have special logic for p_modulus because to_limbs_field only works for numbers in
        // the field, but modulus can == the field modulus so it can have 1 extra limb (uint256).
        let mut p_modulus: Vec<u8> = modulus.to_bytes_le();
        p_modulus.resize(P::MODULUS_LIMBS, 0);
        let mut p_result: Vec<u8> = result.to_bytes_le();
        p_result.resize(P::NB_LIMBS, 0);
        let mut p_carry: Vec<u8> = carry.to_bytes_le();
        p_carry.resize(P::NB_LIMBS, 0);

        let mut p_vanishing = vec![0i32; P::NB_WITNESS_LIMBS + 1];
        match op {
            FieldOperation::Add => {
                for i in 0..P::NB_LIMBS {
                    p_vanishing[i] += (p_a[i] as u16 + p_b[i] as u16) as i32;
                }
            }
            FieldOperation::Mul => {
                for i in 0..P::NB_LIMBS {
                    for j in 0..P::NB_LIMBS {
                        p_vanishing[i + j] += (p_a[i] as u16 * p_b[j] as u16) as i32;
                    }
                }
            }
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        }

        for i in 0..P::NB_LIMBS {
            p_vanishing[i] -= p_result[i] as i32;
            for j in 0..P::MODULUS_LIMBS {
                p_vanishing[i + j] -= (p_carry[i] as u16 * p_modulus[j] as u16) as i32;
            }
        }

        let len = P::NB_WITNESS_LIMBS + 1;
        let mut carry = p_vanishing[len - 1];
        for i in (0..len - 1).rev() {
            let ai = p_vanishing[i];
            p_vanishing[i] = carry;
            carry = ai + carry * 256;
        }
        debug_assert_eq!(carry, 0);

        for i in 0..P::NB_LIMBS {
            self.result[i] = F::from_canonical_u8(p_result[i]);
            self.carry[i] = F::from_canonical_u8(p_carry[i]);
        }
        for i in 0..P::NB_WITNESS_LIMBS {
            self.witness[i] =
                F::from_canonical_u16((p_vanishing[i] + P::WITNESS_OFFSET as i32) as u16);
        }

        result
    }

    /// Populate these columns with a specified modulus. This is useful in the `mulmod` precompile
    /// as an example.
    #[allow(clippy::too_many_arguments)]
    pub fn populate_with_modulus(
        &mut self,
        record: &mut impl ByteRecord,
        a: &BigUint,
        b: &BigUint,
        modulus: &BigUint,
        op: FieldOperation,
    ) -> BigUint {
        if op == FieldOperation::Div {
            assert_ne!(*b, BigUint::zero(), "division by zero is not allowed");
            assert_ne!(*b, *modulus, "division by zero is not allowed");
        }

        let result = match op {
            // If doing the subtraction operation, a - b = result, equivalent to a = result + b.
            FieldOperation::Sub => {
                let result = (modulus.clone() + a - b) % modulus;
                // We populate the carry, witness_low, witness_high as if we were doing an addition
                // with result + b. But we populate `result` with the actual result
                // of the subtraction because those columns are expected to contain
                // the result by the user. Note that this reversal means we have to
                // flip result, a correspondingly in the `eval` function.
                self.populate_carry_and_witness(&result, b, FieldOperation::Add, modulus);
                self.result = P::to_limbs_field::<F, _>(&result);
                result
            }
            // a / b = result is equivalent to a = result * b.
            FieldOperation::Div => {
                // As modulus is prime, we can use Fermat's little theorem to compute the
                // inverse.
                cfg_if::cfg_if! {
                    if #[cfg(feature = "bigint-rug")] {
                        use sp1_curves::utils::{biguint_to_rug, rug_to_biguint};
                        let rug_a = biguint_to_rug(a);
                        let rug_b = biguint_to_rug(b);
                        let rug_modulus = biguint_to_rug(modulus);
                        let rug_result = (rug_a
                            * rug_b.pow_mod(&(rug_modulus.clone() - 2u32), &rug_modulus.clone()).unwrap())
                            % rug_modulus.clone();
                        let result = rug_to_biguint(&rug_result);
                    } else {
                        let result =
                            (a * b.modpow(&(modulus.clone() - 2u32), &modulus.clone())) % modulus.clone();
                    }
                }
                // We populate the carry, witness_low, witness_high as if we were doing a
                // multiplication with result * b. But we populate `result` with the
                // actual result of the multiplication because those columns are
                // expected to contain the result by the user. Note that this
                // reversal means we have to flip result, a correspondingly in the `eval`
                // function.
                self.populate_carry_and_witness(&result, b, FieldOperation::Mul, modulus);
                self.result = P::to_limbs_field::<F, _>(&result);
                result
            }
            _ => self.populate_carry_and_witness(a, b, op, modulus),
        };

        // Range checks
        record.add_u8_range_checks_field(&self.result.0);
        record.add_u8_range_checks_field(&self.carry.0);
        record.add_u16_range_checks_field(&self.witness.0);

        result
    }

    /// Populate these columns without a specified modulus (will use the modulus of the field
    /// parameters).
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        a: &BigUint,
        b: &BigUint,
        op: FieldOperation,
    ) -> BigUint {
        self.populate_with_modulus(record, a, b, &P::modulus(), op)
    }
}

impl<V: Copy, P: FieldParameters> FieldOpCols<V, P> {
    /// Allows an evaluation over opetations specified by boolean flags.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_variable<AB: SP1AirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        a: &(impl Into<Polynomial<AB::Expr>> + Clone),
        b: &(impl Into<Polynomial<AB::Expr>> + Clone),
        modulus: &(impl Into<Polynomial<AB::Expr>> + Clone),
        is_add: impl Into<AB::Expr> + Clone,
        is_sub: impl Into<AB::Expr> + Clone,
        is_mul: impl Into<AB::Expr> + Clone,
        is_div: impl Into<AB::Expr> + Clone,
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        let p_a_param: Polynomial<AB::Expr> = (a).clone().into();
        let p_b: Polynomial<AB::Expr> = (b).clone().into();
        let p_res_param: Polynomial<AB::Expr> = self.result.into();

        let is_add: AB::Expr = is_add.into();
        let is_sub: AB::Expr = is_sub.into();
        let is_mul: AB::Expr = is_mul.into();
        let is_div: AB::Expr = is_div.into();

        let p_result = p_res_param.clone() * (is_add.clone() + is_mul.clone())
            + p_a_param.clone() * (is_sub.clone() + is_div.clone());

        let p_add = p_a_param.clone() + p_b.clone();
        let p_sub = p_res_param.clone() + p_b.clone();
        let p_mul = p_a_param.clone() * p_b.clone();
        let p_div = p_res_param * p_b.clone();
        let p_op = p_add * is_add + p_sub * is_sub + p_mul * is_mul + p_div * is_div;

        self.eval_with_polynomials(builder, p_op, modulus.clone(), p_result, is_real);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_add_mul_and_carry<AB: SP1AirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        is_add: impl Into<AB::Expr> + Clone,
        is_mul: impl Into<AB::Expr> + Clone,
        a: &(impl Into<Polynomial<AB::Expr>> + Clone),
        b: &(impl Into<Polynomial<AB::Expr>> + Clone),
        c: &(impl Into<Polynomial<AB::Expr>> + Clone),
        modulus: &(impl Into<Polynomial<AB::Expr>> + Clone),
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        let p_a: Polynomial<AB::Expr> = (a).clone().into();
        let p_b: Polynomial<AB::Expr> = (b).clone().into();
        let p_c: Polynomial<AB::Expr> = (c).clone().into();

        let is_add: AB::Expr = is_add.into();
        let is_mul: AB::Expr = is_mul.into();

        let p_result: Polynomial<_> = self.result.into();
        let p_op = (p_a.clone() + p_b.clone()) * is_add + (p_a * p_b) * is_mul + p_c;

        self.eval_with_polynomials(builder, p_op, modulus.clone(), p_result, is_real);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_mul_and_carry<AB: SP1AirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        a: &(impl Into<Polynomial<AB::Expr>> + Clone),
        b: &(impl Into<Polynomial<AB::Expr>> + Clone),
        c: &(impl Into<Polynomial<AB::Expr>> + Clone),
        modulus: &(impl Into<Polynomial<AB::Expr>> + Clone),
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        let p_a: Polynomial<AB::Expr> = (a).clone().into();
        let p_b: Polynomial<AB::Expr> = (b).clone().into();
        let p_c: Polynomial<AB::Expr> = (c).clone().into();

        let p_result: Polynomial<_> = self.result.into();
        let p_op = p_a * p_b + p_c;

        self.eval_with_polynomials(builder, p_op, modulus.clone(), p_result, is_real);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_with_modulus<AB: SP1AirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        a: &(impl Into<Polynomial<AB::Expr>> + Clone),
        b: &(impl Into<Polynomial<AB::Expr>> + Clone),
        modulus: &(impl Into<Polynomial<AB::Expr>> + Clone),
        op: FieldOperation,
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        let p_a_param: Polynomial<AB::Expr> = (a).clone().into();
        let p_b: Polynomial<AB::Expr> = (b).clone().into();

        let (p_a, p_result): (Polynomial<_>, Polynomial<_>) = match op {
            FieldOperation::Add | FieldOperation::Mul => (p_a_param, self.result.into()),
            FieldOperation::Sub | FieldOperation::Div => (self.result.into(), p_a_param),
        };
        let p_op: Polynomial<<AB as AirBuilder>::Expr> = match op {
            FieldOperation::Add | FieldOperation::Sub => p_a + p_b,
            FieldOperation::Mul | FieldOperation::Div => p_a * p_b,
        };
        self.eval_with_polynomials(builder, p_op, modulus.clone(), p_result, is_real);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_with_polynomials<AB: SP1AirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        op: impl Into<Polynomial<AB::Expr>>,
        modulus: impl Into<Polynomial<AB::Expr>>,
        result: impl Into<Polynomial<AB::Expr>>,
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        let p_op: Polynomial<AB::Expr> = op.into();
        let p_result: Polynomial<AB::Expr> = result.into();
        let p_modulus: Polynomial<AB::Expr> = modulus.into();
        let p_carry: Polynomial<<AB as AirBuilder>::Expr> = self.carry.into();
        let p_op_minus_result: Polynomial<AB::Expr> = p_op - &p_result;
        let p_vanishing = p_op_minus_result - &(&p_carry * &p_modulus);
        let p_witness = self.witness.0.iter().into();
        eval_field_operation::<AB, P>(builder, &p_vanishing, &p_witness);

        // Range checks for the result, carry, and witness columns.
        builder.slice_range_check_u8(&self.result.0, is_real.clone());
        builder.slice_range_check_u8(&self.carry.0, is_real.clone());
        builder.slice_range_check_u16(p_witness.coefficients(), is_real.clone());
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        a: &(impl Into<Polynomial<AB::Expr>> + Clone),
        b: &(impl Into<Polynomial<AB::Expr>> + Clone),
        op: FieldOperation,
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        let p_limbs = Polynomial::from_iter(P::modulus_field_iter::<AB::F>().map(AB::Expr::from));
        self.eval_with_modulus::<AB>(builder, a, b, &p_limbs, op, is_real);
    }
}

// #[cfg(test)]
// mod tests {
//     #![allow(clippy::print_stdout)]

//     use num::BigUint;
//     use slop_air::BaseAir;
//     use slop_algebra::{Field, PrimeField32};
//     use sp1_core_executor::{ExecutionRecord, Program};
//     use sp1_curves::params::FieldParameters;
//     use sp1_hypercube::{
//         air::{MachineAir, SP1AirBuilder, SP1_PROOF_NUM_PV_ELTS},
//         Chip, StarkMachine,
//     };

//     use super::{FieldOpCols, FieldOperation, Limbs};

//     use crate::utils::{pad_to_power_of_two, run_test_machine, setup_test_machine};
//     use core::borrow::{Borrow, BorrowMut};
//     use num::bigint::RandBigInt;
//     use slop_air::Air;
//     use sp1_primitives::SP1Field;
//     use slop_algebra::AbstractField;
//     use slop_matrix::{dense::RowMajorMatrix, Matrix};
//     use rand::thread_rng;
//     use sp1_core_executor::events::ByteRecord;
//     use sp1_curves::{
//         edwards::ed25519::Ed25519BaseField, weierstrass::secp256k1::Secp256k1BaseField,
//     };
//     use sp1_derive::AlignedBorrow;
//     use sp1_hypercube::koala_bear_poseidon2::SP1CoreJaggedConfig;
//     use std::mem::size_of;

//     #[derive(AlignedBorrow, Debug, Clone)]
//     pub struct TestCols<T, P: FieldParameters> {
//         pub a: Limbs<T, P::Limbs>,
//         pub b: Limbs<T, P::Limbs>,
//         pub a_op_b: FieldOpCols<T, P>,
//     }

//     pub const NUM_TEST_COLS: usize = size_of::<TestCols<u8, Secp256k1BaseField>>();

//     struct FieldOpChip<P: FieldParameters> {
//         pub operation: FieldOperation,
//         pub _phantom: std::marker::PhantomData<P>,
//     }

//     impl<P: FieldParameters> FieldOpChip<P> {
//         pub const fn new(operation: FieldOperation) -> Self {
//             Self { operation, _phantom: std::marker::PhantomData }
//         }
//     }

//     impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for FieldOpChip<P> {
//         type Record = ExecutionRecord;

//         type Program = Program;

//         fn name(&self) -> String {
//             format!("FieldOp{:?}", self.operation)
//         }

//         fn generate_trace(
//             &self,
//             _: &ExecutionRecord,
//             output: &mut ExecutionRecord,
//         ) -> RowMajorMatrix<F> {
//             let mut rng = thread_rng();
//             let num_rows = 1 << 8;
//             let mut operands: Vec<(BigUint, BigUint)> = (0..num_rows - 4)
//                 .map(|_| {
//                     let a = rng.gen_biguint(256) % &P::modulus();
//                     let b = rng.gen_biguint(256) % &P::modulus();
//                     (a, b)
//                 })
//                 .collect();

//             // Hardcoded edge cases.
//             operands.extend(vec![
//                 (BigUint::from(0u32), BigUint::from(1u32)),
//                 (BigUint::from(1u32), BigUint::from(2u32)),
//                 (BigUint::from(4u32), BigUint::from(5u32)),
//                 (BigUint::from(10u32), BigUint::from(19u32)),
//             ]);

//             let rows = operands
//                 .iter()
//                 .map(|(a, b)| {
//                     let mut blu_events = Vec::new();
//                     let mut row = [F::zero(); NUM_TEST_COLS];
//                     let cols: &mut TestCols<F, P> = row.as_mut_slice().borrow_mut();
//                     cols.a = P::to_limbs_field::<F, _>(a);
//                     cols.b = P::to_limbs_field::<F, _>(b);
//                     cols.a_op_b.populate(&mut blu_events, a, b, self.operation);
//                     output.add_byte_lookup_events(blu_events);
//                     row
//                 })
//                 .collect::<Vec<_>>();
//             // Convert the trace to a row major matrix.
//             let mut trace =
//                 RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(),
// NUM_TEST_COLS);

//             // Pad the trace to a power of two.
//             pad_to_power_of_two::<NUM_TEST_COLS, F>(&mut trace.values);

//             trace
//         }

//         fn included(&self, _: &Self::Record) -> bool {
//             true
//         }
//     }

//     impl<F: Field, P: FieldParameters> BaseAir<F> for FieldOpChip<P> {
//         fn width(&self) -> usize {
//             NUM_TEST_COLS
//         }
//     }

//     impl<AB, P: FieldParameters> Air<AB> for FieldOpChip<P>
//     where
//         AB: SP1AirBuilder,
//         Limbs<AB::Var, P::Limbs>: Copy,
//     {
//         fn eval(&self, builder: &mut AB) {
//             let main = builder.main();
//             let local = main.row_slice(0);
//             let local: &TestCols<AB::Var, P> = (*local).borrow();
//             local.a_op_b.eval(builder, &local.a, &local.b, self.operation, AB::F::one());
//         }
//     }

//     #[test]
//     fn generate_trace() {
//         for op in [FieldOperation::Add, FieldOperation::Mul, FieldOperation::Sub].iter() {
//             println!("op: {op:?}");
//             let chip: FieldOpChip<Ed25519BaseField> = FieldOpChip::new(*op);
//             let shard = ExecutionRecord::default();
//             let _: RowMajorMatrix<SP1Field> =
//                 chip.generate_trace(&shard, &mut ExecutionRecord::default());
//             // println!("{:?}", trace.values)
//         }
//     }

//     #[test]
//     fn prove_koalabear() {
//         for op in
//             [FieldOperation::Add, FieldOperation::Sub, FieldOperation::Mul, FieldOperation::Div]
//                 .iter()
//         {
//             println!("op: {op:?}");

//             let air: FieldOpChip<Ed25519BaseField> = FieldOpChip::new(*op);
//             let shard = ExecutionRecord::default();
//             <FieldOpChip<Ed25519BaseField> as MachineAir<SP1Field>>::generate_trace(
//                 &air,
//                 &shard,
//                 &mut ExecutionRecord::default(),
//             );

//             // Run setup.
//             let config = SP1CoreJaggedConfig::new();
//             let chip: Chip<SP1Field, FieldOpChip<Ed25519BaseField>> = Chip::new(air);
//             let (pk, vk) = setup_test_machine(StarkMachine::new(
//                 config.clone(),
//                 vec![chip],
//                 SP1_PROOF_NUM_PV_ELTS,
//                 true,
//             ));

//             // Run the test.
//             let air: FieldOpChip<Ed25519BaseField> = FieldOpChip::new(*op);
//             let chip: Chip<SP1Field, FieldOpChip<Ed25519BaseField>> = Chip::new(air);
//             let machine =
//                 StarkMachine::new(config.clone(), vec![chip], SP1_PROOF_NUM_PV_ELTS, true);
//             run_test_machine::<SP1CoreJaggedConfig, FieldOpChip<Ed25519BaseField>>(
//                 vec![shard],
//                 machine,
//                 pk,
//                 vk,
//             )
//             .unwrap();
//         }
//     }
// }
