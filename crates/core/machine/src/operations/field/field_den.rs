use std::fmt::Debug;

use num::BigUint;
use slop_air::AirBuilder;
use slop_algebra::PrimeField32;
use sp1_core_executor::events::ByteRecord;
use sp1_curves::params::{FieldParameters, Limbs};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::polynomial::Polynomial;

use super::util_air::eval_field_operation;
use crate::air::WordAirBuilder;

/// A set of columns to compute `FieldDen(a, b)` where `a`, `b` are field elements.
///
/// `a / (1 + b)` if `sign`
/// `a / (1 - b) ` if `!sign`
///
/// *Safety*: the operation assumes that the denominators are never zero. It is the responsibility
/// of the caller to ensure that condition.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldDenCols<T, P: FieldParameters> {
    /// The result of `a den b`, where a, b are field elements
    pub result: Limbs<T, P::Limbs>,
    pub(crate) carry: Limbs<T, P::Limbs>,
    pub(crate) witness: Limbs<T, P::Witness>,
}

impl<F: PrimeField32, P: FieldParameters> FieldDenCols<F, P> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        a: &BigUint,
        b: &BigUint,
        sign: bool,
    ) -> BigUint {
        let p = P::modulus();
        let minus_b_int = &p - b;
        let b_signed = if sign { b.clone() } else { minus_b_int };
        let denominator = (b_signed + 1u32) % &(p.clone());
        let den_inv = denominator.modpow(&(&p - 2u32), &p);
        let result = (a * &den_inv) % &p;
        debug_assert_eq!(&den_inv * &denominator % &p, BigUint::from(1u32));
        debug_assert!(result < p);

        let equation_lhs = if sign { b * &result + &result } else { b * &result + a };
        let equation_rhs = if sign { a.clone() } else { result.clone() };
        let carry = (&equation_lhs - &equation_rhs) / &p;
        debug_assert!(carry < p);
        debug_assert_eq!(&carry * &p, &equation_lhs - &equation_rhs);

        let mut p_a: Vec<u8> = a.to_bytes_le();
        p_a.resize(P::NB_LIMBS, 0);
        let mut p_b: Vec<u8> = b.to_bytes_le();
        p_b.resize(P::NB_LIMBS, 0);
        let mut p_p: Vec<u8> = p.to_bytes_le();
        p_p.resize(P::MODULUS_LIMBS, 0);
        let mut p_result: Vec<u8> = result.to_bytes_le();
        p_result.resize(P::NB_LIMBS, 0);
        let mut p_carry: Vec<u8> = carry.to_bytes_le();
        p_carry.resize(P::NB_LIMBS, 0);

        let mut p_vanishing_limbs = vec![0; P::NB_WITNESS_LIMBS + 1];

        for i in 0..P::NB_LIMBS {
            for j in 0..P::NB_LIMBS {
                p_vanishing_limbs[i + j] += (p_b[i] as u16 * p_result[j] as u16) as i32;
            }
        }

        for i in 0..P::NB_LIMBS {
            for j in 0..P::MODULUS_LIMBS {
                p_vanishing_limbs[i + j] -= (p_carry[i] as u16 * p_p[j] as u16) as i32;
            }
        }

        if sign {
            for i in 0..P::NB_LIMBS {
                p_vanishing_limbs[i] += p_result[i] as i32;
                p_vanishing_limbs[i] -= p_a[i] as i32;
            }
        } else {
            for i in 0..P::NB_LIMBS {
                p_vanishing_limbs[i] -= p_result[i] as i32;
                p_vanishing_limbs[i] += p_a[i] as i32;
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

        // Range checks
        record.add_u8_range_checks_field(&self.result.0);
        record.add_u8_range_checks_field(&self.carry.0);
        record.add_u16_range_checks_field(&self.witness.0);

        result
    }
}

impl<V: Copy, P: FieldParameters> FieldDenCols<V, P>
where
    Limbs<V, P::Limbs>: Copy,
{
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        a: &Limbs<AB::Var, P::Limbs>,
        b: &Limbs<AB::Var, P::Limbs>,
        sign: bool,
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
    {
        let p_a: Polynomial<<AB as AirBuilder>::Expr> = (*a).into();
        let p_b: Polynomial<<AB as AirBuilder>::Expr> = (*b).into();
        let p_result: Polynomial<<AB as AirBuilder>::Expr> = self.result.into();
        let p_carry: Polynomial<<AB as AirBuilder>::Expr> = self.carry.into();

        // Compute the vanishing polynomial:
        //      lhs(x) = sign * (b(x) * result(x) + result(x)) + (1 - sign) * (b(x) * result(x) +
        // a(x))      rhs(x) = sign * a(x) + (1 - sign) * result(x)
        //      lhs(x) - rhs(x) - carry(x) * p(x)
        let p_equation_lhs =
            if sign { &p_b * &p_result + &p_result } else { &p_b * &p_result + &p_a };
        let p_equation_rhs = if sign { p_a } else { p_result };

        let p_lhs_minus_rhs = &p_equation_lhs - &p_equation_rhs;
        let p_limbs: Polynomial<<AB as AirBuilder>::Expr> =
            Polynomial::from_iter(P::modulus_field_iter::<AB::F>().map(AB::Expr::from));

        let p_vanishing: Polynomial<<AB as AirBuilder>::Expr> =
            p_lhs_minus_rhs - &p_carry * &p_limbs;

        let p_witness = self.witness.0.iter().into();

        eval_field_operation::<AB, P>(builder, &p_vanishing, &p_witness);

        // Range checks for the result, carry, and witness columns.
        builder.slice_range_check_u8(&self.result.0, is_real.clone());
        builder.slice_range_check_u8(&self.carry.0, is_real.clone());
        builder.slice_range_check_u16(&self.witness.0, is_real.clone());
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
//         koala_bear_poseidon2::SP1CoreJaggedConfig,
//         Chip, StarkMachine,
//     };

//     use crate::utils::{run_test_machine, setup_test_machine};

//     use super::{FieldDenCols, Limbs};

//     use core::{
//         borrow::{Borrow, BorrowMut},
//         mem::size_of,
//     };
//     use num::bigint::RandBigInt;
//     use slop_air::Air;
//     use sp1_primitives::SP1Field;
//     use slop_algebra::AbstractField;
//     use slop_matrix::{dense::RowMajorMatrix, Matrix};
//     use rand::thread_rng;
//     use sp1_curves::edwards::ed25519::Ed25519BaseField;
//     use sp1_derive::AlignedBorrow;

//     #[derive(Debug, Clone, AlignedBorrow)]
//     pub struct TestCols<T, P: FieldParameters> {
//         pub a: Limbs<T, P::Limbs>,
//         pub b: Limbs<T, P::Limbs>,
//         pub a_den_b: FieldDenCols<T, P>,
//     }

//     pub const NUM_TEST_COLS: usize = size_of::<TestCols<u8, Ed25519BaseField>>();

//     struct FieldDenChip<P: FieldParameters> {
//         pub sign: bool,
//         pub _phantom: std::marker::PhantomData<P>,
//     }

//     impl<P: FieldParameters> FieldDenChip<P> {
//         pub const fn new(sign: bool) -> Self {
//             Self { sign, _phantom: std::marker::PhantomData }
//         }
//     }

//     impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for FieldDenChip<P> {
//         type Record = ExecutionRecord;

//         type Program = Program;

//         fn name(&self) -> String {
//             "FieldDen".to_string()
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
//                 (BigUint::from(0u32), BigUint::from(0u32)),
//                 (BigUint::from(1u32), BigUint::from(2u32)),
//                 (BigUint::from(4u32), BigUint::from(5u32)),
//                 (BigUint::from(10u32), BigUint::from(19u32)),
//             ]);
//             // It is important that the number of rows is an exact power of 2,
//             // otherwise the padding will not work correctly.
//             assert_eq!(operands.len(), num_rows);

//             let rows = operands
//                 .iter()
//                 .map(|(a, b)| {
//                     let mut row = [F::zero(); NUM_TEST_COLS];
//                     let cols: &mut TestCols<F, P> = row.as_mut_slice().borrow_mut();
//                     cols.a = P::to_limbs_field::<F, _>(a);
//                     cols.b = P::to_limbs_field::<F, _>(b);
//                     cols.a_den_b.populate(output, a, b, self.sign);
//                     row
//                 })
//                 .collect::<Vec<_>>();
//             // Convert the trace to a row major matrix.

//             // Note we do not pad the trace here because we cannot just pad with all 0s.

//             RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_TEST_COLS)
//         }

//         fn included(&self, _: &Self::Record) -> bool {
//             true
//         }
//     }

//     impl<F: Field, P: FieldParameters> BaseAir<F> for FieldDenChip<P> {
//         fn width(&self) -> usize {
//             NUM_TEST_COLS
//         }
//     }

//     impl<AB, P: FieldParameters> Air<AB> for FieldDenChip<P>
//     where
//         AB: SP1AirBuilder,
//         Limbs<AB::Var, P::Limbs>: Copy,
//     {
//         fn eval(&self, builder: &mut AB) {
//             let main = builder.main();
//             let local = main.row_slice(0);
//             let local: &TestCols<AB::Var, P> = (*local).borrow();
//             local.a_den_b.eval(builder, &local.a, &local.b, self.sign, AB::F::zero());
//         }
//     }

//     #[test]
//     fn generate_trace() {
//         let shard = ExecutionRecord::default();
//         let chip: FieldDenChip<Ed25519BaseField> = FieldDenChip::new(true);
//         let trace: RowMajorMatrix<SP1Field> =
//             chip.generate_trace(&shard, &mut ExecutionRecord::default());
//         println!("{:?}", trace.values)
//     }

//     #[test]
//     fn prove_field() {
//         let shard = ExecutionRecord::default();

//         let air: FieldDenChip<Ed25519BaseField> = FieldDenChip::new(true);
//         <FieldDenChip<Ed25519BaseField> as MachineAir<SP1Field>>::generate_trace(
//             &air,
//             &shard,
//             &mut ExecutionRecord::default(),
//         );
//         // This it to test that the proof DOESN'T work if messed up.
//         // let row = trace.row_mut(0);
//         // row[0] = SP1Field::from_canonical_u8(0);

//         // Run setup.
//         let config = SP1CoreJaggedConfig::new();
//         let chip: Chip<SP1Field, FieldDenChip<Ed25519BaseField>> = Chip::new(air);
//         let (pk, vk) = setup_test_machine(StarkMachine::new(
//             config.clone(),
//             vec![chip],
//             SP1_PROOF_NUM_PV_ELTS,
//             true,
//         ));

//         // Run the test.
//         let air: FieldDenChip<Ed25519BaseField> = FieldDenChip::new(true);
//         let chip: Chip<SP1Field, FieldDenChip<Ed25519BaseField>> = Chip::new(air);
//         let machine = StarkMachine::new(config.clone(), vec![chip], SP1_PROOF_NUM_PV_ELTS, true);
//         run_test_machine::<SP1CoreJaggedConfig, FieldDenChip<Ed25519BaseField>>(
//             vec![shard],
//             machine,
//             pk,
//             vk,
//         )
//         .unwrap();
//     }
// }
