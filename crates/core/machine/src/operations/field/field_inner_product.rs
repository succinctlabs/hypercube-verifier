use std::fmt::Debug;

use super::util_air::eval_field_operation;
use crate::air::WordAirBuilder;
use itertools::Itertools;
use num::{BigUint, Zero};
use slop_air::AirBuilder;
use slop_algebra::{AbstractField, PrimeField32};
use sp1_core_executor::events::ByteRecord;
use sp1_curves::params::{FieldParameters, Limbs};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::polynomial::Polynomial;

/// A set of columns to compute `InnerProduct([a], [b])` where a, b are emulated elements.
///
/// *Safety*: The `FieldInnerProductCols` asserts that `result = sum_i a_i * b_i mod M` where
/// `M` is the modulus `P::modulus()` under the assumption that the length of `a` and `b` is small
/// enough so that the vanishing polynomial has limbs bounded by the witness shift. It is the
/// responsibility of the caller to ensure that the length of `a` and `b` is small enough.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldInnerProductCols<T, P: FieldParameters> {
    /// The result of `a inner product b`, where a, b are field elements
    pub result: Limbs<T, P::Limbs>,
    pub(crate) carry: Limbs<T, P::Limbs>,
    pub(crate) witness: Limbs<T, P::Witness>,
}

impl<F: PrimeField32, P: FieldParameters> FieldInnerProductCols<F, P> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        a: &[BigUint],
        b: &[BigUint],
    ) -> BigUint {
        let modulus = &P::modulus();
        let inner_product = a.iter().zip(b.iter()).fold(BigUint::zero(), |acc, (c, d)| acc + c * d);

        let result = &(&inner_product % modulus);
        let carry = &((&inner_product - result) / modulus);
        debug_assert!(result < modulus);
        debug_assert!(carry < &(2u32 * modulus));
        debug_assert_eq!(carry * modulus, inner_product - result);

        let p_a_vec: Vec<Vec<u8>> = a
            .iter()
            .map(|x| {
                let mut bytes = x.to_bytes_le();
                bytes.resize(P::NB_LIMBS, 0);
                bytes
            })
            .collect();
        let p_b_vec: Vec<Vec<u8>> = b
            .iter()
            .map(|x| {
                let mut bytes = x.to_bytes_le();
                bytes.resize(P::NB_LIMBS, 0);
                bytes
            })
            .collect();

        let mut p_modulus: Vec<u8> = modulus.to_bytes_le();
        p_modulus.resize(P::MODULUS_LIMBS, 0);
        let mut p_result: Vec<u8> = result.to_bytes_le();
        p_result.resize(P::NB_LIMBS, 0);
        let mut p_carry: Vec<u8> = carry.to_bytes_le();
        p_carry.resize(P::NB_LIMBS, 0);

        let mut p_vanishing_limbs = vec![0i32; P::NB_WITNESS_LIMBS + 1];
        for (p_a, p_b) in p_a_vec.into_iter().zip_eq(p_b_vec) {
            for i in 0..P::NB_LIMBS {
                for j in 0..P::NB_LIMBS {
                    p_vanishing_limbs[i + j] += (p_a[i] as u16 * p_b[j] as u16) as i32;
                }
            }
        }
        for i in 0..P::NB_LIMBS {
            p_vanishing_limbs[i] -= p_result[i] as i32;
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

        // Range checks
        record.add_u8_range_checks_field(&self.result.0);
        record.add_u8_range_checks_field(&self.carry.0);
        record.add_u16_range_checks_field(&self.witness.0);

        result.clone()
    }
}

impl<V: Copy, P: FieldParameters> FieldInnerProductCols<V, P>
where
    Limbs<V, P::Limbs>: Copy,
{
    pub fn eval<AB: SP1AirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        a: &[impl Into<Polynomial<AB::Expr>> + Clone],
        b: &[impl Into<Polynomial<AB::Expr>> + Clone],
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
    {
        let p_a_vec: Vec<Polynomial<AB::Expr>> = a.iter().cloned().map(|x| x.into()).collect();
        let p_b_vec: Vec<Polynomial<AB::Expr>> = b.iter().cloned().map(|x| x.into()).collect();
        let p_result: Polynomial<<AB as AirBuilder>::Expr> = self.result.into();
        let p_carry: Polynomial<<AB as AirBuilder>::Expr> = self.carry.into();

        let p_zero = Polynomial::<AB::Expr>::new(vec![AB::Expr::zero()]);

        let p_inner_product = p_a_vec
            .iter()
            .zip(p_b_vec.iter())
            .map(|(p_a, p_b)| p_a * p_b)
            .collect::<Vec<_>>()
            .iter()
            .fold(p_zero, |acc, x| acc + x);

        let p_inner_product_minus_result = &p_inner_product - &p_result;
        let p_limbs = Polynomial::from_iter(P::modulus_field_iter::<AB::F>().map(AB::Expr::from));
        let p_vanishing = &p_inner_product_minus_result - &(&p_carry * &p_limbs);

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
//         Chip, StarkMachine,
//     };

//     use super::{FieldInnerProductCols, Limbs};

//     use crate::utils::{pad_to_power_of_two, run_test_machine, setup_test_machine};
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
//     use sp1_hypercube::koala_bear_poseidon2::SP1CoreJaggedConfig;

//     #[derive(AlignedBorrow, Debug, Clone)]
//     pub struct TestCols<T, P: FieldParameters> {
//         pub a: [Limbs<T, P::Limbs>; 1],
//         pub b: [Limbs<T, P::Limbs>; 1],
//         pub a_ip_b: FieldInnerProductCols<T, P>,
//     }

//     pub const NUM_TEST_COLS: usize = size_of::<TestCols<u8, Ed25519BaseField>>();

//     struct FieldIpChip<P: FieldParameters> {
//         pub _phantom: std::marker::PhantomData<P>,
//     }

//     impl<P: FieldParameters> FieldIpChip<P> {
//         pub const fn new() -> Self {
//             Self { _phantom: std::marker::PhantomData }
//         }
//     }

//     impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for FieldIpChip<P> {
//         type Record = ExecutionRecord;

//         type Program = Program;

//         fn name(&self) -> String {
//             "FieldInnerProduct".to_string()
//         }

//         fn generate_trace(
//             &self,
//             _: &ExecutionRecord,
//             output: &mut ExecutionRecord,
//         ) -> RowMajorMatrix<F> {
//             let mut rng = thread_rng();
//             let num_rows = 1 << 8;
//             let mut operands: Vec<(Vec<BigUint>, Vec<BigUint>)> = (0..num_rows - 4)
//                 .map(|_| {
//                     let a = rng.gen_biguint(256) % &P::modulus();
//                     let b = rng.gen_biguint(256) % &P::modulus();
//                     (vec![a], vec![b])
//                 })
//                 .collect();

//             operands.extend(vec![
//                 (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
//                 (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
//                 (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
//                 (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
//             ]);
//             let rows = operands
//                 .iter()
//                 .map(|(a, b)| {
//                     let mut row = [F::zero(); NUM_TEST_COLS];
//                     let cols: &mut TestCols<F, P> = row.as_mut_slice().borrow_mut();
//                     cols.a[0] = P::to_limbs_field::<F, _>(&a[0]);
//                     cols.b[0] = P::to_limbs_field::<F, _>(&b[0]);
//                     cols.a_ip_b.populate(output, a, b);
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

//     impl<F: Field, P: FieldParameters> BaseAir<F> for FieldIpChip<P> {
//         fn width(&self) -> usize {
//             NUM_TEST_COLS
//         }
//     }

//     impl<AB, P: FieldParameters> Air<AB> for FieldIpChip<P>
//     where
//         AB: SP1AirBuilder,
//         Limbs<AB::Var, P::Limbs>: Copy,
//     {
//         fn eval(&self, builder: &mut AB) {
//             let main = builder.main();
//             let local = main.row_slice(0);
//             let local: &TestCols<AB::Var, P> = (*local).borrow();
//             local.a_ip_b.eval(builder, &local.a, &local.b, AB::F::one());
//         }
//     }

//     #[test]
//     fn generate_trace() {
//         let shard = ExecutionRecord::default();
//         let chip: FieldIpChip<Ed25519BaseField> = FieldIpChip::new();
//         let trace: RowMajorMatrix<SP1Field> =
//             chip.generate_trace(&shard, &mut ExecutionRecord::default());
//         println!("{:?}", trace.values)
//     }

//     #[test]
//     fn prove_koalabear() {
//         let shard = ExecutionRecord::default();

//         let air: FieldIpChip<Ed25519BaseField> = FieldIpChip::new();
//         <FieldIpChip<Ed25519BaseField> as MachineAir<SP1Field>>::generate_trace(
//             &air,
//             &shard,
//             &mut ExecutionRecord::default(),
//         );

//         // Run setup.
//         let config = SP1CoreJaggedConfig::new();
//         let chip: Chip<SP1Field, FieldIpChip<Ed25519BaseField>> = Chip::new(air);
//         let (pk, vk) = setup_test_machine(StarkMachine::new(
//             config.clone(),
//             vec![chip],
//             SP1_PROOF_NUM_PV_ELTS,
//             true,
//         ));

//         // Run the test.
//         let air: FieldIpChip<Ed25519BaseField> = FieldIpChip::new();
//         let chip: Chip<SP1Field, FieldIpChip<Ed25519BaseField>> = Chip::new(air);
//         let machine = StarkMachine::new(config.clone(), vec![chip], SP1_PROOF_NUM_PV_ELTS, true);
//         run_test_machine::<SP1CoreJaggedConfig, FieldIpChip<Ed25519BaseField>>(
//             vec![shard],
//             machine,
//             pk,
//             vk,
//         )
//         .unwrap();
//     }
// }
