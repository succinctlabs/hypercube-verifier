pub mod witness;

use crate::{
    challenger::{CanObserveVariable, FieldChallengerVariable},
    symbolic::IntoSymbolic,
    BabyBearFriConfigVariable, CircuitConfig,
};
use hypercube_recursion_compiler::{
    ir::Felt,
    prelude::{Builder, Ext, SymbolicExt},
};
use p3_baby_bear::BabyBear;
use p3_field::{extension::BinomialExtensionField, AbstractField};
use slop_algebra::UnivariatePolynomial;
use slop_alloc::{buffer, Buffer};
use slop_multilinear::{partial_lagrange_blocking, Mle, MleEval, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::{Dimensions, Tensor};

pub fn evaluate_mle_ext<
    C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
>(
    builder: &mut Builder<C>,
    mle: Mle<Ext<C::F, C::EF>>,
    point: Point<Ext<C::F, C::EF>>,
) -> MleEval<Ext<C::F, C::EF>> {
    let point_symbolic = <Point<Ext<C::F, C::EF>> as IntoSymbolic<C>>::as_symbolic(&point);
    let partial_lagrange = partial_lagrange_blocking(&point_symbolic);
    let mle = mle.guts();
    let mut sizes = mle.sizes().to_vec();
    sizes.remove(0);
    let dimensions = Dimensions::try_from(sizes).unwrap();
    let mut dst = Tensor { storage: buffer![], dimensions };
    let total_len = dst.total_len();
    let dot_products = mle
        .as_buffer()
        .chunks_exact(mle.strides()[0])
        .zip(partial_lagrange.as_buffer().iter())
        .map(|(chunk, scalar)| chunk.iter().map(|a| *scalar * *a).collect())
        .fold(
            vec![SymbolicExt::<C::F, C::EF>::zero(); total_len],
            |mut a, b: Vec<SymbolicExt<_, _>>| {
                a.iter_mut().zip(b.iter()).for_each(|(a, b)| *a += *b);
                a
            },
        );
    let dot_products = dot_products.into_iter().map(|x| builder.eval(x)).collect::<Buffer<_>>();
    dst.storage = dot_products;
    MleEval::new(dst)
}

pub fn verify_sumcheck<C: CircuitConfig<F = BabyBear>, SC: BabyBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    challenger: &mut SC::FriChallengerVariable,
    proof: &PartialSumcheckProof<Ext<C::F, C::EF>>,
) {
    let num_variables = proof.univariate_polys.len();
    let mut alpha_point: Point<SymbolicExt<C::F, C::EF>> = Point::default();

    assert_eq!(num_variables, proof.point_and_eval.0.dimension());

    let first_poly = proof.univariate_polys[0].clone();
    let first_poly_symbolic: UnivariatePolynomial<SymbolicExt<C::F, C::EF>> =
        UnivariatePolynomial {
            coefficients: first_poly
                .coefficients
                .clone()
                .into_iter()
                .map(|c| c.into())
                .collect::<Vec<_>>(),
        };
    builder.assert_ext_eq(first_poly_symbolic.eval_one_plus_eval_zero(), proof.claimed_sum);

    let coeffs: Vec<Felt<C::F>> =
        first_poly.coefficients.iter().flat_map(|x| C::ext2felt(builder, *x)).collect::<Vec<_>>();

    challenger.observe_slice(builder, coeffs);

    let mut previous_poly = first_poly_symbolic;
    for poly in proof.univariate_polys.iter().skip(1) {
        let alpha = challenger.sample_ext(builder);
        alpha_point.add_dimension(alpha.into());
        let poly_symbolic: UnivariatePolynomial<SymbolicExt<C::F, C::EF>> = UnivariatePolynomial {
            coefficients: poly
                .coefficients
                .clone()
                .into_iter()
                .map(|c| c.into())
                .collect::<Vec<_>>(),
        };
        let expected_eval = previous_poly.eval_at_point(alpha.into());
        builder.assert_ext_eq(expected_eval, poly_symbolic.eval_one_plus_eval_zero());

        let coeffs: Vec<Felt<C::F>> =
            poly.coefficients.iter().flat_map(|x| C::ext2felt(builder, *x)).collect::<Vec<_>>();
        challenger.observe_slice(builder, coeffs);
        previous_poly = poly_symbolic;
    }

    let alpha = challenger.sample_ext(builder);
    alpha_point.add_dimension(alpha.into());

    alpha_point.iter().zip(proof.point_and_eval.0.iter()).for_each(|(d, p)| {
        builder.assert_ext_eq(*d, *p);
    });

    builder.assert_ext_eq(previous_poly.eval_at_point(alpha.into()), proof.point_and_eval.1);
}
