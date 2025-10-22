use rayon::prelude::*;

use slop_algebra::{
    interpolate_univariate_polynomial, AbstractExtensionField, AbstractField, ExtensionField,
    Field, UnivariatePolynomial,
};
use slop_alloc::{Backend, CpuBackend, HasBackend};
use slop_multilinear::MleBaseBackend;
use slop_sumcheck::{
    ComponentPolyEvalBackend, SumCheckPolyFirstRoundBackend, SumcheckPolyBackend, SumcheckPolyBase,
    SumcheckPolyFirstRound,
};
use tokio::sync::oneshot;

use crate::LongMle;

#[derive(Clone, Debug)]
pub struct HadamardProduct<F, EF = F, A: Backend = CpuBackend> {
    pub base: LongMle<F, A>,
    pub ext: LongMle<EF, A>,
}

impl<F, EF, A> HasBackend for HadamardProduct<F, EF, A>
where
    A: Backend,
    F: AbstractField,
    EF: AbstractExtensionField<F>,
{
    type Backend = A;
    #[inline]
    fn backend(&self) -> &Self::Backend {
        self.base.backend()
    }
}

impl<F, EF, A> SumcheckPolyBase for HadamardProduct<F, EF, A>
where
    F: AbstractField,
    EF: AbstractExtensionField<F>,
    A: MleBaseBackend<F> + MleBaseBackend<EF>,
{
    #[inline]
    fn num_variables(&self) -> u32 {
        self.base.num_variables()
    }
}

impl<F, EF> ComponentPolyEvalBackend<HadamardProduct<F, EF, CpuBackend>, EF> for CpuBackend
where
    F: AbstractField,
    EF: AbstractExtensionField<F>,
{
    async fn get_component_poly_evals(poly: &HadamardProduct<F, EF, CpuBackend>) -> Vec<EF> {
        assert_eq!(poly.base.num_components(), 1);
        let base_eval: EF = (*poly.base.first_component_mle().guts()[[0, 0]]).clone().into();
        let ext_eval: EF = (*poly.ext.first_component_mle().guts()[[0, 0]]).clone();
        vec![base_eval, ext_eval]
    }
}

impl<F> SumcheckPolyBackend<HadamardProduct<F, F, CpuBackend>, F> for CpuBackend
where
    F: Field,
{
    async fn fix_last_variable(
        poly: HadamardProduct<F, F, CpuBackend>,
        alpha: F,
    ) -> HadamardProduct<F, F, CpuBackend> {
        let base = poly.base.fix_last_variable(alpha).await;
        let ext = poly.ext.fix_last_variable(alpha).await;
        HadamardProduct { base, ext }
    }

    #[inline]
    async fn sum_as_poly_in_last_variable(
        poly: &HadamardProduct<F, F, CpuBackend>,
        claim: Option<F>,
    ) -> UnivariatePolynomial<F> {
        poly.sum_as_poly_in_last_t_variables(claim, 1).await
    }
}

impl<F, EF> SumCheckPolyFirstRoundBackend<HadamardProduct<F, EF, CpuBackend>, EF> for CpuBackend
where
    F: Field,
    EF: ExtensionField<F>,
{
    type NextRoundPoly = HadamardProduct<EF, EF, CpuBackend>;
    async fn fix_t_variables(
        poly: HadamardProduct<F, EF, CpuBackend>,
        alpha: EF,
        t: usize,
    ) -> HadamardProduct<EF, EF, CpuBackend> {
        assert_eq!(t, 1);
        let base = poly.base.fix_last_variable(alpha).await;
        let ext = poly.ext.fix_last_variable(alpha).await;
        HadamardProduct { base, ext }
    }

    async fn sum_as_poly_in_last_t_variables(
        poly: &HadamardProduct<F, EF, CpuBackend>,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        assert_eq!(t, 1);
        assert_eq!(poly.base.num_components(), 1);
        assert_eq!(poly.ext.num_components(), 1);

        let poly_base = poly.base.first_component_mle().clone();
        let poly_ext = poly.ext.first_component_mle().clone();
        let (tx, rx) = oneshot::channel();
        slop_futures::rayon::spawn(move || {
            // The sumcheck polynomial is a multi-quadratic polynomial, so three evaluations are
            // needed.
            let eval_0 = poly_ext
                .guts()
                .as_slice()
                .par_iter()
                .step_by(2)
                .zip(poly_base.guts().as_slice().par_iter().step_by(2))
                .map(|(x, y)| *x * *y)
                .sum();

            let eval_1 = claim.map(|x| x - eval_0).unwrap_or(
                poly_ext
                    .guts()
                    .as_slice()
                    .par_iter()
                    .skip(1)
                    .step_by(2)
                    .zip(poly_base.guts().as_slice().par_iter().skip(1).step_by(2))
                    .map(|(x, y)| *x * *y)
                    .sum(),
            );

            let eval_half: EF = poly_ext
                .guts()
                .as_slice()
                .par_iter()
                .step_by(2)
                .zip(poly_ext.guts().as_slice().par_iter().skip(1).step_by(2))
                .zip(poly_base.guts().as_slice().par_iter().step_by(2))
                .zip(poly_base.guts().as_slice().par_iter().skip(1).step_by(2))
                .map(|(((je_0, je_1), mle_0), mle_1)| (*je_0 + *je_1) * (*mle_0 + *mle_1))
                .sum();

            let univariate_poly = interpolate_univariate_polynomial(
                &[
                    EF::from_canonical_u16(0),
                    EF::from_canonical_u16(1),
                    EF::from_canonical_u16(2).inverse(),
                ],
                &[eval_0, eval_1, eval_half * EF::from_canonical_u16(4).inverse()],
            );
            tx.send(univariate_poly).unwrap();
        });
        rx.await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
    use slop_challenger::{CanSample, IopCtx};
    use slop_multilinear::Mle;
    use slop_sumcheck::{partially_verify_sumcheck_proof, reduce_sumcheck_to_evaluation};

    use super::*;

    #[tokio::test]
    async fn test_hadamard_product_sumcheck() {
        let mut rng = thread_rng();

        type F = BabyBear;
        type EF = BinomialExtensionField<BabyBear, 4>;

        let num_variables = 14;

        let base = Mle::<F>::rand(&mut rng, 1, num_variables);
        let ext = Mle::<EF>::rand(&mut rng, 1, num_variables);

        let base = LongMle::from_components(vec![base], num_variables);
        let ext = LongMle::from_components(vec![ext], num_variables);

        let product = HadamardProduct { base, ext };

        let mut challenger = BabyBearDegree4Duplex::default_challenger();

        let claim: EF = product
            .ext
            .first_component_mle()
            .guts()
            .as_slice()
            .iter()
            .zip(product.base.first_component_mle().guts().as_slice().iter())
            .map(|(x, y)| EF::from(*x) * EF::from(*y))
            .sum();

        let lambda: EF = challenger.sample();

        let (proof, mut eval_claims) = reduce_sumcheck_to_evaluation::<F, EF, _>(
            vec![product.clone()],
            &mut challenger,
            vec![claim],
            1,
            lambda,
        )
        .await;

        let point = &proof.point_and_eval.0;
        let [exp_eval_base, exp_eval_ext] = eval_claims.pop().unwrap().try_into().unwrap();

        let eval_ext =
            product.ext.first_component_mle().eval_at(point).await.to_vec().pop().unwrap();
        let eval_base =
            product.base.first_component_mle().eval_at(point).await.to_vec().pop().unwrap();

        assert_eq!(eval_ext, exp_eval_ext);
        assert_eq!(eval_base, exp_eval_base);

        // Check that the final claimed evaluation is the product of the two evaluations
        let claimed_eval = proof.point_and_eval.1;
        assert_eq!(claimed_eval, exp_eval_ext * exp_eval_base);

        let mut challenger = BabyBearDegree4Duplex::default_challenger();
        let _lambda: EF = challenger.sample();
        assert!(partially_verify_sumcheck_proof::<F, EF, _>(
            &proof,
            &mut challenger,
            num_variables as usize,
            2
        )
        .is_ok());
        assert_eq!(proof.univariate_polys.len(), num_variables as usize);
    }
}
