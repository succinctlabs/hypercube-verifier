use futures::future;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractField, ExtensionField, Field, UnivariatePolynomial,
};
use slop_alloc::{Backend, CpuBackend};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{ComponentPoly, SumcheckPoly, SumcheckPolyBase, SumcheckPolyFirstRound};

use crate::sparse_poly::SparsePolynomial;

// Represents the polynomials for PGSPCS sumcheck
pub struct SparsePCSSumcheckPoly<EF, B: Backend = CpuBackend> {
    // The point that the sumcheck is evaluating at
    pub eval_point: Point<EF, B>,

    // The MLE of the values of the polynomial
    // This is a MLE on log_sparsity variables
    pub val_mle: Mle<EF, B>,

    // The indexes, these are num_variables MLEs on log_sparsity variables
    pub index_mles: Vec<Mle<EF, B>>,
}

impl<EF> SparsePCSSumcheckPoly<EF>
where
    EF: Field,
{
    pub async fn new<F>(eval_point: &Point<EF>, sparse_polynomial: &SparsePolynomial<F>) -> Self
    where
        F: Field,
        EF: ExtensionField<F>,
    {
        Self {
            eval_point: eval_point.clone(),
            val_mle: sparse_polynomial.val_mle(),
            index_mles: sparse_polynomial.index_mles(),
        }
    }
}

impl<EF> SumcheckPolyBase for SparsePCSSumcheckPoly<EF>
where
    EF: AbstractField,
{
    fn num_variables(&self) -> u32 {
        self.val_mle.num_variables()
    }
}

impl<EF> ComponentPoly<EF> for SparsePCSSumcheckPoly<EF>
where
    EF: Field,
{
    async fn get_component_poly_evals(&self) -> Vec<EF> {
        let mut index_vec = future::join_all(
            self.index_mles
                .iter()
                .map(|m| async { m.eval_at(&Point::<EF>::new(vec![].into())).await.to_vec()[0] }),
        )
        .await;
        index_vec.push(self.val_mle.eval_at(&Point::<EF>::new(vec![].into())).await.to_vec()[0]);
        index_vec
    }
}

impl<EF> SumcheckPoly<EF> for SparsePCSSumcheckPoly<EF>
where
    EF: Field,
{
    async fn fix_last_variable(self, alpha: EF) -> Self {
        let index_mles = future::join_all(
            self.index_mles.iter().map(|m| async { m.fix_last_variable(alpha).await }),
        )
        .await;
        let val_mle = self.val_mle.fix_last_variable(alpha).await;

        Self { eval_point: self.eval_point, index_mles, val_mle }
    }

    async fn sum_as_poly_in_last_variable(&self, claim: Option<EF>) -> UnivariatePolynomial<EF> {
        assert!(claim.is_some());
        let zero = EF::zero();
        let one = EF::one();
        let mut evals: Vec<_> =
            (0..self.index_mles.len()).map(|n| EF::from_canonical_usize(n + 2)).collect();
        let chi_evals: Vec<_> = evals.iter().map(|e| EF::one() - *e).collect();
        let mut eval_zero = EF::zero();
        let mut evals_index = vec![EF::zero(); evals.len()];

        let mut val_iter = self.val_mle.hypercube_iter();
        let mut index_iters: Vec<_> =
            self.index_mles.iter().map(|mle| mle.hypercube_iter()).collect();

        // TODO: This is kind of ugly
        // TODO: This is the naive algorithm, we can instead use the WARP algo to speed up
        while let Some(e_0) = val_iter.next() {
            let e_0 = e_0[0];
            let e_1 = val_iter.next().unwrap()[0];
            let index_0_vals: Vec<_> = index_iters
                .iter_mut()
                .map(|it| it.next().expect("All iters should have same length")[0])
                .collect();
            let index_1_vals: Vec<_> = index_iters
                .iter_mut()
                .map(|it| it.next().expect("All iters should have same length")[0])
                .collect();

            eval_zero += e_0
                * Mle::full_lagrange_eval(
                    &self.eval_point,
                    &Point::new(index_0_vals.clone().into()),
                );

            for (i, (&e, &m_e)) in evals.iter().zip(&chi_evals).enumerate() {
                evals_index[i] += (m_e * e_0 + e * e_1)
                    * Mle::full_lagrange_eval(
                        &self.eval_point,
                        &Point::new(
                            index_0_vals
                                .iter()
                                .zip(&index_1_vals)
                                .map(|(&v_0, &v_1)| m_e * v_0 + e * v_1)
                                .collect::<Vec<_>>()
                                .into(),
                        ),
                    );
            }
        }

        let eval_one = claim.unwrap() - eval_zero;

        evals.push(zero);
        evals.push(one);

        evals_index.push(eval_zero);
        evals_index.push(eval_one);

        interpolate_univariate_polynomial(&evals, &evals_index)
    }
}

impl<EF> SumcheckPolyFirstRound<EF> for SparsePCSSumcheckPoly<EF>
where
    EF: Field,
{
    type NextRoundPoly = Self;

    async fn fix_t_variables(self, alpha: EF, t: usize) -> Self::NextRoundPoly {
        assert_eq!(t, 1);

        self.fix_last_variable(alpha).await
    }

    async fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        assert_eq!(t, 1);

        self.sum_as_poly_in_last_variable(claim).await
    }
}

#[cfg(test)]
mod tests {
    use futures::future;
    use rand::Rng;
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_baby_bear::{
        baby_bear_poseidon2::{my_bb_16_perm, Perm},
        BabyBear,
    };
    use slop_challenger::DuplexChallenger;
    use slop_multilinear::{Mle, Point};
    use slop_sumcheck::{partially_verify_sumcheck_proof, reduce_sumcheck_to_evaluation};

    use crate::sparse_poly::SparsePolynomial;

    use super::SparsePCSSumcheckPoly;

    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;

    #[tokio::test]
    async fn pgspcs_sumcheck() {
        let mut rng = rand::thread_rng();
        let default_perm = my_bb_16_perm();
        let mut challenger_prover =
            DuplexChallenger::<BabyBear, Perm, 16, 8>::new(default_perm.clone());
        let mut challenger_verifier =
            DuplexChallenger::<BabyBear, Perm, 16, 8>::new(default_perm.clone());

        let log_sparsity = 8;
        let num_variables = 16;
        let sparsity = 1 << log_sparsity;

        let poly = SparsePolynomial::<F>::new(
            (0..sparsity).map(|i| (i, F::from_canonical_usize(i))).collect(),
            num_variables,
        );

        let alpha = Point::new((0..num_variables).map(|_| rng.gen::<EF>()).collect());

        let v = poly.eval_at(&alpha);
        let sumcheck_poly = SparsePCSSumcheckPoly::<_, _>::new(&alpha, &poly).await;

        let (pgspcs_proof, matrix_component_evals) = reduce_sumcheck_to_evaluation(
            vec![sumcheck_poly],
            &mut challenger_prover,
            vec![v],
            1,
            EF::one(),
        )
        .await;

        // Check the top level sum
        assert_eq!(
            pgspcs_proof.univariate_polys[0].eval_one_plus_eval_zero(),
            pgspcs_proof.claimed_sum
        );
        assert_eq!(pgspcs_proof.claimed_sum, v);

        assert!(partially_verify_sumcheck_proof(
            &pgspcs_proof,
            &mut challenger_verifier,
            log_sparsity,
            num_variables + 1
        )
        .is_ok());

        // Check the final claim
        let index_poly_evals: Vec<_> =
            (0..num_variables).map(|i| matrix_component_evals[0][i]).collect();
        let val_eval = matrix_component_evals[0][num_variables];

        assert_eq!(
            val_eval * Mle::full_lagrange_eval(&alpha, &index_poly_evals.clone().into()),
            pgspcs_proof.point_and_eval.1
        );

        // Check one claim is the MLE of z
        assert_eq!(val_eval, poly.val_mle::<EF>().eval_at(&pgspcs_proof.point_and_eval.0).await[0]);

        let index_alpha_eval =
            future::join_all(poly.index_mles::<EF>().iter().map(|index_mle| async {
                index_mle.eval_at(&pgspcs_proof.point_and_eval.0).await[0]
            }))
            .await;

        assert_eq!(index_alpha_eval, index_poly_evals);
    }
}
