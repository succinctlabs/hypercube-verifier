use std::marker::PhantomData;

use itertools::Itertools;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractField, ExtensionField, Field, UnivariatePolynomial,
};
use slop_alloc::{Backend, CpuBackend};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{ComponentPoly, SumcheckPoly, SumcheckPolyBase, SumcheckPolyFirstRound};

use crate::sparse_matrix::SparseMatrix;

// Represents the polynomials for the first round of the Spartan sumcheck
pub struct LincheckPoly<F, EF, B: Backend = CpuBackend> {
    // This is initiliazed to correspond to A[alpha, -]
    pub m: Mle<EF, B>,
    // This is the witness
    pub z: Mle<EF, B>,
    _marker: PhantomData<F>,
}

impl<F, EF> LincheckPoly<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub async fn new(z: &[F], m: &SparseMatrix<F>, alpha: &Point<EF>) -> Self {
        assert!(z.len().is_power_of_two());

        let m = Mle::partial_lagrange(alpha).await.guts().as_slice() * m;

        Self {
            m: m.into(),
            z: z.iter().cloned().map(EF::from_base).collect::<Vec<_>>().into(),
            _marker: PhantomData,
        }
    }
}

impl<F, EF> SumcheckPolyBase for LincheckPoly<F, EF>
where
    EF: AbstractField,
{
    fn num_variables(&self) -> u32 {
        self.m.num_variables()
    }
}

impl<F, EF> ComponentPoly<EF> for LincheckPoly<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    async fn get_component_poly_evals(&self) -> Vec<EF> {
        assert_eq!(self.num_variables(), 0, "Queried before the reduction was finished");
        // The component polys are:
        // 1) The M[alpha] poly
        // 2) The z poly

        vec![
            self.m.eval_at(&Point::<EF>::new(vec![].into())).await.to_vec()[0],
            self.z.eval_at(&Point::<EF>::new(vec![].into())).await.to_vec()[0],
        ]
    }
}

impl<F, EF> SumcheckPoly<EF> for LincheckPoly<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    async fn fix_last_variable(self, alpha: EF) -> Self {
        let m = self.m.fix_last_variable(alpha).await;
        let z = self.z.fix_last_variable(alpha).await;

        Self { m, z, _marker: self._marker }
    }

    async fn sum_as_poly_in_last_variable(&self, claim: Option<EF>) -> UnivariatePolynomial<EF> {
        assert!(claim.is_some());

        // The evaluations points we use
        let zero = EF::zero();
        let one = EF::one();
        let half = one.halve();

        let mut eval_zero = EF::zero();
        let mut eval_half = EF::zero();
        for (c_0, c_1) in
            self.m.hypercube_iter().zip(self.z.hypercube_iter()).map(|(m, z)| (m[0], z[0])).tuples()
        {
            let m_0 = c_0.0;
            let m_1 = c_1.0;
            let z_0 = c_0.1;
            let z_1 = c_1.1;

            eval_zero += m_0 * z_0;
            eval_half += (m_0 + m_1) * (z_0 + z_1);
        }

        let eval_one = claim.unwrap() - eval_zero;

        interpolate_univariate_polynomial(
            &[zero, one, half],
            &[eval_zero, eval_one, (half * half) * eval_half],
        )
    }
}

impl<F, EF> SumcheckPolyFirstRound<EF> for LincheckPoly<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
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
    use rand::Rng;
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_baby_bear::BabyBear;
    use slop_challenger::DuplexChallenger;
    use slop_merkle_tree::{my_bb_16_perm, Perm};
    use slop_multilinear::{Mle, Point};
    use slop_sumcheck::{partially_verify_sumcheck_proof, reduce_sumcheck_to_evaluation};

    use crate::sparse_matrix::SparseMatrix;

    use super::LincheckPoly;

    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;

    #[tokio::test]
    async fn lincheck_sumcheck() {
        let mut rng = rand::thread_rng();
        let default_perm = my_bb_16_perm();
        let mut challenger_prover =
            DuplexChallenger::<BabyBear, Perm, 16, 8>::new(default_perm.clone());
        let mut challenger_verifier =
            DuplexChallenger::<BabyBear, Perm, 16, 8>::new(default_perm.clone());

        let log_witness_len = 8;
        let witness_len = 1 << log_witness_len;
        let entries: Vec<_> = (0..witness_len)
            .map(|_| (rng.gen_range(0..witness_len), rng.gen_range(0..witness_len), rng.gen::<F>()))
            .collect();

        let alpha = Point::new((0..log_witness_len).map(|_| rng.gen::<EF>()).collect());

        let z: Vec<_> = (0..witness_len).map(|_| rng.gen::<F>()).collect();

        let mut m = SparseMatrix::new(witness_len, witness_len);
        entries.into_iter().for_each(|(r, c, v)| m.set(r, c, v));

        let m_alpha = Mle::partial_lagrange(&alpha).await.guts().as_slice() * &m;
        let v = m_alpha.iter().zip(&z).map(|(m, z)| *m * *z).sum();

        let lincheck_poly = LincheckPoly::<_, _>::new(&z, &m, &alpha).await;

        let (lincheck_proof, matrix_component_evals) = reduce_sumcheck_to_evaluation(
            vec![lincheck_poly],
            &mut challenger_prover,
            vec![v],
            1,
            EF::one(),
        )
        .await;

        // Check the top level sum
        assert_eq!(
            lincheck_proof.univariate_polys[0].eval_one_plus_eval_zero(),
            lincheck_proof.claimed_sum
        );
        assert_eq!(lincheck_proof.claimed_sum, v);

        assert!(partially_verify_sumcheck_proof(&lincheck_proof, &mut challenger_verifier).is_ok());

        // Check the final claim
        let sumcheck_m_eval = matrix_component_evals[0][0];
        let sumcheck_z_eval = matrix_component_evals[0][1];

        assert_eq!(sumcheck_m_eval * sumcheck_z_eval, lincheck_proof.point_and_eval.1);

        // Check one claim is the MLE of z
        assert_eq!(
            sumcheck_z_eval,
            Mle::new(z.into()).eval_at(&lincheck_proof.point_and_eval.0).await[0]
        );

        // Check one claim is the MLE of m
        assert_eq!(
            sumcheck_m_eval,
            Mle::new(m_alpha.into()).eval_at(&lincheck_proof.point_and_eval.0).await[0]
        );
    }
}
