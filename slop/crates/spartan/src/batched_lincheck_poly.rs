use futures::future;
use itertools::Itertools;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractField, ExtensionField, Field, UnivariatePolynomial,
};
use slop_alloc::{Backend, CpuBackend};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{ComponentPoly, SumcheckPoly, SumcheckPolyBase, SumcheckPolyFirstRound};

use crate::{prodcheck_poly::pad_vec_to_next_power_of_two, sparse_matrix::SparseMatrix};

// Represents the polynomials for the first round of the Spartan sumcheck
pub struct BatchedLincheckPoly<EF, B: Backend = CpuBackend> {
    // This is initiliazed to correspond to A[alpha, -]
    pub ms: Vec<Mle<EF, B>>,
    // This is the witness
    pub z: Mle<EF, B>,

    // This is the batching randomness
    pub lambda: EF,
}

impl<EF> BatchedLincheckPoly<EF>
where
    EF: Field,
{
    pub async fn new<F>(
        z: &[EF],
        ms: impl IntoIterator<Item = &SparseMatrix<F>>,
        alpha: &Point<EF>,
        lambda: EF,
    ) -> Self
    where
        F: Field,
        EF: ExtensionField<F>,
    {
        let mut z = z.to_vec();
        pad_vec_to_next_power_of_two(&mut z);
        //assert!(z.len().is_power_of_two());

        let alpha_evals = Mle::partial_lagrange(alpha).await.guts().as_slice().to_vec();
        let ms = ms.into_iter().map(|m| {
            let mut res = &alpha_evals[..] * m;
            pad_vec_to_next_power_of_two(&mut res);
            res.into()
        });

        Self { ms: ms.collect_vec(), z: z.into(), lambda }
    }
}

impl<EF> SumcheckPolyBase for BatchedLincheckPoly<EF>
where
    EF: AbstractField,
{
    fn num_variables(&self) -> u32 {
        self.ms[0].num_variables()
    }
}

impl<EF> ComponentPoly<EF> for BatchedLincheckPoly<EF>
where
    EF: Field,
{
    async fn get_component_poly_evals(&self) -> Vec<EF> {
        assert_eq!(self.num_variables(), 0, "Queried before the reduction was finished");
        // The component polys are:
        // 1) The Ms[alpha] poly
        // 2) The z poly
        let mut m_vec = future::join_all(
            self.ms
                .iter()
                .map(|m| async { m.eval_at(&Point::<EF>::new(vec![].into())).await.to_vec()[0] }),
        )
        .await;
        m_vec.push(self.z.eval_at(&Point::<EF>::new(vec![].into())).await.to_vec()[0]);
        m_vec
    }
}

impl<EF> SumcheckPoly<EF> for BatchedLincheckPoly<EF>
where
    EF: Field,
{
    async fn fix_last_variable(self, alpha: EF) -> Self {
        let ms =
            future::join_all(self.ms.iter().map(|m| async { m.fix_last_variable(alpha).await }))
                .await;
        let z = self.z.fix_last_variable(alpha).await;

        Self { ms, z, lambda: self.lambda }
    }

    async fn sum_as_poly_in_last_variable(&self, claim: Option<EF>) -> UnivariatePolynomial<EF> {
        assert!(claim.is_some());

        // The evaluations points we use
        let zero = EF::zero();
        let one = EF::one();
        let half = one.halve();

        let mut eval_zero = EF::zero();
        let mut eval_half = EF::zero();

        let mut z_iter = self.z.hypercube_iter();
        let mut ms_iters: Vec<_> = self.ms.iter().map(|mle| mle.hypercube_iter()).collect();

        // We only precompute it once
        let lambda_expanded: Vec<_> = self.lambda.powers().take(ms_iters.len()).collect();

        // TODO: This is kind of ugly
        while let Some(z_0) = z_iter.next() {
            let z_0 = z_0[0];
            let z_1 = z_iter.next().unwrap()[0];
            let m0_vals: Vec<_> = ms_iters
                .iter_mut()
                .map(|it| it.next().expect("All iters should have same length")[0])
                .collect();
            let m1_vals: Vec<_> = ms_iters
                .iter_mut()
                .map(|it| it.next().expect("All iters should have same length")[0])
                .collect();

            eval_zero += z_0
                * (m0_vals
                    .iter()
                    .zip(&lambda_expanded)
                    .map(|(m_0, lambda_pow)| *lambda_pow * *m_0)
                    .sum::<EF>());

            eval_half += (z_0 + z_1)
                * m0_vals
                    .iter()
                    .zip(m1_vals.iter())
                    .zip(&lambda_expanded)
                    .map(|((m_0, m_1), lambda_pow)| *lambda_pow * (*m_0 + *m_1))
                    .sum::<EF>();
        }

        let eval_one = claim.unwrap() - eval_zero;

        interpolate_univariate_polynomial(
            &[zero, one, half],
            &[eval_zero, eval_one, eval_half.halve().halve()],
        )
    }
}

impl<EF> SumcheckPolyFirstRound<EF> for BatchedLincheckPoly<EF>
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

    use crate::sparse_matrix::SparseMatrix;

    use super::BatchedLincheckPoly;

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

        let num_matrices = 4;
        let log_witness_len = 8;
        let witness_len = 1 << log_witness_len;

        let ms: Vec<_> = (0..num_matrices)
            .map(|_| {
                let entries: Vec<_> = (0..witness_len)
                    .map(|_| {
                        (
                            rng.gen_range(0..witness_len),
                            rng.gen_range(0..witness_len),
                            rng.gen::<F>(),
                        )
                    })
                    .collect();

                let mut m = SparseMatrix::new(witness_len, witness_len);
                entries.into_iter().for_each(|(r, c, v)| m.set(r, c, v));
                m
            })
            .collect();

        let z: Vec<_> = (0..witness_len).map(|_| rng.gen::<EF>()).collect();

        let alpha = Point::new((0..log_witness_len).map(|_| rng.gen::<EF>()).collect());
        let lambda: EF = rng.gen();

        let m_alphas =
            future::join_all(ms.iter().map(|m| async {
                Mle::partial_lagrange(&alpha).await.guts().as_slice() * &m.clone()
            }))
            .await;
        let v = m_alphas
            .iter()
            .map(|m_alpha| m_alpha.iter().zip(&z).map(|(m, z)| *m * *z).sum::<EF>())
            .zip(lambda.powers())
            .map(|(v, lambda)| v * lambda)
            .sum();

        let lincheck_poly = BatchedLincheckPoly::<_, _>::new(&z, &ms, &alpha, lambda).await;

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

        assert!(partially_verify_sumcheck_proof(
            &lincheck_proof,
            &mut challenger_verifier,
            log_witness_len,
            2
        )
        .is_ok());

        // Check the final claim
        let sumcheck_ms_eval: Vec<_> =
            (0..num_matrices).map(|i| matrix_component_evals[0][i]).collect();
        let batched_eval =
            sumcheck_ms_eval.iter().zip(lambda.powers()).map(|(e, l)| *e * l).sum::<EF>();
        let sumcheck_z_eval = matrix_component_evals[0][num_matrices];

        assert_eq!(batched_eval * sumcheck_z_eval, lincheck_proof.point_and_eval.1);

        // Check one claim is the MLE of z
        assert_eq!(
            sumcheck_z_eval,
            Mle::new(z.into()).eval_at(&lincheck_proof.point_and_eval.0).await[0]
        );

        let m_alpha_eval = future::join_all(m_alphas.iter().map(|m_alpha| async {
            Mle::new(m_alpha.clone().into()).eval_at(&lincheck_proof.point_and_eval.0).await[0]
        }))
        .await;

        // Check one claim is the MLE of m
        assert_eq!(
            batched_eval,
            m_alpha_eval.into_iter().zip(lambda.powers()).map(|(e, l)| l * e).sum()
        );
    }
}
