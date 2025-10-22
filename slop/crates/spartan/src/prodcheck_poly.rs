use itertools::Itertools;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractField, ExtensionField, Field, UnivariatePolynomial,
};
use slop_alloc::{Backend, CpuBackend};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{ComponentPoly, SumcheckPoly, SumcheckPolyBase, SumcheckPolyFirstRound};

use crate::r1cs::R1CS;

// Represents the polynomials for the first round of the Spartan sumcheck
pub struct ProdcheckPoly<EF, B: Backend = CpuBackend> {
    // These are the tables that we compress
    pub eq_r: Mle<EF, B>,
    pub az: Mle<EF, B>,
    pub bz: Mle<EF, B>,
    pub cz: Mle<EF, B>,
}

pub(crate) fn pad_vec_to_next_power_of_two<F: Field>(v: &mut Vec<F>) {
    v.resize(v.len().next_power_of_two(), F::zero())
}

impl<EF> ProdcheckPoly<EF>
where
    EF: Field,
{
    pub async fn new<F>(r: &Point<EF>, r1cs: &R1CS<F>, z: &[EF]) -> Self
    where
        F: Field,
        EF: ExtensionField<F>,
    {
        let eq_r = Mle::partial_lagrange(r).await;
        let mut az = &r1cs.a * z;
        let mut bz = &r1cs.b * z;
        let mut cz = &r1cs.c * z;
        pad_vec_to_next_power_of_two(&mut az);
        pad_vec_to_next_power_of_two(&mut bz);
        pad_vec_to_next_power_of_two(&mut cz);

        Self { eq_r, az: az.into(), bz: bz.into(), cz: cz.into() }
    }
}

impl<EF> SumcheckPolyBase for ProdcheckPoly<EF>
where
    EF: AbstractField,
{
    fn num_variables(&self) -> u32 {
        self.az.num_variables()
    }
}

impl<EF> ComponentPoly<EF> for ProdcheckPoly<EF>
where
    EF: Field,
{
    async fn get_component_poly_evals(&self) -> Vec<EF> {
        assert_eq!(self.num_variables(), 0, "Queried before the reduction was finished");
        // The component polys are:
        // 1) The Az poly
        // 2) The Bz poly
        // 3) The Cz poly

        vec![
            self.az.eval_at(&Point::<EF>::new(vec![].into())).await.to_vec()[0],
            self.bz.eval_at(&Point::<EF>::new(vec![].into())).await.to_vec()[0],
            self.cz.eval_at(&Point::<EF>::new(vec![].into())).await.to_vec()[0],
        ]
    }
}

impl<EF> SumcheckPoly<EF> for ProdcheckPoly<EF>
where
    EF: Field,
{
    async fn fix_last_variable(self, alpha: EF) -> Self {
        let eq_r = self.eq_r.fix_last_variable(alpha).await;
        let az = self.az.fix_last_variable(alpha).await;
        let bz = self.bz.fix_last_variable(alpha).await;
        let cz = self.cz.fix_last_variable(alpha).await;

        Self { eq_r, az, bz, cz }
    }

    async fn sum_as_poly_in_last_variable(&self, claim: Option<EF>) -> UnivariatePolynomial<EF> {
        assert!(claim.is_some());

        // The evaluation points we use
        let zero = EF::zero();
        let one = EF::one();
        let m_one = -one;
        //let half = one.halve();
        let two = one + one;

        let mut eval_zero = EF::zero();
        //let mut eval_one = EF::zero();
        let mut eval_m_one = EF::zero();
        //let mut eval_half = EF::zero();
        let mut eval_two = EF::zero();

        // Single loop to compute all evals (in 2 by 2 fashion)
        // c_0 correspond to evaluations[2*i]
        // c_1 correspond to evaluations[2*i + 1]
        for (c_0, c_1) in self
            .eq_r
            .hypercube_iter()
            .zip(self.az.hypercube_iter())
            .zip(self.bz.hypercube_iter())
            .zip(self.cz.hypercube_iter())
            .map(|(((eq, az), bz), cz)| (eq[0], az[0], bz[0], cz[0]))
            .tuples()
        {
            let eq_0 = c_0.0;
            let eq_1 = c_1.0;

            let az_0 = c_0.1;
            let az_1 = c_1.1;

            let bz_0 = c_0.2;
            let bz_1 = c_1.2;

            let cz_0 = c_0.3;
            let cz_1 = c_1.3;

            eval_zero += eq_0 * (az_0 * bz_0 - cz_0);
            //eval_one += eq_1 * (az_1 * bz_1 - cz_1);

            let common_eq = eq_0 - eq_1;
            let common_az = az_0 - az_1;
            let common_bz = bz_0 - bz_1;
            let common_cz = cz_0 - cz_1;

            eval_m_one +=
                (eq_0 + common_eq) * ((az_0 + common_az) * (bz_0 + common_bz) - (cz_0 + common_cz));

            eval_two +=
                (eq_1 - common_eq) * ((az_1 - common_az) * (bz_1 - common_bz) - (cz_1 - common_cz));

            // These are old less efficient variants, kept here for completeness since the optimized
            // version is harder to read Note each of these is 3 mult
            //eval_half += (eq_0 + eq_1) * ((az_0 + az_1) * (bz_0 + bz_1).halve() - (cz_0 + cz_1));
            // Note each of these are just 2 mults! 2 > 1/2
            //eval_m_one += (eq_0 + eq_0 - eq_1)
            //    * ((az_0 + az_0 - az_1) * (bz_0 + bz_0 - bz_1) - (cz_0 + cz_0 - cz_1));
            //eval_two += (-eq_0 + (eq_1 + eq_1))
            //    * ((-az_0 + (az_1 + az_1)) * (-bz_0 + bz_1 + bz_1) - (-cz_0 + cz_1 + cz_1))
            // This would be if we used three
            //  eval_three += (-(eq_0 + eq_0) + (eq_1 + eq_1 + eq_1))
            //    * ((-(az_0 + az_0) + (az_1 + az_1 + az_1)) * (-(bz_0+bz_0) + bz_1 + bz_1 + bz_1) -
            //      (-(cz_0 + cz_0) + cz_1 + cz_1 + cz_1))
        }

        let eval_one = claim.unwrap() - eval_zero;

        interpolate_univariate_polynomial(
            &[zero, one, m_one, two],
            &[eval_zero, eval_one, eval_m_one, eval_two],
        )
    }
}

impl<EF> SumcheckPolyFirstRound<EF> for ProdcheckPoly<EF>
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
    use rand::Rng;
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_baby_bear::{
        baby_bear_poseidon2::{my_bb_16_perm, Perm},
        BabyBear,
    };
    use slop_challenger::DuplexChallenger;
    use slop_multilinear::{Mle, Point};
    use slop_sumcheck::{partially_verify_sumcheck_proof, reduce_sumcheck_to_evaluation};

    use crate::{r1cs, sparse_matrix::SparseMatrix};

    use super::ProdcheckPoly;

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
        let entries_a: Vec<_> = (0..witness_len)
            .map(|_| (rng.gen_range(0..witness_len), rng.gen_range(0..witness_len), rng.gen::<F>()))
            .collect();
        let entries_b: Vec<_> = (0..witness_len)
            .map(|_| (rng.gen_range(0..witness_len), rng.gen_range(0..witness_len), rng.gen::<F>()))
            .collect();

        let entries_c: Vec<_> = (0..witness_len)
            .map(|_| (rng.gen_range(0..witness_len), rng.gen_range(0..witness_len), rng.gen::<F>()))
            .collect();

        let z: Vec<_> = (0..witness_len).map(|_| rng.gen::<EF>()).collect();

        let mut a = SparseMatrix::new(witness_len, witness_len);
        entries_a.into_iter().for_each(|(r, c, v)| a.set(r, c, v));

        let mut b = SparseMatrix::new(witness_len, witness_len);
        entries_b.into_iter().for_each(|(r, c, v)| b.set(r, c, v));

        let mut c = SparseMatrix::new(witness_len, witness_len);
        entries_c.into_iter().for_each(|(r, col, v)| c.set(r, col, v));

        let r1cs = r1cs::R1CS { num_public_inputs: 0, a: a.clone(), b: b.clone(), c: c.clone() };

        let r = Point::new((0..log_witness_len).map(|_| rng.gen::<EF>()).collect());
        let lagrange_r = Mle::partial_lagrange(&r).await;

        let az = &a * &z;
        let bz = &b * &z;
        let cz = &c * &z;

        let remainder: Vec<_> =
            az.iter().zip(bz.iter()).zip(cz.iter()).map(|((az, bz), cz)| *az * *bz - *cz).collect();

        let v = lagrange_r.hypercube_iter().zip(remainder.iter()).map(|(r, rem)| r[0] * *rem).sum();

        let prodcheck_poly = ProdcheckPoly::<_, _>::new(&r, &r1cs, &z).await;

        let (prodcheck_proof, component_evals) = reduce_sumcheck_to_evaluation(
            vec![prodcheck_poly],
            &mut challenger_prover,
            vec![v],
            1,
            EF::one(),
        )
        .await;

        // Check the top level sum
        assert_eq!(
            prodcheck_proof.univariate_polys[0].eval_one_plus_eval_zero(),
            prodcheck_proof.claimed_sum
        );
        assert_eq!(prodcheck_proof.claimed_sum, v);

        // Check intermediate
        assert!(partially_verify_sumcheck_proof(
            &prodcheck_proof,
            &mut challenger_verifier,
            log_witness_len,
            3
        )
        .is_ok());

        // Check the final claim
        let v_a = component_evals[0][0];
        let v_b = component_evals[0][1];
        let v_c = component_evals[0][2];

        let alpha = prodcheck_proof.point_and_eval.0.clone();

        assert_eq!(
            Mle::full_lagrange_eval(&r, &alpha) * (v_a * v_b - v_c),
            prodcheck_proof.point_and_eval.1
        );

        // Check one claim is the MLE of Az
        assert_eq!(v_a, Mle::new(az.into()).eval_at(&alpha).await[0]);
        assert_eq!(v_b, Mle::new(bz.into()).eval_at(&alpha).await[0]);
        assert_eq!(v_c, Mle::new(cz.into()).eval_at(&alpha).await[0]);
    }
}
