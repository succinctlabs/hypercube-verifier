use std::marker::PhantomData;

use slop_algebra::{ExtensionField, Field};
use slop_challenger::{FieldChallenger, GrindingChallenger};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{partially_verify_sumcheck_proof, SumcheckError};

use crate::{proof::PartialSpartanProof, r1cs::R1CS};

#[derive(Clone, PartialEq)]
pub struct SpartanR1CSVerifier<F> {
    pub log_witness_size: usize,
    pub log_num_constraints: usize,
    _field: PhantomData<F>,
}

impl<F> SpartanR1CSVerifier<F> {
    pub fn new_for_size(witnesses: usize, constraints: usize) -> Self {
        // m is equal to ceiling(log(number of variables in constraint system)). It is
        // equal to the log of the width of the matrices.
        let m = witnesses.next_power_of_two().ilog2() as usize;

        // m_0 is equal to ceiling(log(number_of_constraints)). It is equal to the
        // number of variables in the multilinear polynomial we are running our sumcheck
        // on.
        let m_0 = constraints.next_power_of_two().ilog2() as usize;

        Self { log_witness_size: m, log_num_constraints: m_0, _field: PhantomData }
    }
}

impl<F> SpartanR1CSVerifier<F>
where
    F: Field,
{
    pub async fn partial_verify<EF, C>(
        &self,
        challenger: &mut C,
        proof: &PartialSpartanProof<EF>,
    ) -> Result<(), SumcheckError>
    where
        EF: ExtensionField<F> + Send + Sync,
        C: FieldChallenger<F> + GrindingChallenger,
    {
        // Squeeze the zerocheck randomness
        let mut r = Vec::with_capacity(self.log_num_constraints);
        for _ in 0..self.log_num_constraints {
            r.push(challenger.sample_ext_element());
        }
        let r = Point::<EF>::new(r.into());

        partially_verify_sumcheck_proof(
            &proof.prodcheck_proof,
            challenger,
            self.log_num_constraints,
            3,
        )?;

        challenger.observe_ext_element(proof.v_a);
        challenger.observe_ext_element(proof.v_b);
        challenger.observe_ext_element(proof.v_c);

        let alpha = proof.prodcheck_proof.point_and_eval.0.clone();

        if Mle::full_lagrange_eval(&r, &alpha) * (proof.v_a * proof.v_b - proof.v_c)
            != proof.prodcheck_proof.point_and_eval.1
        {
            return Err(SumcheckError::InconsistencyWithEval);
        }

        let lambda: EF = challenger.sample_ext_element();

        partially_verify_sumcheck_proof(
            &proof.lincheck_proof,
            challenger,
            self.log_witness_size,
            2,
        )?;

        if proof.a_claim * proof.z_claim
            + lambda * (proof.b_claim * proof.z_claim)
            + lambda * lambda * (proof.c_claim * proof.z_claim)
            != proof.lincheck_proof.point_and_eval.1
        {
            return Err(SumcheckError::InconsistencyWithEval);
        }

        Ok(())
    }

    pub async fn verify_claims<EF>(
        &self,
        witness: Vec<EF>,
        r1cs: &R1CS<F>,
        proof: &PartialSpartanProof<EF>,
    ) -> Result<(), SumcheckError>
    where
        EF: ExtensionField<F> + Send + Sync,
    {
        let alpha = proof.prodcheck_proof.point_and_eval.0.clone();
        let beta = proof.lincheck_proof.point_and_eval.0.clone();

        let alpha_eval: Vec<_> =
            Mle::partial_lagrange(&alpha).await.hypercube_iter().map(|alpha| alpha[0]).collect();

        let z_eval: EF = Mle::new(witness.into()).eval_at(&beta).await[0];
        let a_eval: EF = Mle::new((&alpha_eval[..] * &r1cs.a).into()).eval_at(&beta).await[0];
        let b_eval: EF = Mle::new((&alpha_eval[..] * &r1cs.b).into()).eval_at(&beta).await[0];
        let c_eval: EF = Mle::new((&alpha_eval[..] * &r1cs.c).into()).eval_at(&beta).await[0];

        if z_eval != proof.z_claim
            || a_eval != proof.a_claim
            || b_eval != proof.b_claim
            || c_eval != proof.c_claim
        {
            return Err(SumcheckError::InconsistencyWithEval);
        }

        Ok(())
    }

    pub async fn full_verify<EF, C>(
        &self,
        witness: Vec<EF>,
        r1cs: &R1CS<F>,
        proof: &PartialSpartanProof<EF>,
        challenger: &mut C,
    ) -> Result<(), SumcheckError>
    where
        EF: ExtensionField<F> + Send + Sync,
        C: GrindingChallenger + FieldChallenger<F>,
    {
        self.partial_verify(challenger, proof).await?;
        self.verify_claims(witness, r1cs, proof).await
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

    use crate::{
        prover::SpartanR1CSProver, r1cs, sparse_matrix::SparseMatrix, verifier::SpartanR1CSVerifier,
    };

    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;

    #[tokio::test]
    async fn test_e2e_spartan() {
        let mut rng = rand::thread_rng();
        let default_perm = my_bb_16_perm();
        let mut challenger_prover =
            DuplexChallenger::<BabyBear, Perm, 16, 8>::new(default_perm.clone());
        let mut challenger_verifier =
            DuplexChallenger::<BabyBear, Perm, 16, 8>::new(default_perm.clone());

        // TODO: Setup a non-trivial R1CS here
        let log_witness_len = 8;
        let log_num_constraints = 10;
        let num_constraints = 1 << log_num_constraints;
        let witness_len = 1 << log_witness_len;
        let entries_a: Vec<_> = (0..witness_len)
            .map(|_| {
                (rng.gen_range(0..num_constraints), rng.gen_range(0..witness_len), rng.gen::<F>())
            })
            .collect();
        let entries_b: Vec<_> = (0..witness_len)
            .map(|_| {
                (rng.gen_range(0..num_constraints), rng.gen_range(0..witness_len), rng.gen::<F>())
            })
            .collect();
        let entries_c: Vec<_> = (0..witness_len)
            .map(|_| {
                (rng.gen_range(0..num_constraints), rng.gen_range(0..witness_len), rng.gen::<F>())
            })
            .collect();

        let z: Vec<_> = (0..witness_len).map(|_| EF::zero()).collect();

        let mut a = SparseMatrix::new(num_constraints, witness_len);
        entries_a.into_iter().for_each(|(r, c, v)| a.set(r, c, v));
        let mut b = SparseMatrix::new(num_constraints, witness_len);
        entries_b.into_iter().for_each(|(r, c, v)| b.set(r, c, v));
        let mut c = SparseMatrix::new(num_constraints, witness_len);
        entries_c.into_iter().for_each(|(r, col, v)| c.set(r, col, v));

        let r1cs = r1cs::R1CS { num_public_inputs: 0, a: a.clone(), b: b.clone(), c: c.clone() };

        let spartan_prover = SpartanR1CSProver::<F>::new_for_r1cs(&r1cs);

        let proof = spartan_prover.prove::<EF, _>(z.clone(), &mut challenger_prover).await;

        let spartan_verifier = SpartanR1CSVerifier::<F>::new_for_size(witness_len, num_constraints);
        assert!(spartan_verifier
            .full_verify(z, &r1cs, &proof, &mut challenger_verifier)
            .await
            .is_ok());
    }
}
