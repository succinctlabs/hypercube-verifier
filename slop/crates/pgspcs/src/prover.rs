use std::marker::PhantomData;

use slop_algebra::AbstractField;
use slop_alloc::CpuBackend;
use slop_challenger::IopCtx;
use slop_commit::{Message, Rounds};
use slop_multilinear::{
    Evaluations, Mle, MultilinearPcsBatchProver, MultilinearPcsBatchVerifier, Point,
};
use slop_sumcheck::{reduce_sumcheck_to_evaluation, PartialSumcheckProof};

use crate::{sparse_poly::SparsePolynomial, sumcheck_polynomials::SparsePCSSumcheckPoly};

pub struct SparsePCSProver<GC: IopCtx, MP: MultilinearPcsBatchProver<GC>> {
    pub multilinear_prover: MP,
    _global_config: PhantomData<GC>,
}

pub struct ProverData<GC: IopCtx, MP: MultilinearPcsBatchProver<GC>> {
    pub multilinear_prover_data: MP::ProverData,
    pub mles: Message<Mle<GC::F, MP::A>>,
    _prover: PhantomData<MP>,
}

pub struct Proof<EF, PCSProof> {
    pub evaluation_claims: Vec<EF>,
    pub sparse_sumcheck_proof: PartialSumcheckProof<EF>,
    pub pcs_proof: PCSProof,
}

impl<GC: IopCtx, MP: MultilinearPcsBatchProver<GC, A = CpuBackend>> SparsePCSProver<GC, MP> {
    pub fn new(prover: MP) -> Self {
        Self { multilinear_prover: prover, _global_config: PhantomData }
    }

    pub async fn commit_sparse_poly(
        &self,
        poly: &SparsePolynomial<GC::F>,
    ) -> Result<(GC::Digest, ProverData<GC, MP>), MP::ProverError> {
        // TODO: Implement batching
        // TODO: This is always done in a trusted setting, can something be optimized here?

        // Decompose the polynomial into the components to be committed
        let mut mles = poly.index_mles();
        mles.push(poly.val_mle());

        // Commit them as a MLE
        let mles: Message<Mle<_>> = mles.into();
        let (commitment, prover_data) =
            self.multilinear_prover.commit_multilinears(mles.clone()).await?;

        Ok((
            commitment,
            ProverData { multilinear_prover_data: prover_data, mles, _prover: Default::default() },
        ))
    }

    pub async fn prove_evaluation(
        &self,
        poly: &SparsePolynomial<GC::F>,
        eval_point: &Point<GC::EF>,
        prover_data: ProverData<GC, MP>,
        challenger: &mut GC::Challenger,
    ) -> Result<
        Proof<GC::EF, <MP::Verifier as MultilinearPcsBatchVerifier<GC>>::Proof>,
        MP::ProverError,
    > {
        // Compute the evaluation claim
        let v = poly.eval_at(eval_point);

        // Run the sumcheck to reduce sum_b eq(eval_point, index(b)) * val(b) = v
        let sumcheck_poly = SparsePCSSumcheckPoly::<_, _>::new(eval_point, poly).await;
        let (pgspcs_proof, matrix_component_evals) = reduce_sumcheck_to_evaluation(
            vec![sumcheck_poly],
            challenger,
            vec![v],
            1,
            <GC::EF as AbstractField>::one(),
        )
        .await;

        // Claim is now reduced to eq(eval_point, index(new_eval_point)) * val(new_eval_point)
        let new_eval_point = pgspcs_proof.point_and_eval.0.clone();
        let new_evaluation_claims = matrix_component_evals[0].clone();

        // Prove the evaluations (untrusted because we send them)
        let pcs_proof = self
            .multilinear_prover
            .prove_untrusted_evaluations(
                new_eval_point,
                // prover_data.mles = [index_1, ..., index_n, val]
                Rounds { rounds: vec![prover_data.mles] },
                // The matrix component_evals already contains the evaluations in the same order
                Rounds {
                    rounds: vec![Evaluations::new(vec![new_evaluation_claims.clone().into()])],
                },
                Rounds { rounds: vec![prover_data.multilinear_prover_data] },
                challenger,
            )
            .await?;

        Ok(Proof {
            sparse_sumcheck_proof: pgspcs_proof,
            pcs_proof,
            evaluation_claims: new_evaluation_claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
    use slop_basefold::BasefoldVerifier;
    use slop_basefold_prover::{BasefoldProver, Poseidon2BabyBear16BasefoldCpuProverComponents};

    use crate::verifier::SparsePCSVerifier;

    use super::*;

    #[tokio::test]
    async fn test_sparse_polynomial_prover() {
        type GC = BabyBearDegree4Duplex;
        type BackendProver = BasefoldProver<GC, Poseidon2BabyBear16BasefoldCpuProverComponents>;
        type BackendVerifier = BasefoldVerifier<GC>;
        type F = BabyBear;
        type EF = BinomialExtensionField<BabyBear, 4>;

        let mut rng = thread_rng();

        let log_blowup = 1;
        let log_sparsity = 8;
        let num_variables = 16;
        let sparsity = 1 << log_sparsity;

        let poly = SparsePolynomial::<F>::new(
            (0..sparsity).map(|i| (i, F::from_canonical_usize(i))).collect(),
            num_variables,
        );
        let alpha = Point::new((0..num_variables).map(|_| rng.gen::<EF>()).collect());

        let basefold_verifier = BackendVerifier::new(log_blowup, 1);
        let basefold_prover = BackendProver::new(&basefold_verifier);

        let mut challenger = GC::default_challenger();

        let sparse_prover = SparsePCSProver::new(basefold_prover);
        let (commitment, prover_data) = sparse_prover.commit_sparse_poly(&poly).await.unwrap();

        let proof = sparse_prover
            .prove_evaluation(&poly, &alpha, prover_data, &mut challenger)
            .await
            .unwrap();
        let evaluation_claim = poly.eval_at(&alpha);

        let mut challenger = GC::default_challenger();

        let sparse_verifier = SparsePCSVerifier::new(basefold_verifier);
        sparse_verifier
            .verify_trusted_evaluations(
                commitment,
                &alpha,
                evaluation_claim,
                &proof,
                &mut challenger,
            )
            .unwrap();
    }
}
