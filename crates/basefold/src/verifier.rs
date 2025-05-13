use hypercube_commit::{TensorCs, TensorCsOpening};
use hypercube_multilinear::{Evaluations, MultilinearPcsVerifier, Point};
use hypercube_utils::reverse_bits_len;
use itertools::Itertools;
use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::{AbstractExtensionField, AbstractField, TwoAdicField};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{BasefoldConfig, DefaultBasefoldConfig};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BasefoldVerifier<B: BasefoldConfig> {
    pub fri_config: crate::FriConfig<B::F>,
    pub tcs: B::Tcs,
}

impl<B: DefaultBasefoldConfig> BasefoldVerifier<B> {
    pub fn new(log_blowup: usize) -> Self {
        B::default_verifier(log_blowup)
    }

    pub fn challenger(&self) -> B::Challenger {
        B::default_challenger(self)
    }
}

#[derive(Error)]
pub enum BaseFoldVerifierError<B: BasefoldConfig> {
    #[error("Sumcheck and FRI commitments length mismatch")]
    SumcheckFriLengthMismatch,
    #[error("Query failed to verify: {0}")]
    TcsError(<B::Tcs as TensorCs>::VerifierError),
    #[error("Sumcheck error")]
    Sumcheck,
    #[error("Invalid proof of work witness")]
    Pow,
    #[error("Query value mismatch")]
    QueryValueMismatch,
    #[error("query final polynomial mismatch")]
    QueryFinalPolyMismatch,
    #[error("sumcheck final polynomial mismatch")]
    SumcheckFinalPolyMismatch,
}

impl<B: BasefoldConfig> std::fmt::Debug for BaseFoldVerifierError<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseFoldVerifierError::SumcheckFriLengthMismatch => {
                write!(f, "sumcheck and FRI commitments length mismatch")
            }
            BaseFoldVerifierError::TcsError(e) => write!(f, "tensor opening error: {e}"),
            BaseFoldVerifierError::Sumcheck => write!(f, "sumcheck error"),
            BaseFoldVerifierError::Pow => write!(f, "invalid proof of work witness"),
            BaseFoldVerifierError::QueryValueMismatch => write!(f, "query value mismatch"),
            BaseFoldVerifierError::QueryFinalPolyMismatch => {
                write!(f, "query final polynomial mismatch")
            }
            BaseFoldVerifierError::SumcheckFinalPolyMismatch => {
                write!(f, "sumcheck final polynomial mismatch")
            }
        }
    }
}

/// A proof of a Basefold evaluation claim.
#[derive(Clone, Serialize, Deserialize)]
pub struct BasefoldProof<B: BasefoldConfig> {
    /// The univariate polynomials that are used in the sumcheck part of the BaseFold protocol.
    pub univariate_messages: Vec<[B::EF; 2]>,
    /// The FRI parts of the proof.
    /// The commitments to the folded polynomials produced in the commit phase.
    pub fri_commitments: Vec<<B::Tcs as TensorCs>::Commitment>,
    /// The query openings for the individual multilinear polynmomials.
    ///
    /// The vector is indexed by the batch number.
    pub component_polynomials_query_openings: Vec<TensorCsOpening<B::Tcs>>,
    /// The query openings and the FRI query proofs for the FRI query phase.
    pub query_phase_openings: Vec<TensorCsOpening<B::Tcs>>,
    /// The prover performs FRI until we reach a polynomial of degree 0, and return the constant
    /// value of this polynomial.
    pub final_poly: B::EF,
    /// Proof-of-work witness.
    pub pow_witness: <B::Challenger as GrindingChallenger>::Witness,
}

impl<B: BasefoldConfig> MultilinearPcsVerifier for BasefoldVerifier<B> {
    type F = B::F;
    type EF = B::EF;
    type Commitment = B::Commitment;
    type Proof = BasefoldProof<B>;
    type Challenger = B::Challenger;
    type VerifierError = BaseFoldVerifierError<B>;

    fn default_challenger(&self) -> Self::Challenger {
        B::default_challenger(self)
    }

    fn verify_trusted_evaluations(
        &self,
        commitments: &[Self::Commitment],
        point: Point<Self::EF>,
        evaluation_claims: &[Evaluations<Self::EF>],
        proof: &Self::Proof,
        challenger: &mut Self::Challenger,
    ) -> Result<(), Self::VerifierError> {
        self.verify_mle_evaluations(commitments, point, evaluation_claims, proof, challenger)
    }
}

impl<B: BasefoldConfig> BasefoldVerifier<B> {
    fn verify_mle_evaluations(
        &self,
        commitments: &[B::Commitment],
        mut point: Point<B::EF>,
        evaluation_claims: &[Evaluations<B::EF>],
        proof: &BasefoldProof<B>,
        challenger: &mut B::Challenger,
    ) -> Result<(), BaseFoldVerifierError<B>> {
        // Sample the challenge used to batch all the different polynomials.
        let batching_challenge = challenger.sample_ext_element::<B::EF>();
        // Compute the batched evaluation claim.
        let eval_claim = evaluation_claims
            .iter()
            .flat_map(|batch_claims| batch_claims.iter().flat_map(|eval| eval.iter()))
            .flatten()
            .zip(batching_challenge.powers())
            .map(|(eval, batch_power)| *eval * batch_power)
            .sum::<B::EF>();

        // Assert correctness of shape.
        if proof.fri_commitments.len() != proof.univariate_messages.len() {
            return Err(BaseFoldVerifierError::SumcheckFriLengthMismatch);
        }

        // The prover messages correspond to fixing the last coordinate first, so we reverse the
        // underlying point for the verification.
        point.reverse();

        // Sample the challenges used for FRI folding and BaseFold random linear combinations.
        let betas = proof
            .fri_commitments
            .iter()
            .zip(proof.univariate_messages.iter())
            .map(|(commitment, poly)| {
                poly.iter().copied().for_each(|x| challenger.observe_ext_element(x));
                challenger.observe(commitment.clone());
                challenger.sample_ext_element::<B::EF>()
            })
            .collect::<Vec<_>>();

        // Check the consistency of the first univariate message with the claimed evaluation. The
        // first_poly is supposed to be `vals(X_0, X_1, ..., X_{d-1}, 0), vals(X_0, X_1, ...,
        // X_{d-1}, 1)`. Given this, the claimed evaluation should be `(1 - X_d) *
        // first_poly[0] + X_d * first_poly[1]`.
        let first_poly = proof.univariate_messages[0];
        if eval_claim != (B::EF::one() - *point[0]) * first_poly[0] + *point[0] * first_poly[1] {
            return Err(BaseFoldVerifierError::Sumcheck);
        };

        // Fold the two messages into a single evaluation claim for the next round, using the
        // sampled randomness.
        let mut expected_eval = first_poly[0] + betas[0] * first_poly[1];

        // Check round-by-round consistency between the successive sumcheck univariate messages.
        for (i, (poly, beta)) in
            proof.univariate_messages[1..].iter().zip(betas[1..].iter()).enumerate()
        {
            // The check is similar to the one for `first_poly`.
            let i = i + 1;
            if expected_eval != (B::EF::one() - *point[i]) * poly[0] + *point[i] * poly[1] {
                return Err(BaseFoldVerifierError::Sumcheck);
            }

            // Fold the two pieces of the message.
            expected_eval = poly[0] + *beta * poly[1];
        }

        challenger.observe_ext_element(proof.final_poly);

        // Check proof of work (grinding to find a number that hashes to have
        // `self.config.proof_of_work_bits` zeroes at the beginning).
        if !challenger.check_witness(self.fri_config.proof_of_work_bits, proof.pow_witness) {
            return Err(BaseFoldVerifierError::Pow);
        }

        let log_len = proof.fri_commitments.len();

        // Sample query indices for the FRI query IOPP part of BaseFold. This part is very similar
        // to the corresponding part in the univariate FRI verifier.
        let query_indices = (0..self.fri_config.num_queries)
            .map(|_| challenger.sample_bits(log_len + self.fri_config.log_blowup()))
            .collect::<Vec<_>>();

        // Compute the batch evaluations from the openings of the component polynomials.
        let mut batch_evals = vec![B::EF::zero(); query_indices.len()];
        let mut batch_challenge_power = B::EF::one();
        for opening in proof.component_polynomials_query_openings.iter() {
            let values = &opening.values;
            for (batch_eval, values) in batch_evals.iter_mut().zip_eq(values.split()) {
                let beta_powers = batching_challenge.shifted_powers(batch_challenge_power);
                for (value, beta_power) in values.as_slice().iter().zip(beta_powers) {
                    *batch_eval += beta_power * *value;
                }
            }
            let count = values.get(0).unwrap().as_slice().len();
            batch_challenge_power =
                batching_challenge.shifted_powers(batch_challenge_power).nth(count).unwrap();
        }

        // Verify the proof of the claimed values.
        for (commit, opening) in
            commitments.iter().zip_eq(proof.component_polynomials_query_openings.iter())
        {
            self.tcs
                .verify_tensor_openings(commit, &query_indices, opening)
                .map_err(BaseFoldVerifierError::TcsError)?;
        }

        // Check that the query openings are consistent as FRI messages.
        self.verify_queries(
            &proof.fri_commitments,
            &query_indices,
            proof.final_poly,
            batch_evals,
            &proof.query_phase_openings,
            &betas,
        )?;

        // The final consistency check between the FRI messages and the partial evaluation messages.
        if proof.final_poly
            != proof.univariate_messages.last().unwrap()[0]
                + *betas.last().unwrap() * proof.univariate_messages.last().unwrap()[1]
        {
            return Err(BaseFoldVerifierError::SumcheckFinalPolyMismatch);
        }

        Ok(())
    }

    /// The FRI verifier for a single query. We modify this from Plonky3 to be compatible with opening
    /// only a single vector.
    fn verify_queries(
        &self,
        commitments: &[<B::Tcs as TensorCs>::Commitment],
        indices: &[usize],
        final_poly: B::EF,
        reduced_openings: Vec<B::EF>,
        query_openings: &[TensorCsOpening<B::Tcs>],
        betas: &[B::EF],
    ) -> Result<(), BaseFoldVerifierError<B>> {
        let log_max_height = commitments.len() + self.fri_config.log_blowup();

        let mut folded_evals = reduced_openings;
        let mut indices = indices.to_vec();

        let mut xis = indices
            .iter()
            .map(|index| {
                B::F::two_adic_generator(log_max_height)
                    .exp_u64(reverse_bits_len(*index, log_max_height) as u64)
            })
            .collect::<Vec<_>>();

        // TODO: replace with log_blowup here.
        assert_eq!(commitments.len(), log_max_height - 1);
        // Loop over the FRI queries.
        for ((commitment, query_opening), beta) in
            commitments.iter().zip_eq(query_openings.iter()).zip_eq(betas)
        {
            let openings = &query_opening.values;
            for (((index, folded_eval), opening), x) in indices
                .iter_mut()
                .zip_eq(folded_evals.iter_mut())
                .zip_eq(openings.split())
                .zip_eq(xis.iter_mut())
            {
                let index_sibling = *index ^ 1;
                let index_pair = *index >> 1;

                let evals: [B::EF; 2] = opening
                    .as_slice()
                    .chunks_exact(B::EF::D)
                    .map(B::EF::from_base_slice)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();

                // Check that the folded evaluation is consistent with the FRI query proof opening.
                if evals[*index % 2] != *folded_eval {
                    return Err(BaseFoldVerifierError::QueryValueMismatch);
                }

                let mut xs = [*x; 2];
                xs[index_sibling % 2] *= B::F::two_adic_generator(1);

                // interpolate and evaluate at beta
                *folded_eval =
                    evals[0] + (*beta - xs[0]) * (evals[1] - evals[0]) / B::EF::from(xs[1] - xs[0]);

                *index = index_pair;
                *x = x.square();
            }
            // Check that the opening is consistent with the commitment.
            self.tcs
                .verify_tensor_openings(commitment, &indices, query_opening)
                .map_err(BaseFoldVerifierError::TcsError)?;
        }

        for folded_eval in folded_evals {
            if folded_eval != final_poly {
                return Err(BaseFoldVerifierError::QueryFinalPolyMismatch);
            }
        }

        Ok(())
    }
}
