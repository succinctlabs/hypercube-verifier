use p3_challenger::FieldChallenger;
use p3_field::AbstractField;
use serde::{Deserialize, Serialize};
use slop_multilinear::{full_geq, Evaluations, Mle, Point};
use slop_stacked::{StackedPcsProof, StackedPcsVerifier};
use slop_sumcheck::{partially_verify_sumcheck_proof, PartialSumcheckProof, SumcheckError};
use std::fmt::Debug;
use thiserror::Error;

use crate::{JaggedConfig, JaggedEvalConfig, JaggedLittlePolynomialVerifierParams};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JaggedPcsProof<C: JaggedConfig> {
    pub stacked_pcs_proof: StackedPcsProof<C::BatchPcsProof, C::EF>,
    pub sumcheck_proof: PartialSumcheckProof<C::EF>,
    pub jagged_eval_proof:
        <C::JaggedEvaluator as JaggedEvalConfig<C::F, C::EF, C::Challenger>>::JaggedEvalProof,
    pub params: JaggedLittlePolynomialVerifierParams<C::F>,
}

#[derive(Debug, Clone)]
pub struct JaggedPcsVerifier<C: JaggedConfig> {
    pub stacked_pcs_verifier: StackedPcsVerifier<C::BatchPcsVerifier>,
    pub max_log_row_count: usize,
    pub jagged_evaluator: C::JaggedEvaluator,
}

#[derive(Debug, Error)]
pub enum JaggedPcsVerifierError<EF> {
    #[error("sumcheck claim mismatch: {0} != {1}")]
    SumcheckClaimMismatch(EF, EF),
    #[error("sumcheck proof verification failed: {0}")]
    SumcheckError(SumcheckError),
    #[error("jagged evaluation proof verification failed")]
    JaggedEvalProofVerificationFailed,
    #[error("dense pcs verification failed")]
    DensePcsVerificationFailed,
    #[error("booleanity check failed")]
    BooleanityCheckFailed,
    #[error("montonicity check failed")]
    MonotonicityCheckFailed,
}

impl<C: JaggedConfig> JaggedPcsVerifier<C> {
    pub fn challenger(&self) -> C::Challenger {
        self.stacked_pcs_verifier.challenger()
    }

    pub fn verify_trusted_evaluations(
        &self,
        commitments: &[C::Commitment],
        point: Point<C::EF>,
        evaluation_claims: &[Evaluations<C::EF>],
        proof: &JaggedPcsProof<C>,
        insertion_points: &[usize],
        challenger: &mut C::Challenger,
    ) -> Result<(), JaggedPcsVerifierError<C::EF>> {
        let JaggedPcsProof { stacked_pcs_proof, sumcheck_proof, jagged_eval_proof, params } = proof;
        let num_col_variables = (params.col_prefix_sums.len() - 1).next_power_of_two().ilog2();
        let z_col = (0..num_col_variables)
            .map(|_| challenger.sample_ext_element::<C::EF>())
            .collect::<Point<_>>();

        let z_row = point;

        // Collect the claims for the different polynomials.
        let mut column_claims =
            evaluation_claims.iter().flatten().flatten().copied().collect::<Vec<_>>();

        // For each commit, Rizz needed a commitment to a vector of length a multiple of
        // 1 << self.pcs.log_stacking_height, and this is achieved by adding a single column of zeroes
        // as the last matrix of the commitment. We insert these "artificial" zeroes into the evaluation
        // claims.
        for insertion_point in insertion_points.iter().rev() {
            column_claims.insert(*insertion_point, C::EF::zero());
        }

        // Pad the column claims to the next power of two.
        column_claims.resize(column_claims.len().next_power_of_two(), C::EF::zero());

        let column_mle = Mle::from(column_claims);
        let sumcheck_claim = column_mle.blocking_eval_at(&z_col)[0];

        if sumcheck_claim != sumcheck_proof.claimed_sum {
            return Err(JaggedPcsVerifierError::SumcheckClaimMismatch(
                sumcheck_claim,
                sumcheck_proof.claimed_sum,
            ));
        }

        partially_verify_sumcheck_proof(sumcheck_proof, challenger)
            .map_err(JaggedPcsVerifierError::SumcheckError)?;

        for t_col in params.col_prefix_sums.iter() {
            for &elem in t_col.iter() {
                if elem * (C::F::one() - elem) != C::F::zero() {
                    return Err(JaggedPcsVerifierError::BooleanityCheckFailed);
                }
            }
        }

        for (t_col, next_t_col) in
            params.col_prefix_sums.iter().zip(params.col_prefix_sums.iter().skip(1))
        {
            if full_geq(t_col, next_t_col) != C::F::one() {
                return Err(JaggedPcsVerifierError::MonotonicityCheckFailed);
            }
        }

        let jagged_eval = self
            .jagged_evaluator
            .jagged_evaluation(
                params,
                &z_row,
                &z_col,
                &sumcheck_proof.point_and_eval.0,
                jagged_eval_proof,
                challenger,
            )
            .map_err(|_| JaggedPcsVerifierError::JaggedEvalProofVerificationFailed)?;

        // Compute the expected evaluation of the dense trace polynomial.
        let expected_eval = sumcheck_proof.point_and_eval.1 / jagged_eval;

        // Verify the evaluation proof.
        let evaluation_point = sumcheck_proof.point_and_eval.0.clone();
        self.stacked_pcs_verifier
            .verify_trusted_evaluation(
                commitments,
                &evaluation_point,
                stacked_pcs_proof,
                expected_eval,
                challenger,
            )
            .map_err(|_| JaggedPcsVerifierError::DensePcsVerificationFailed)?;

        Ok(())
    }
}

pub struct MachineJaggedPcsVerifier<'a, C: JaggedConfig> {
    pub jagged_pcs_verifier: &'a JaggedPcsVerifier<C>,
    pub column_counts_by_round: Vec<Vec<usize>>,
}

impl<'a, C: JaggedConfig> MachineJaggedPcsVerifier<'a, C> {
    pub fn new(
        jagged_pcs_verifier: &'a JaggedPcsVerifier<C>,
        column_counts_by_round: Vec<Vec<usize>>,
    ) -> Self {
        Self { jagged_pcs_verifier, column_counts_by_round }
    }

    pub fn verify_trusted_evaluations(
        &self,
        commitments: &[C::Commitment],
        point: Point<C::EF>,
        evaluation_claims: &[Evaluations<C::EF>],
        proof: &JaggedPcsProof<C>,
        challenger: &mut C::Challenger,
    ) -> Result<(), JaggedPcsVerifierError<C::EF>> {
        let insertion_points = self
            .column_counts_by_round
            .iter()
            .scan(0, |state, y| {
                *state += y.iter().sum::<usize>();
                Some(*state)
            })
            .collect::<Vec<_>>();

        self.jagged_pcs_verifier.verify_trusted_evaluations(
            commitments,
            point,
            evaluation_claims,
            proof,
            &insertion_points,
            challenger,
        )
    }
}
