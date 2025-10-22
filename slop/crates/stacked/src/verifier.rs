use itertools::Itertools;
use serde::{Deserialize, Serialize};
use slop_challenger::IopCtx;
use slop_commit::Rounds;
use slop_multilinear::{Mle, MleEval, MultilinearPcsBatchVerifier, MultilinearPcsVerifier, Point};
use thiserror::Error;
#[derive(Debug, Clone)]
pub struct StackedPcsVerifier<GC, P> {
    pub pcs_verifier: P,
    pub log_stacking_height: u32,
    _marker: std::marker::PhantomData<GC>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StackedVerifierError<PcsError> {
    #[error("PCS error: {0}")]
    PcsError(PcsError),
    #[error("Batch evaluations do not match the claimed evaluations")]
    StackingError,
    #[error("Proof has incorrect shape")]
    IncorrectShape,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackedPcsProof<PcsProof, EF> {
    pub pcs_proof: PcsProof,
    pub batch_evaluations: Rounds<MleEval<EF>>,
}

impl<GC: IopCtx, P: MultilinearPcsBatchVerifier<GC>> StackedPcsVerifier<GC, P> {
    pub fn challenger(&self) -> GC::Challenger {
        self.pcs_verifier.default_challenger()
    }

    #[inline]
    pub const fn new(pcs_verifier: P, log_stacking_height: u32) -> Self {
        Self { pcs_verifier, log_stacking_height, _marker: std::marker::PhantomData }
    }

    pub fn verify_trusted_evaluation(
        &self,
        commitments: &[GC::Digest],
        round_areas: &[usize],
        point: &Point<GC::EF>,
        proof: &StackedPcsProof<P::Proof, GC::EF>,
        evaluation_claim: GC::EF,
        challenger: &mut GC::Challenger,
    ) -> Result<(), StackedVerifierError<P::VerifierError>> {
        if point.dimension() < self.log_stacking_height as usize {
            return Err(StackedVerifierError::IncorrectShape);
        }

        // Split the point into the interleaved and batched parts.
        let (batch_point, stack_point) =
            point.split_at(point.dimension() - self.log_stacking_height as usize);

        if proof.batch_evaluations.len() != round_areas.len()
            || commitments.len() != round_areas.len()
        {
            return Err(StackedVerifierError::IncorrectShape);
        }

        for (round_area, proof_evaluation_len) in
            round_areas.iter().zip_eq(proof.batch_evaluations.iter())
        {
            if !round_area.is_multiple_of(1 << self.log_stacking_height)
                || round_area >> self.log_stacking_height as usize
                    != proof_evaluation_len.num_polynomials()
            {
                return Err(StackedVerifierError::IncorrectShape);
            }
        }

        // Interpolate the batch evaluations as a multilinear polynomial.
        let batch_evaluations =
            proof.batch_evaluations.iter().flatten().cloned().collect::<Mle<_>>();

        // Verify that the climed evaluations matched the interpolated evaluations.
        let expected_evaluation = batch_evaluations.blocking_eval_at(&batch_point)[0];
        if evaluation_claim != expected_evaluation {
            return Err(StackedVerifierError::StackingError);
        }

        // Verify the PCS proof with respect to the claimed evaluations.
        // It is assumed that the multilinear batch PCS verifier checks that the number of
        // commitments is as expected.
        self.pcs_verifier
            .verify_untrusted_evaluations(
                commitments,
                stack_point,
                &proof.batch_evaluations,
                &proof.pcs_proof,
                challenger,
            )
            .map_err(StackedVerifierError::PcsError)
    }
}

impl<GC: IopCtx, P: MultilinearPcsBatchVerifier<GC>> MultilinearPcsVerifier<GC>
    for StackedPcsVerifier<GC, P>
{
    type VerifierError = StackedVerifierError<P::VerifierError>;

    fn num_expected_commitments(&self) -> usize {
        self.pcs_verifier.num_expected_commitments()
    }

    fn default_challenger(&self) -> GC::Challenger {
        self.challenger()
    }

    type Proof = StackedPcsProof<P::Proof, GC::EF>;

    fn verify_trusted_evaluation(
        &self,
        commitments: &[<GC as IopCtx>::Digest],
        round_polynomial_sizes: &[usize],
        point: Point<<GC as IopCtx>::EF>,
        evaluation_claim: <GC as IopCtx>::EF,
        proof: &Self::Proof,
        challenger: &mut <GC as IopCtx>::Challenger,
    ) -> Result<(), Self::VerifierError> {
        self.verify_trusted_evaluation(
            commitments,
            round_polynomial_sizes,
            &point,
            proof,
            evaluation_claim,
            challenger,
        )
    }
}
