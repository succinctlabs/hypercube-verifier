use hypercube_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Ext, SymbolicExt},
};
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use slop_commit::Rounds;
use slop_multilinear::{Evaluations, Mle, Point};

use crate::sumcheck::evaluate_mle_ext;

use super::RecursiveMultilinearPcsVerifier;

#[derive(Clone)]
pub struct RecursiveStackedPcsVerifier<P> {
    pub recursive_pcs_verifier: P,
    pub log_stacking_height: u32,
}

pub struct RecursiveStackedPcsProof<PcsProof, F, EF> {
    pub batch_evaluations: Rounds<Evaluations<Ext<F, EF>>>,
    pub pcs_proof: PcsProof,
}

impl<
        P: RecursiveMultilinearPcsVerifier<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
    > RecursiveStackedPcsVerifier<P>
{
    pub const fn new(recursive_pcs_verifier: P, log_stacking_height: u32) -> Self {
        Self { recursive_pcs_verifier, log_stacking_height }
    }

    pub fn verify_trusted_evaluation(
        &self,
        builder: &mut Builder<P::Circuit>,
        commitments: &[P::Commitment],
        point: &Point<Ext<P::F, P::EF>>,
        proof: &RecursiveStackedPcsProof<P::Proof, P::F, P::EF>,
        evaluation_claim: SymbolicExt<P::F, P::EF>,
        challenger: &mut P::Challenger,
    ) {
        let (batch_point, stack_point) =
            point.split_at(point.dimension() - self.log_stacking_height as usize);
        let batch_evaluations =
            proof.batch_evaluations.iter().flatten().flatten().cloned().collect::<Mle<_>>();

        builder.cycle_tracker_v2_enter("rizz - evaluate_mle_ext");
        let expected_evaluation = evaluate_mle_ext(builder, batch_evaluations, batch_point)[0];
        builder.assert_ext_eq(evaluation_claim, expected_evaluation);
        builder.cycle_tracker_v2_exit();

        builder.cycle_tracker_v2_enter("rizz - verify_untrusted_evaluations");
        self.recursive_pcs_verifier.verify_untrusted_evaluations(
            builder,
            commitments,
            stack_point,
            &proof.batch_evaluations,
            &proof.pcs_proof,
            challenger,
        );
        builder.cycle_tracker_v2_exit();
    }
}
