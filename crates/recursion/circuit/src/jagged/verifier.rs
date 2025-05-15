use std::marker::PhantomData;

use hypercube_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Ext, Felt, SymbolicExt},
};
use hypercube_stark::BabyBearPoseidon2;
use p3_baby_bear::BabyBear;
use p3_field::{extension::BinomialExtensionField, AbstractField};
use slop_jagged::{
    JaggedBasefoldConfig, JaggedLittlePolynomialVerifierParams, JaggedSumcheckEvalProof,
};
use slop_multilinear::{Evaluations, Mle, Point};
use slop_sumcheck::PartialSumcheckProof;

use crate::{
    basefold::{
        stacked::{RecursiveStackedPcsProof, RecursiveStackedPcsVerifier},
        RecursiveBasefoldConfigImpl, RecursiveBasefoldProof, RecursiveBasefoldVerifier,
        RecursiveMultilinearPcsVerifier,
    },
    challenger::FieldChallengerVariable,
    sumcheck::{evaluate_mle_ext, verify_sumcheck},
    AsRecursive, BabyBearFriConfigVariable, CircuitConfig,
};

use super::jagged_eval::{RecursiveJaggedEvalConfig, RecursiveJaggedEvalSumcheckConfig};

pub trait RecursiveJaggedConfig: Sized {
    type F;
    type EF: AbstractField;
    type Bit;
    type Circuit: CircuitConfig<F = Self::F, EF = Self::EF, Bit = Self::Bit>;
    type Commitment;
    type Challenger: FieldChallengerVariable<Self::Circuit, Self::Bit>;
    type BatchPcsProof;
    type BatchPcsVerifier;
    type JaggedEvaluator: RecursiveJaggedEvalConfig<
        Self::Circuit,
        Self::Challenger,
        JaggedEvalProof = Self::JaggedEvalProof,
    >;
    type JaggedEvalProof;
}

pub struct RecursiveJaggedConfigImpl<C, SC, P> {
    _marker: PhantomData<(C, SC, P)>,
}

impl<
        C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
        SC: BabyBearFriConfigVariable<C>,
        P: RecursiveMultilinearPcsVerifier<F = C::F, EF = C::EF>,
    > RecursiveJaggedConfig for RecursiveJaggedConfigImpl<C, SC, P>
{
    type F = C::F;
    type EF = C::EF;
    type Bit = C::Bit;
    type Circuit = C;
    type Commitment = SC::DigestVariable;
    type Challenger = SC::FriChallengerVariable;
    type BatchPcsProof = RecursiveBasefoldProof<RecursiveBasefoldConfigImpl<C, SC>>;
    type BatchPcsVerifier = RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>;
    type JaggedEvaluator = RecursiveJaggedEvalSumcheckConfig<SC>;
    type JaggedEvalProof = JaggedSumcheckEvalProof<Ext<C::F, C::EF>>;
}

pub struct JaggedPcsProofVariable<JC: RecursiveJaggedConfig> {
    pub params: JaggedLittlePolynomialVerifierParams<Felt<JC::F>>,
    pub sumcheck_proof: PartialSumcheckProof<Ext<JC::F, JC::EF>>,
    pub jagged_eval_proof: JC::JaggedEvalProof,
    pub stacked_pcs_proof: RecursiveStackedPcsProof<JC::BatchPcsProof, JC::F, JC::EF>,
}

impl<
        C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>, Bit = Felt<BabyBear>>,
        BC,
        E,
    > AsRecursive<C> for JaggedBasefoldConfig<BC, E>
{
    type Recursive = RecursiveJaggedConfigImpl<
        C,
        BabyBearPoseidon2,
        RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, BabyBearPoseidon2>>,
    >;
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct RecursiveJaggedPcsVerifier<
    SC: BabyBearFriConfigVariable<C>,
    C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
    JC: RecursiveJaggedConfig<
        BatchPcsVerifier = RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
    >,
> {
    pub stacked_pcs_verifier: RecursiveStackedPcsVerifier<JC::BatchPcsVerifier>,
    pub max_log_row_count: usize,
    pub jagged_evaluator: JC::JaggedEvaluator,
}

impl<
        SC: BabyBearFriConfigVariable<C>,
        C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
        JC: RecursiveJaggedConfig<
            F = C::F,
            EF = C::EF,
            Circuit = C,
            Commitment = SC::DigestVariable,
            Challenger = SC::FriChallengerVariable,
            BatchPcsProof = RecursiveBasefoldProof<RecursiveBasefoldConfigImpl<C, SC>>,
            BatchPcsVerifier = RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
        >,
    > RecursiveJaggedPcsVerifier<SC, C, JC>
{
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_trusted_evaluations(
        &self,
        builder: &mut Builder<JC::Circuit>,
        commitments: &[JC::Commitment],
        point: Point<Ext<JC::F, JC::EF>>,
        evaluation_claims: &[Evaluations<Ext<JC::F, JC::EF>>],
        proof: &JaggedPcsProofVariable<JC>,
        insertion_points: &[usize],
        challenger: &mut JC::Challenger,
    ) -> Vec<Felt<JC::F>> {
        let JaggedPcsProofVariable { stacked_pcs_proof, sumcheck_proof, jagged_eval_proof, params } =
            proof;
        let num_col_variables = (params.col_prefix_sums.len() - 1).next_power_of_two().ilog2();
        let z_col =
            (0..num_col_variables).map(|_| challenger.sample_ext(builder)).collect::<Point<_>>();

        let z_row = point;

        // Collect the claims for the different polynomials.
        let mut column_claims =
            evaluation_claims.iter().flatten().flatten().copied().collect::<Vec<_>>();

        // For each commit, Rizz needed a commitment to a vector of length a multiple of
        // 1 << self.pcs.log_stacking_height, and this is achieved by adding a single column of
        // zeroes as the last matrix of the commitment. We insert these "artificial" zeroes
        // into the evaluation claims.
        let zero_ext: Ext<JC::F, JC::EF> = builder.constant(JC::EF::zero());
        for insertion_point in insertion_points.iter().rev() {
            column_claims.insert(*insertion_point, zero_ext);
        }

        // Pad the column claims to the next power of two.
        column_claims.resize(column_claims.len().next_power_of_two(), zero_ext);

        let column_mle = Mle::from(column_claims);
        let sumcheck_claim: Ext<JC::F, JC::EF> =
            evaluate_mle_ext(builder, column_mle, z_col.clone())[0];

        builder.assert_ext_eq(sumcheck_claim, sumcheck_proof.claimed_sum);

        builder.cycle_tracker_v2_enter("jagged - verify sumcheck");
        verify_sumcheck::<C, SC>(builder, challenger, sumcheck_proof);
        builder.cycle_tracker_v2_exit();

        builder.cycle_tracker_v2_enter("jagged - jagged-eval");
        let (jagged_eval, prefix_sum_felts) = self.jagged_evaluator.jagged_evaluation(
            builder,
            params,
            z_row,
            z_col,
            sumcheck_proof.point_and_eval.0.clone(),
            jagged_eval_proof,
            challenger,
        );
        builder.cycle_tracker_v2_exit();

        // Compute the expected evaluation of the dense trace polynomial.
        let expected_eval: SymbolicExt<BabyBear, BinomialExtensionField<BabyBear, 4>> =
            sumcheck_proof.point_and_eval.1 / jagged_eval;

        // Verify the evaluation proof.
        let evaluation_point = sumcheck_proof.point_and_eval.0.clone();
        self.stacked_pcs_verifier.verify_trusted_evaluation(
            builder,
            commitments,
            &evaluation_point,
            stacked_pcs_proof,
            expected_eval,
            challenger,
        );
        prefix_sum_felts
    }
}

#[allow(dead_code)]
pub struct RecursiveMachineJaggedPcsVerifier<
    'a,
    SC: BabyBearFriConfigVariable<C>,
    C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
    JC: RecursiveJaggedConfig<
        BatchPcsVerifier = RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
    >,
> {
    pub jagged_pcs_verifier: &'a RecursiveJaggedPcsVerifier<SC, C, JC>,
    pub column_counts_by_round: Vec<Vec<usize>>,
}

impl<
        'a,
        SC: BabyBearFriConfigVariable<C>,
        C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
        JC: RecursiveJaggedConfig<
            F = C::F,
            EF = C::EF,
            Circuit = C,
            Commitment = SC::DigestVariable,
            Challenger = SC::FriChallengerVariable,
            BatchPcsProof = RecursiveBasefoldProof<RecursiveBasefoldConfigImpl<C, SC>>,
            BatchPcsVerifier = RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
        >,
    > RecursiveMachineJaggedPcsVerifier<'a, SC, C, JC>
{
    #[allow(dead_code)]
    pub fn new(
        jagged_pcs_verifier: &'a RecursiveJaggedPcsVerifier<SC, C, JC>,
        column_counts_by_round: Vec<Vec<usize>>,
    ) -> Self {
        Self { jagged_pcs_verifier, column_counts_by_round }
    }

    #[allow(dead_code)]
    pub fn verify_trusted_evaluations(
        &self,
        builder: &mut Builder<JC::Circuit>,
        commitments: &[JC::Commitment],
        point: Point<Ext<JC::F, JC::EF>>,
        evaluation_claims: &[Evaluations<Ext<JC::F, JC::EF>>],
        proof: &JaggedPcsProofVariable<JC>,
        challenger: &mut JC::Challenger,
    ) -> Vec<Felt<JC::F>> {
        let insertion_points = self
            .column_counts_by_round
            .iter()
            .scan(0, |state, y| {
                *state += y.iter().sum::<usize>();
                Some(*state)
            })
            .collect::<Vec<_>>();

        self.jagged_pcs_verifier.verify_trusted_evaluations(
            builder,
            commitments,
            point,
            evaluation_claims,
            proof,
            &insertion_points,
            challenger,
        )
    }
}
