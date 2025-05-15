use std::collections::{BTreeMap, BTreeSet};

use crate::{
    basefold::{RecursiveBasefoldConfigImpl, RecursiveBasefoldProof, RecursiveBasefoldVerifier},
    challenger::{CanObserveVariable, FieldChallengerVariable},
    jagged::{
        JaggedPcsProofVariable, RecursiveJaggedConfig, RecursiveJaggedPcsVerifier,
        RecursiveMachineJaggedPcsVerifier,
    },
    logup_gkr::RecursiveLogUpGkrVerifier,
    zerocheck::RecursiveVerifierConstraintFolder,
    BabyBearFriConfigVariable, CircuitConfig,
};
use hypercube_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Felt, SymbolicExt},
    prelude::{Ext, SymbolicFelt},
};
use hypercube_recursion_executor::DIGEST_SIZE;
use hypercube_stark::{
    air::MachineAir, septic_digest::SepticDigest, ChipDimensions,
    GenericVerifierPublicValuesConstraintFolder, LogupGkrProof, Machine, MachineConfig,
    ShardOpenedValues,
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_field::{extension::BinomialExtensionField, AbstractField, TwoAdicField};
use slop_commit::Rounds;
use slop_multilinear::{Evaluations, MleEval};
use slop_sumcheck::PartialSumcheckProof;

#[allow(clippy::type_complexity)]
pub struct ShardProofVariable<
    C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
    SC: BabyBearFriConfigVariable<C> + Send + Sync,
    JC: RecursiveJaggedConfig<
        BatchPcsVerifier = RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
    >,
> {
    /// The commitments to main traces.
    pub main_commitment: SC::DigestVariable,
    /// The values of the traces at the final random point.
    pub opened_values: ShardOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
    /// The zerocheck IOP proof.
    pub zerocheck_proof: PartialSumcheckProof<Ext<C::F, C::EF>>,
    /// The public values
    pub public_values: Vec<Felt<C::F>>,
    // TODO: The `LogUp+GKR` IOP proofs.
    pub logup_gkr_proof: LogupGkrProof<Ext<C::F, C::EF>>,
    /// The chips participating in the shard.
    pub shard_chips: BTreeSet<String>,
    /// The evaluation proof.
    pub evaluation_proof: JaggedPcsProofVariable<JC>,
}

pub struct MachineVerifyingKeyVariable<
    C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
    SC: BabyBearFriConfigVariable<C>,
> {
    pub pc_start: Felt<C::F>,
    /// The starting global digest of the program, after incorporating the initial memory.
    pub initial_global_cumulative_sum: SepticDigest<Felt<C::F>>,
    /// The preprocessed commitments.
    pub preprocessed_commit: Option<SC::DigestVariable>,
    /// The preprocessed chip information.
    pub preprocessed_chip_information: BTreeMap<String, ChipDimensions>,
}
impl<C, SC> MachineVerifyingKeyVariable<C, SC>
where
    C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
    SC: BabyBearFriConfigVariable<C>,
{
    /// Hash the verifying key + prep domains into a single digest.
    /// poseidon2( commit[0..8] || pc_start || initial_global_cumulative_sum ||
    /// prep_domains[N].{log_n, .size, .shift, .g})
    pub fn hash(&self, builder: &mut Builder<C>) -> SC::DigestVariable
    where
        C::F: TwoAdicField,
        SC::DigestVariable: IntoIterator<Item = Felt<C::F>>,
    {
        let num_inputs = DIGEST_SIZE + 1 + 14; //(4 * prep_domains.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        if let Some(commit) = self.preprocessed_commit {
            inputs.extend(commit)
        }
        inputs.push(self.pc_start);
        inputs.extend(self.initial_global_cumulative_sum.0.x.0);
        inputs.extend(self.initial_global_cumulative_sum.0.y.0);
        for ChipDimensions { height, num_polynomials: _ } in
            self.preprocessed_chip_information.values()
        {
            let height = builder.eval(C::F::from_canonical_usize(*height));
            inputs.push(height);
        }
        // for domain in prep_domains {
        //     inputs.push(builder.eval(C::F::from_canonical_usize(domain.log_n)));
        //     let size = 1 << domain.log_n;
        //     inputs.push(builder.eval(C::F::from_canonical_usize(size)));
        //     let g = C::F::two_adic_generator(domain.log_n);
        //     inputs.push(builder.eval(domain.shift));
        //     inputs.push(builder.eval(g));
        // }

        SC::hash(builder, &inputs)
    }
}

/// A verifier for shard proofs.
pub struct RecursiveShardVerifier<
    A: MachineAir<C::F>,
    SC: BabyBearFriConfigVariable<C>,
    C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
    JC: RecursiveJaggedConfig<
        BatchPcsVerifier = RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
    >,
> {
    /// The machine.
    pub machine: Machine<C::F, A>,
    /// The jagged pcs verifier.
    pub pcs_verifier: RecursiveJaggedPcsVerifier<SC, C, JC>,
    pub _phantom: std::marker::PhantomData<(C, SC, A, JC)>,
}

impl<C, SC, A, JC> RecursiveShardVerifier<A, SC, C, JC>
where
    A: MachineAir<C::F>,
    SC: BabyBearFriConfigVariable<C> + MachineConfig,
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
{
    pub fn verify_shard(
        &self,
        builder: &mut Builder<C>,
        vk: &MachineVerifyingKeyVariable<C, SC>,
        proof: &ShardProofVariable<C, SC, JC>,
        challenger: &mut SC::FriChallengerVariable,
    ) where
        A: for<'b> Air<RecursiveVerifierConstraintFolder<'b, C>>,
    {
        let ShardProofVariable {
            main_commitment,
            opened_values,
            evaluation_proof,
            zerocheck_proof,
            public_values,
            shard_chips,
            logup_gkr_proof,
        } = proof;

        // Convert height bits to felts.
        let heights = opened_values.chips.iter().map(|x| x.degree.clone()).collect::<Vec<_>>();
        let mut height_felts = Vec::new();
        let two = SymbolicFelt::from_canonical_u32(2);
        for height in heights {
            let mut acc = SymbolicFelt::zero();
            // Assert max height to avoid overflow during prefix-sum-checks.
            assert!(height.len() <= 29);
            height.iter().for_each(|x| {
                acc = *x + two * acc;
            });
            height_felts.push(acc);
        }

        // Observe the public values.
        for value in public_values[0..self.machine.num_pv_elts()].iter() {
            challenger.observe(builder, *value);
        }
        // Observe the main commitment.
        challenger.observe(builder, *main_commitment);

        // Sample the permutation challenges.
        let alpha = challenger.sample_ext(builder);
        let beta = challenger.sample_ext(builder);
        // Sample the public value challenge.
        let _pv_challenge = challenger.sample_ext(builder);

        // There is no public values check in the recursion program.

        let cumulative_sum = SymbolicExt::zero();

        let shard_chips = self
            .machine
            .chips()
            .iter()
            .filter(|chip| shard_chips.contains(&chip.name()))
            .cloned()
            .collect::<BTreeSet<_>>();

        let degrees = opened_values.chips.iter().map(|x| x.degree.clone()).collect::<Vec<_>>();

        let max_log_row_count = self.pcs_verifier.max_log_row_count;

        // Verify the `LogUp` GKR proof.
        builder.cycle_tracker_v2_enter("verify-logup-gkr");
        RecursiveLogUpGkrVerifier::<C, SC, A>::verify_logup_gkr(
            builder,
            &shard_chips,
            &degrees,
            alpha,
            beta,
            cumulative_sum,
            max_log_row_count,
            logup_gkr_proof,
            challenger,
        );
        builder.cycle_tracker_v2_exit();

        // Verify the zerocheck proof.
        builder.cycle_tracker_v2_enter("verify-zerocheck");
        self.verify_zerocheck(
            builder,
            &shard_chips,
            opened_values,
            &logup_gkr_proof.logup_evaluations,
            zerocheck_proof,
            public_values,
            challenger,
        );
        builder.cycle_tracker_v2_exit();

        // Verify the opening proof.
        let (preprocessed_openings_for_proof, main_openings_for_proof): (Vec<_>, Vec<_>) = proof
            .opened_values
            .chips
            .iter()
            .map(|opening| (opening.preprocessed.clone(), opening.main.clone()))
            .unzip();

        let preprocessed_openings = preprocessed_openings_for_proof
            .iter()
            .map(|x| x.local.iter().as_slice())
            .collect::<Vec<_>>();

        let main_openings = main_openings_for_proof
            .iter()
            .map(|x| x.local.iter().copied().collect::<MleEval<_>>())
            .collect::<Evaluations<_>>();

        let filtered_preprocessed_openings = preprocessed_openings
            .clone()
            .into_iter()
            .filter(|x| !x.is_empty())
            .map(|x| x.iter().copied().collect::<MleEval<_>>())
            .collect::<Evaluations<_>>();

        let preprocessed_column_count = filtered_preprocessed_openings
            .iter()
            .map(|table_openings| table_openings.len())
            .collect::<Vec<_>>();

        let unfiltered_preprocessed_column_count = preprocessed_openings
            .iter()
            .map(|table_openings| table_openings.len())
            .collect::<Vec<_>>();

        let main_column_count =
            main_openings.iter().map(|table_openings| table_openings.len()).collect::<Vec<_>>();

        let only_has_main_commitment = vk.preprocessed_commit.is_none();

        let (commitments, column_counts, unfiltered_column_counts, openings) =
            if only_has_main_commitment {
                (
                    vec![*main_commitment],
                    vec![main_column_count.clone()],
                    vec![main_column_count],
                    Rounds { rounds: vec![main_openings] },
                )
            } else {
                (
                    vec![vk.preprocessed_commit.unwrap(), *main_commitment],
                    vec![preprocessed_column_count, main_column_count.clone()],
                    vec![unfiltered_preprocessed_column_count, main_column_count],
                    Rounds { rounds: vec![filtered_preprocessed_openings, main_openings] },
                )
            };

        let machine_jagged_verifier =
            RecursiveMachineJaggedPcsVerifier::new(&self.pcs_verifier, column_counts.clone());

        builder.cycle_tracker_v2_enter("jagged-verifier");
        let prefix_sum_felts = machine_jagged_verifier.verify_trusted_evaluations(
            builder,
            &commitments,
            zerocheck_proof.point_and_eval.0.clone(),
            &openings,
            evaluation_proof,
            challenger,
        );
        builder.cycle_tracker_v2_exit();

        let params: Vec<Vec<SymbolicFelt<C::F>>> = unfiltered_column_counts
            .iter()
            .map(|round| {
                round
                    .iter()
                    .copied()
                    .zip(height_felts.iter().copied())
                    .flat_map(|(column_count, height)| {
                        std::iter::repeat(height).take(column_count).collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        let preprocessed_count = params[0].len();
        let params = params.into_iter().flatten().collect::<Vec<_>>();

        // Verify the prefix sums (TODO: skips the padding indices for now).
        builder.cycle_tracker_v2_enter("jagged - prefix-sum-checks");
        let mut param_index = 0;
        let skip_indices = [preprocessed_count, prefix_sum_felts.len() - 1];
        prefix_sum_felts
            .iter()
            .zip(prefix_sum_felts.iter().skip(1))
            .enumerate()
            .filter(|(i, _)| !skip_indices.contains(i))
            .for_each(|(_, (x, y))| {
                let sum = *x + params[param_index];
                builder.assert_felt_eq(sum, *y);
                param_index += 1;
            });
        builder.cycle_tracker_v2_exit();
    }
}

pub type RecursiveVerifierPublicValuesConstraintFolder<'a, C> =
    GenericVerifierPublicValuesConstraintFolder<
        'a,
        <C as Config>::F,
        <C as Config>::EF,
        Felt<<C as Config>::F>,
        Ext<<C as Config>::F, <C as Config>::EF>,
        SymbolicExt<<C as Config>::F, <C as Config>::EF>,
    >;
