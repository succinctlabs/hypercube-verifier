use hypercube_recursion_compiler::prelude::*;
use itertools::Itertools;
use std::{collections::BTreeSet, marker::PhantomData, ops::Deref};

use hypercube_recursion_compiler::ir::Builder;
use hypercube_stark::{
    air::MachineAir, Chip, ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof,
    LogupGkrRoundProof,
};
use p3_baby_bear::BabyBear;
use p3_field::{extension::BinomialExtensionField, AbstractField};
use slop_multilinear::{full_geq, Mle, MleEval, Point};

use crate::{
    challenger::FieldChallengerVariable,
    sumcheck::{evaluate_mle_ext, verify_sumcheck},
    symbolic::IntoSymbolic,
    witness::{WitnessWriter, Witnessable},
    BabyBearFriConfigVariable, CircuitConfig,
};

/// Verifier for `LogUp` GKR.
#[derive(Clone, Debug, Copy, Default, PartialEq, Eq, Hash)]
pub struct RecursiveLogUpGkrVerifier<C, SC, A>(PhantomData<(C, SC, A)>);

impl<C, SC, A> RecursiveLogUpGkrVerifier<C, SC, A>
where
    C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
    SC: BabyBearFriConfigVariable<C>,
    A: MachineAir<C::F>,
{
    /// Verify the `LogUp` GKR proof.
    ///
    /// # Errors
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    pub fn verify_logup_gkr(
        builder: &mut Builder<C>,
        shard_chips: &BTreeSet<Chip<C::F, A>>,
        degrees: &[Point<Felt<C::F>>],
        alpha: Ext<C::F, C::EF>,
        beta: Ext<C::F, C::EF>,
        cumulative_sum: SymbolicExt<C::F, C::EF>,
        max_log_row_count: usize,
        proof: &LogupGkrProof<Ext<C::F, C::EF>>,
        challenger: &mut SC::FriChallengerVariable,
    ) {
        let LogupGkrProof { circuit_output, round_proofs, logup_evaluations } = proof;

        //  TODO: compare the number of variables to total number of itneractions as read from
        // chips.
        let LogUpGkrOutput { numerator, denominator } = circuit_output;

        // Observe the output claims.
        for (n, d) in
            numerator.guts().as_slice().iter().zip_eq(denominator.guts().as_slice().iter())
        {
            challenger.observe_ext_element(builder, *n);
            challenger.observe_ext_element(builder, *d);
        }

        // Verify that the cumulative sum matches the claimed one.
        let output_cumulative_sum = numerator
            .guts()
            .as_slice()
            .iter()
            .zip_eq(denominator.guts().as_slice().iter())
            .map(|(n, d)| *n / *d)
            .sum::<SymbolicExt<C::F, C::EF>>();
        // Assert that the cumulative sum matches the claimed one.
        builder.assert_ext_eq(output_cumulative_sum, cumulative_sum);

        // Calculate the interaction number.
        let num_of_interactions =
            shard_chips.iter().map(|c| c.sends().len() + c.receives().len()).sum::<usize>();
        let number_of_interaction_variables = num_of_interactions.next_power_of_two().ilog2();

        // Assert that the size of the first layer matches the expected one.
        let initial_number_of_variables = number_of_interaction_variables + 1;
        // let initial_number_of_variables = numerator.num_variables();
        // assert_eq!(initial_number_of_variables, number_of_interaction_variables + 1);

        // Sample the first evaluation point.
        let first_eval_point = challenger.sample_point(builder, initial_number_of_variables);

        // Follow the GKR protocol layer by layer.
        let mut numerator_eval = IntoSymbolic::<C>::as_symbolic(
            &evaluate_mle_ext(builder, numerator.clone(), first_eval_point.clone())[0],
        );
        let mut denominator_eval = IntoSymbolic::<C>::as_symbolic(
            &evaluate_mle_ext(builder, denominator.clone(), first_eval_point.clone())[0],
        );
        let mut eval_point = first_eval_point;
        for round_proof in round_proofs.iter() {
            // Get the batching challenge for combining the claims.
            let lambda = challenger.sample_ext(builder);
            // Check that the claimed sum is consistent with the previous round values.
            let expected_claim = numerator_eval * lambda + denominator_eval;
            builder.assert_ext_eq(round_proof.sumcheck_proof.claimed_sum, expected_claim);

            // Verify the sumcheck proof.
            verify_sumcheck::<C, SC>(builder, challenger, &round_proof.sumcheck_proof);
            // Verify that the evaluation claim is consistent with the prover messages.
            let (point, final_eval) = round_proof.sumcheck_proof.point_and_eval.clone();
            let point = IntoSymbolic::<C>::as_symbolic(&point);
            let eval_point_symbolic = IntoSymbolic::<C>::as_symbolic(&eval_point);
            let eq_eval = Mle::full_lagrange_eval(&point, &eval_point_symbolic);
            let numerator_sumcheck_eval = round_proof.numerator_0 * round_proof.denominator_1
                + round_proof.numerator_1 * round_proof.denominator_0;
            let denominator_sumcheck_eval = round_proof.denominator_0 * round_proof.denominator_1;
            let expected_final_eval =
                eq_eval * (numerator_sumcheck_eval * lambda + denominator_sumcheck_eval);
            builder.assert_ext_eq(final_eval, expected_final_eval);

            // Observe the prover message.
            challenger.observe_ext_element(builder, round_proof.numerator_0);
            challenger.observe_ext_element(builder, round_proof.numerator_1);
            challenger.observe_ext_element(builder, round_proof.denominator_0);
            challenger.observe_ext_element(builder, round_proof.denominator_1);

            // Get the evaluation point for the claims of the next round.
            eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
            // Sample the last coordinate and add to the point.
            let last_coordinate = challenger.sample_ext(builder);
            eval_point.add_dimension_back(last_coordinate);
            // Update the evaluation of the numerator and denominator at the last coordinate.
            numerator_eval = round_proof.numerator_0
                + (round_proof.numerator_1 - round_proof.numerator_0) * last_coordinate;
            denominator_eval = round_proof.denominator_0
                + (round_proof.denominator_1 - round_proof.denominator_0) * last_coordinate;
        }

        // Verify that the last layer evaluations are consistent with the evaluations of the traces.
        let (interaction_point, trace_point) =
            eval_point.split_at(number_of_interaction_variables as usize);
        // Assert that the number of trace variables matches the expected one.
        let trace_variables = trace_point.dimension();
        assert_eq!(trace_variables, max_log_row_count);

        // Assert that the trace point is the same as the claimed opening point
        let LogUpEvaluations { point, chip_openings } = logup_evaluations;
        for (value, expected) in point.iter().zip_eq(trace_point.iter()) {
            builder.assert_ext_eq(*value, *expected);
        }

        // Compute the expected opening of the last layer numerator and denominator values from the
        // trace openings.
        let mut numerator_values =
            Vec::<SymbolicExt<C::F, C::EF>>::with_capacity(num_of_interactions);
        let mut denominator_values =
            Vec::<SymbolicExt<C::F, C::EF>>::with_capacity(num_of_interactions);
        let mut point_extended = IntoSymbolic::<C>::as_symbolic(point);

        let alpha = IntoSymbolic::<C>::as_symbolic(&alpha);
        let beta = IntoSymbolic::<C>::as_symbolic(&beta);
        point_extended.add_dimension(SymbolicExt::zero());
        for ((chip, openings), threshold) in
            shard_chips.iter().zip_eq(chip_openings.values()).zip_eq(degrees)
        {
            // Observe the opening
            if let Some(prep_eval) = openings.preprocessed_trace_evaluations.as_ref() {
                for eval in prep_eval.deref().iter() {
                    challenger.observe_ext_element(builder, *eval);
                }
            }
            for eval in openings.main_trace_evaluations.deref().iter() {
                challenger.observe_ext_element(builder, *eval);
            }
            let threshold = threshold.iter().map(|x| SymbolicExt::from(*x)).collect::<Point<_>>();
            let geq_eval = full_geq(&threshold, &point_extended);
            let ChipEvaluation { main_trace_evaluations, preprocessed_trace_evaluations } =
                openings;

            for (interaction, is_send) in chip
                .sends()
                .iter()
                .map(|s| (s, true))
                .chain(chip.receives().iter().map(|r| (r, false)))
            {
                let (real_numerator, real_denominator) = interaction.eval(
                    preprocessed_trace_evaluations.as_ref(),
                    main_trace_evaluations,
                    alpha,
                    &beta,
                );
                let padding_trace_opening =
                    MleEval::from(vec![C::F::zero(); main_trace_evaluations.num_polynomials()]);
                let padding_preprocessed_opening = preprocessed_trace_evaluations
                    .as_ref()
                    .map(|eval| MleEval::from(vec![C::F::zero(); eval.num_polynomials()]));
                let (padding_numerator, padding_denominator) = interaction.eval(
                    padding_preprocessed_opening.as_ref(),
                    &padding_trace_opening,
                    alpha,
                    &beta,
                );

                let numerator_eval = real_numerator - padding_numerator * geq_eval;
                let denominator_eval = real_denominator
                    + (SymbolicExt::<C::F, C::EF>::one() - padding_denominator) * geq_eval;
                let numerator_eval = if is_send { numerator_eval } else { -numerator_eval };
                numerator_values.push(numerator_eval);
                denominator_values.push(denominator_eval);
            }
        }
        // Convert the values to a multilinear polynomials.
        // Pad the numerator values with zeros.
        numerator_values.resize(1 << interaction_point.dimension(), SymbolicExt::zero());
        let numerator_values = numerator_values
            .into_iter()
            .map(|x| builder.eval(x))
            .collect::<Vec<Ext<C::F, C::EF>>>();
        let numerator = Mle::from(numerator_values);
        // Pad the denominator values with ones.
        denominator_values.resize(1 << interaction_point.dimension(), SymbolicExt::one());
        let denominator_values = denominator_values
            .into_iter()
            .map(|x| builder.eval(x))
            .collect::<Vec<Ext<C::F, C::EF>>>();
        let denominator = Mle::from(denominator_values);

        let expected_numerator_eval =
            evaluate_mle_ext(builder, numerator, interaction_point.clone())[0];
        let expected_denominator_eval =
            evaluate_mle_ext(builder, denominator, interaction_point.clone())[0];

        builder.assert_ext_eq(numerator_eval, expected_numerator_eval);
        builder.assert_ext_eq(denominator_eval, expected_denominator_eval);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for LogupGkrRoundProof<T> {
    type WitnessVariable = LogupGkrRoundProof<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let numerator_0 = self.numerator_0.read(builder);
        let numerator_1 = self.numerator_1.read(builder);
        let denominator_0 = self.denominator_0.read(builder);
        let denominator_1 = self.denominator_1.read(builder);
        let sumcheck_proof = self.sumcheck_proof.read(builder);
        Self::WitnessVariable {
            numerator_0,
            numerator_1,
            denominator_0,
            denominator_1,
            sumcheck_proof,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.numerator_0.write(witness);
        self.numerator_1.write(witness);
        self.denominator_0.write(witness);
        self.denominator_1.write(witness);
        self.sumcheck_proof.write(witness);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for LogUpGkrOutput<T> {
    type WitnessVariable = LogUpGkrOutput<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let numerator = self.numerator.read(builder);
        let denominator = self.denominator.read(builder);
        Self::WitnessVariable { numerator, denominator }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.numerator.write(witness);
        self.denominator.write(witness);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for ChipEvaluation<T> {
    type WitnessVariable = ChipEvaluation<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let main_trace_evaluations = self.main_trace_evaluations.read(builder);
        let preprocessed_trace_evaluations =
            self.preprocessed_trace_evaluations.as_ref().map(|mle| mle.read(builder));
        Self::WitnessVariable { main_trace_evaluations, preprocessed_trace_evaluations }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.main_trace_evaluations.write(witness);
        if let Some(mle) = self.preprocessed_trace_evaluations.as_ref() {
            mle.write(witness);
        }
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for LogUpEvaluations<T> {
    type WitnessVariable = LogUpEvaluations<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let point = self.point.read(builder);
        let chip_openings = self.chip_openings.read(builder);
        Self::WitnessVariable { point, chip_openings }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.point.write(witness);
        self.chip_openings.write(witness);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for LogupGkrProof<T> {
    type WitnessVariable = LogupGkrProof<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let circuit_output = self.circuit_output.read(builder);
        let round_proofs = self.round_proofs.read(builder);
        let logup_evaluations = self.logup_evaluations.read(builder);
        Self::WitnessVariable { circuit_output, round_proofs, logup_evaluations }
    }
    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.circuit_output.write(witness);
        self.round_proofs.write(witness);
        self.logup_evaluations.write(witness);
    }
}
