use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    ops::Deref,
};

use itertools::Itertools;
use slop_algebra::{ExtensionField, Field};
use slop_challenger::FieldChallenger;
use slop_multilinear::{
    full_geq, partial_lagrange_blocking, Mle, MleEval, MultilinearPcsChallenger, Point,
};
use slop_sumcheck::{partially_verify_sumcheck_proof, SumcheckError};
use thiserror::Error;

use crate::{air::MachineAir, Chip};

use super::{ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof};

/// An error type for `LogUp` GKR.
#[derive(Debug, Error)]
pub enum LogupGkrVerificationError<EF> {
    /// The sumcheck claim is not consistent with the calculated one from the prover messages.
    #[error("inconsistent sumcheck claim at round {0}")]
    InconsistentSumcheckClaim(usize),
    /// Inconsistency between the calculated evaluation and the sumcheck evaluation.
    #[error("inconsistent evaluation at round {0}")]
    InconsistentEvaluation(usize),
    /// Error when verifying sumcheck proof.
    #[error("sumcheck error: {0}")]
    SumcheckError(#[from] SumcheckError),
    /// The proof shape does not match the expected one for the given number of interactions.
    #[error("invalid shape")]
    InvalidShape,
    /// The size of the first layer does not match the expected one.
    #[error("invalid first layer dimension: {0} != {1}")]
    InvalidFirstLayerDimension(u32, u32),
    /// The dimension of the last layer does not match the expected one.
    #[error("invalid last layer dimension: {0} != {1}")]
    InvalidLastLayerDimension(usize, usize),
    /// The trace point does not match the claimed opening point.
    #[error("trace point mismatch")]
    TracePointMismatch,
    /// The cumulative sum does not match the claimed one.
    #[error("cumulative sum mismatch: {0} != {1}")]
    CumulativeSumMismatch(EF, EF),
    /// The numerator evaluation does not match the expected one.
    #[error("numerator evaluation mismatch: {0} != {1}")]
    NumeratorEvaluationMismatch(EF, EF),
    /// The denominator evaluation does not match the expected one.
    #[error("denominator evaluation mismatch: {0} != {1}")]
    DenominatorEvaluationMismatch(EF, EF),
    /// The denominator guts had zero in it.
    #[error("denominator evaluation has zero value")]
    ZeroDenominator,
}

/// Verifier for `LogUp` GKR.
#[derive(Clone, Debug, Copy, Default, PartialEq, Eq, Hash)]
pub struct LogUpGkrVerifier<F, EF, A>(PhantomData<(F, EF, A)>);

impl<F, EF, A> LogUpGkrVerifier<F, EF, A>
where
    F: Field,
    EF: ExtensionField<F>,
    A: MachineAir<F>,
{
    /// Verify the `LogUp` GKR proof.
    ///
    /// # Errors
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    pub fn verify_logup_gkr(
        shard_chips: &BTreeSet<Chip<F, A>>,
        degrees: &BTreeMap<String, Point<F>>,
        alpha: EF,
        beta_seed: &Point<EF>,
        cumulative_sum: EF,
        max_log_row_count: usize,
        proof: &LogupGkrProof<EF>,
        challenger: &mut impl FieldChallenger<F>,
    ) -> Result<(), LogupGkrVerificationError<EF>> {
        let LogupGkrProof { circuit_output, round_proofs, logup_evaluations } = proof;

        let LogUpGkrOutput { numerator, denominator } = circuit_output;

        // Calculate the interaction number.
        let num_of_interactions =
            shard_chips.iter().map(|c| c.sends().len() + c.receives().len()).sum::<usize>();
        let number_of_interaction_variables = num_of_interactions.next_power_of_two().ilog2();

        let expected_size = 1 << (number_of_interaction_variables + 1);

        if numerator.guts().dimensions.sizes() != [expected_size, 1]
            || denominator.guts().dimensions.sizes() != [expected_size, 1]
        {
            return Err(LogupGkrVerificationError::InvalidShape);
        }

        // Observe the output claims.
        for (n, d) in
            numerator.guts().as_slice().iter().zip_eq(denominator.guts().as_slice().iter())
        {
            challenger.observe_ext_element(*n);
            challenger.observe_ext_element(*d);
        }

        if denominator.guts().as_slice().iter().any(slop_algebra::Field::is_zero) {
            return Err(LogupGkrVerificationError::ZeroDenominator);
        }

        // Verify that the cumulative sum matches the claimed one.
        let output_cumulative_sum = numerator
            .guts()
            .as_slice()
            .iter()
            .zip_eq(denominator.guts().as_slice().iter())
            .map(|(n, d)| *n / *d)
            .sum::<EF>();
        if output_cumulative_sum != cumulative_sum {
            return Err(LogupGkrVerificationError::CumulativeSumMismatch(
                output_cumulative_sum,
                cumulative_sum,
            ));
        }

        // Assert that the size of the first layer matches the expected one.
        let initial_number_of_variables = numerator.num_variables();
        if initial_number_of_variables != number_of_interaction_variables + 1 {
            return Err(LogupGkrVerificationError::InvalidFirstLayerDimension(
                initial_number_of_variables,
                number_of_interaction_variables + 1,
            ));
        }
        // Sample the first evaluation point.
        let first_eval_point = challenger.sample_point::<EF>(initial_number_of_variables);

        // Follow the GKR protocol layer by layer.
        let mut numerator_eval = numerator.blocking_eval_at(&first_eval_point)[0];
        let mut denominator_eval = denominator.blocking_eval_at(&first_eval_point)[0];
        let mut eval_point = first_eval_point;

        if round_proofs.len() + 1 != max_log_row_count {
            return Err(LogupGkrVerificationError::InvalidShape);
        }

        for (i, round_proof) in round_proofs.iter().enumerate() {
            // Get the batching challenge for combining the claims.
            let lambda = challenger.sample_ext_element::<EF>();
            // Check that the claimed sum is consistent with the previous round values.
            let expected_claim = numerator_eval * lambda + denominator_eval;
            if round_proof.sumcheck_proof.claimed_sum != expected_claim {
                return Err(LogupGkrVerificationError::InconsistentSumcheckClaim(i));
            }
            // Verify the sumcheck proof.
            partially_verify_sumcheck_proof(
                &round_proof.sumcheck_proof,
                challenger,
                i + number_of_interaction_variables as usize + 1,
                3,
            )?;
            // Verify that the evaluation claim is consistent with the prover messages.
            let (point, final_eval) = round_proof.sumcheck_proof.point_and_eval.clone();
            let eq_eval = Mle::full_lagrange_eval(&point, &eval_point);
            let numerator_sumcheck_eval = round_proof.numerator_0 * round_proof.denominator_1
                + round_proof.numerator_1 * round_proof.denominator_0;
            let denominator_sumcheck_eval = round_proof.denominator_0 * round_proof.denominator_1;
            let expected_final_eval =
                eq_eval * (numerator_sumcheck_eval * lambda + denominator_sumcheck_eval);
            if final_eval != expected_final_eval {
                return Err(LogupGkrVerificationError::InconsistentEvaluation(i));
            }

            // Observe the prover message.
            challenger.observe_ext_element(round_proof.numerator_0);
            challenger.observe_ext_element(round_proof.numerator_1);
            challenger.observe_ext_element(round_proof.denominator_0);
            challenger.observe_ext_element(round_proof.denominator_1);

            // Get the evaluation point for the claims of the next round.
            eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
            // Sample the last coordinate and add to the point.
            let last_coordinate = challenger.sample_ext_element::<EF>();
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
        if trace_variables != max_log_row_count {
            return Err(LogupGkrVerificationError::InvalidLastLayerDimension(
                trace_variables,
                max_log_row_count,
            ));
        }

        // Assert that the trace point is the same as the claimed opening point
        let LogUpEvaluations { point, chip_openings } = logup_evaluations;
        if point != &trace_point {
            return Err(LogupGkrVerificationError::TracePointMismatch);
        }

        let betas = partial_lagrange_blocking(beta_seed);

        // Compute the expected opening of the last layer numerator and denominator values from the
        // trace openings.
        let mut numerator_values = Vec::with_capacity(num_of_interactions);
        let mut denominator_values = Vec::with_capacity(num_of_interactions);
        let mut point_extended = point.clone();
        point_extended.add_dimension(EF::zero());
        for ((chip, openings), threshold) in
            shard_chips.iter().zip_eq(chip_openings.values()).zip_eq(degrees.values())
        {
            // Observe the opening
            if let Some(prep_eval) = openings.preprocessed_trace_evaluations.as_ref() {
                for eval in prep_eval.deref().iter() {
                    challenger.observe_ext_element(*eval);
                }
                if prep_eval.evaluations().sizes() != [chip.air.preprocessed_width()] {
                    return Err(LogupGkrVerificationError::InvalidShape);
                }
            } else if chip.air.preprocessed_width() != 0 {
                return Err(LogupGkrVerificationError::InvalidShape);
            }
            for eval in openings.main_trace_evaluations.deref().iter() {
                challenger.observe_ext_element(*eval);
            }
            if openings.main_trace_evaluations.evaluations().sizes() != [chip.air.width()] {
                return Err(LogupGkrVerificationError::InvalidShape);
            }

            if threshold.dimension() != point_extended.dimension() {
                return Err(LogupGkrVerificationError::InvalidShape);
            }

            let geq_eval = full_geq(threshold, &point_extended);
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
                    betas.as_slice(),
                );
                let padding_trace_opening =
                    MleEval::from(vec![EF::zero(); main_trace_evaluations.num_polynomials()]);
                let padding_preprocessed_opening = preprocessed_trace_evaluations
                    .as_ref()
                    .map(|eval| MleEval::from(vec![EF::zero(); eval.num_polynomials()]));
                let (padding_numerator, padding_denominator) = interaction.eval(
                    padding_preprocessed_opening.as_ref(),
                    &padding_trace_opening,
                    alpha,
                    betas.as_slice(),
                );

                let numerator_eval = real_numerator - padding_numerator * geq_eval;
                let denominator_eval =
                    real_denominator + (EF::one() - padding_denominator) * geq_eval;
                let numerator_eval = if is_send { numerator_eval } else { -numerator_eval };
                numerator_values.push(numerator_eval);
                denominator_values.push(denominator_eval);
            }
        }
        // Convert the values to a multilinear polynomials.
        // Pad the numerator values with zeros.
        numerator_values.resize(1 << interaction_point.dimension(), EF::zero());
        let numerator = Mle::from(numerator_values);
        // Pad the denominator values with ones.
        denominator_values.resize(1 << interaction_point.dimension(), EF::one());
        let denominator = Mle::from(denominator_values);

        let expected_numerator_eval = numerator.blocking_eval_at(&interaction_point)[0];
        let expected_denominator_eval = denominator.blocking_eval_at(&interaction_point)[0];
        if numerator_eval != expected_numerator_eval {
            return Err(LogupGkrVerificationError::NumeratorEvaluationMismatch(
                numerator_eval,
                expected_numerator_eval,
            ));
        }
        if denominator_eval != expected_denominator_eval {
            return Err(LogupGkrVerificationError::DenominatorEvaluationMismatch(
                denominator_eval,
                expected_denominator_eval,
            ));
        }
        Ok(())
    }
}
