use std::{collections::BTreeSet, ops::Deref};

use crate::{
    basefold::{RecursiveBasefoldConfigImpl, RecursiveBasefoldVerifier},
    challenger::FieldChallengerVariable,
    jagged::RecursiveJaggedConfig,
    shard::RecursiveShardVerifier,
    sumcheck::verify_sumcheck,
    symbolic::IntoSymbolic,
    BabyBearFriConfigVariable, CircuitConfig,
};
use hypercube_recursion_compiler::{
    ir::{Config, Felt},
    prelude::{Builder, Ext, SymbolicExt},
};
use hypercube_stark::{
    air::MachineAir, Chip, ChipOpenedValues, GenericVerifierConstraintFolder, LogUpEvaluations,
    OpeningShapeError, ShardOpenedValues,
};
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::{extension::BinomialExtensionField, AbstractField};
use p3_matrix::{dense::RowMajorMatrixView, stack::VerticalPair};
use slop_multilinear::{full_geq, Mle, Point};
use slop_sumcheck::PartialSumcheckProof;

pub type RecursiveVerifierConstraintFolder<'a, C> = GenericVerifierConstraintFolder<
    'a,
    <C as Config>::F,
    <C as Config>::EF,
    Felt<<C as Config>::F>,
    Ext<<C as Config>::F, <C as Config>::EF>,
    SymbolicExt<<C as Config>::F, <C as Config>::EF>,
>;

#[allow(clippy::type_complexity)]
pub fn eval_constraints<C: CircuitConfig<F = BabyBear>, SC: BabyBearFriConfigVariable<C>, A>(
    builder: &mut Builder<C>,
    chip: &Chip<C::F, A>,
    opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
    alpha: Ext<C::F, C::EF>,
    public_values: &[Felt<C::F>],
) -> Ext<C::F, C::EF>
where
    A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
{
    let default_challenge: Ext<C::F, C::EF> = builder.constant(C::EF::default());
    let mut folder = RecursiveVerifierConstraintFolder::<C> {
        preprocessed: VerticalPair::new(
            RowMajorMatrixView::new_row(&opening.preprocessed.local),
            RowMajorMatrixView::new_row(&opening.preprocessed.local),
        ),
        main: VerticalPair::new(
            RowMajorMatrixView::new_row(&opening.main.local),
            RowMajorMatrixView::new_row(&opening.main.local),
        ),
        perm: VerticalPair::new(RowMajorMatrixView::new_row(&[]), RowMajorMatrixView::new_row(&[])),
        perm_challenges: &[],
        local_cumulative_sum: &default_challenge,
        public_values,
        is_first_row: default_challenge,
        is_last_row: default_challenge,
        is_transition: default_challenge,
        alpha,
        accumulator: SymbolicExt::zero(),
        _marker: std::marker::PhantomData,
    };

    chip.eval(&mut folder);
    builder.eval(folder.accumulator)
}

/// Compute the padded row adjustment for a chip.
pub fn compute_padded_row_adjustment<C: CircuitConfig, A>(
    builder: &mut Builder<C>,
    chip: &Chip<C::F, A>,
    alpha: Ext<C::F, C::EF>,
    public_values: &[Felt<C::F>],
) -> Ext<C::F, C::EF>
where
    A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
{
    let zero = builder.constant(C::EF::zero());
    let dummy_preprocessed_trace = vec![zero; chip.preprocessed_width()];
    let dummy_main_trace = vec![zero; chip.width()];

    let default_challenge: Ext<C::F, C::EF> = builder.constant(C::EF::default());
    let mut folder = RecursiveVerifierConstraintFolder::<C> {
        preprocessed: VerticalPair::new(
            RowMajorMatrixView::new_row(&dummy_preprocessed_trace),
            RowMajorMatrixView::new_row(&dummy_preprocessed_trace),
        ),
        main: VerticalPair::new(
            RowMajorMatrixView::new_row(&dummy_main_trace),
            RowMajorMatrixView::new_row(&dummy_main_trace),
        ),
        perm: VerticalPair::new(RowMajorMatrixView::new_row(&[]), RowMajorMatrixView::new_row(&[])),
        perm_challenges: &[],
        local_cumulative_sum: &default_challenge,
        is_first_row: default_challenge,
        is_last_row: default_challenge,
        is_transition: default_challenge,
        alpha,
        accumulator: SymbolicExt::zero(),
        public_values,
        _marker: std::marker::PhantomData,
    };

    chip.eval(&mut folder);
    builder.eval(folder.accumulator)
}

#[allow(clippy::type_complexity)]
pub fn verify_opening_shape<C: CircuitConfig, A>(
    chip: &Chip<C::F, A>,
    opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
) -> Result<(), OpeningShapeError>
where
    A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
{
    // Verify that the preprocessed width matches the expected value for the chip.
    if opening.preprocessed.local.len() != chip.preprocessed_width() {
        return Err(OpeningShapeError::PreprocessedWidthMismatch(
            chip.preprocessed_width(),
            opening.preprocessed.local.len(),
        ));
    }

    // Verify that the main width matches the expected value for the chip.
    if opening.main.local.len() != chip.width() {
        return Err(OpeningShapeError::MainWidthMismatch(chip.width(), opening.main.local.len()));
    }

    Ok(())
}

impl<C, SC, A, JC> RecursiveShardVerifier<A, SC, C, JC>
where
    C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
    SC: BabyBearFriConfigVariable<C>,
    A: MachineAir<C::F>,
    JC: RecursiveJaggedConfig<
        BatchPcsVerifier = RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
    >,
{
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    pub fn verify_zerocheck(
        &self,
        builder: &mut Builder<C>,
        shard_chips: &BTreeSet<Chip<C::F, A>>,
        opened_values: &ShardOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
        gkr_evaluations: &LogUpEvaluations<Ext<C::F, C::EF>>,
        zerocheck_proof: &PartialSumcheckProof<Ext<C::F, C::EF>>,
        public_values: &[Felt<C::F>],
        challenger: &mut SC::FriChallengerVariable,
    ) where
        A: for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    {
        let zero: Ext<C::F, C::EF> = builder.constant(C::EF::zero());
        let one: Ext<C::F, C::EF> = builder.constant(C::EF::one());
        let mut rlc_eval: Ext<C::F, C::EF> = zero;

        let alpha = challenger.sample_ext(builder);
        let gkr_batch_open_challenge: SymbolicExt<C::F, C::EF> =
            challenger.sample_ext(builder).into();
        let lambda = challenger.sample_ext(builder);

        // Get the value of eq(zeta, sumcheck's reduced point).
        let point_symbolic = <Point<Ext<C::F, C::EF>> as IntoSymbolic<C>>::as_symbolic(
            &zerocheck_proof.point_and_eval.0,
        );

        let gkr_evaluations_point = IntoSymbolic::<C>::as_symbolic(&gkr_evaluations.point);

        let zerocheck_eq_value = Mle::full_lagrange_eval(&gkr_evaluations_point, &point_symbolic);

        let zerocheck_eq_vals = vec![zerocheck_eq_value; shard_chips.len()];

        let max_elements = shard_chips
            .iter()
            .map(|chip| chip.width() + chip.preprocessed_width())
            .max()
            .unwrap_or(0);

        let gkr_batch_open_challenge_powers =
            gkr_batch_open_challenge.powers().take(max_elements).collect::<Vec<_>>();

        for ((chip, openings), zerocheck_eq_val) in
            shard_chips.iter().zip_eq(opened_values.chips.iter()).zip_eq(zerocheck_eq_vals)
        {
            // Verify the shape of the opening arguments matches the expected values.
            verify_opening_shape::<C, A>(chip, openings).unwrap();

            let dimension = zerocheck_proof.point_and_eval.0.dimension();

            assert_eq!(dimension, self.pcs_verifier.max_log_row_count);

            let mut proof_point_extended = point_symbolic.clone();
            proof_point_extended.add_dimension(zero.into());
            let degree_symbolic_ext: Point<SymbolicExt<C::F, C::EF>> =
                openings.degree.iter().map(|x| SymbolicExt::from(*x)).collect::<Point<_>>();
            degree_symbolic_ext.iter().for_each(|x| {
                builder.assert_ext_eq(*x * (*x - one), zero);
            });
            let geq_val = full_geq(&degree_symbolic_ext, &proof_point_extended);

            let padded_row_adjustment =
                compute_padded_row_adjustment(builder, chip, alpha, public_values);

            let constraint_eval =
                eval_constraints::<C, SC, A>(builder, chip, openings, alpha, public_values)
                    - padded_row_adjustment * geq_val;

            let openings_batch = openings
                .main
                .local
                .iter()
                .chain(openings.preprocessed.local.iter())
                .copied()
                .zip(
                    gkr_batch_open_challenge_powers
                        .iter()
                        .take(openings.main.local.len() + openings.preprocessed.local.len())
                        .copied(),
                )
                .map(|(opening, power)| opening * power)
                .sum::<SymbolicExt<C::F, C::EF>>();

            rlc_eval = builder
                .eval(rlc_eval * lambda + zerocheck_eq_val * (constraint_eval + openings_batch));
        }

        builder.assert_ext_eq(rlc_eval, zerocheck_proof.point_and_eval.1);

        let zerocheck_sum_modifications_from_gkr = gkr_evaluations
            .chip_openings
            .values()
            .map(|chip_evaluation| {
                chip_evaluation
                    .main_trace_evaluations
                    .deref()
                    .iter()
                    .copied()
                    .chain(
                        chip_evaluation
                            .preprocessed_trace_evaluations
                            .as_ref()
                            .iter()
                            .flat_map(|&evals| evals.deref().iter().copied()),
                    )
                    .zip(gkr_batch_open_challenge_powers.iter().copied())
                    .map(|(opening, power)| opening * power)
                    .sum::<SymbolicExt<C::F, C::EF>>()
            })
            .collect::<Vec<_>>();

        let zerocheck_sum_modification: SymbolicExt<C::F, C::EF> =
            zerocheck_sum_modifications_from_gkr
                .iter()
                .fold(zero.into(), |acc, modification| lambda * acc + *modification);

        // Verify that the rlc claim is zero.
        builder.assert_ext_eq(zerocheck_proof.claimed_sum, zerocheck_sum_modification);

        // Verify the zerocheck proof.
        verify_sumcheck::<C, SC>(builder, challenger, zerocheck_proof);

        // Observe the openings
        for opening in opened_values.chips.iter() {
            for eval in opening.preprocessed.local.iter() {
                challenger.observe_ext_element(builder, *eval);
            }
            for eval in opening.main.local.iter() {
                challenger.observe_ext_element(builder, *eval);
            }
        }
    }
}
