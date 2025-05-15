use std::marker::PhantomData;

use hypercube_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Ext, Felt, SymbolicExt, SymbolicFelt},
};
use p3_baby_bear::BabyBear;
use rayon::ThreadPoolBuilder;
use slop_jagged::{
    BranchingProgram, JaggedLittlePolynomialVerifierParams, JaggedSumcheckEvalProof,
};
use slop_multilinear::{Mle, Point};

use crate::{
    sumcheck::verify_sumcheck, symbolic::IntoSymbolic, BabyBearFriConfigVariable, CircuitConfig,
};

impl<C: CircuitConfig> IntoSymbolic<C> for JaggedLittlePolynomialVerifierParams<Felt<C::F>> {
    type Output = JaggedLittlePolynomialVerifierParams<SymbolicFelt<C::F>>;

    fn as_symbolic(&self) -> Self::Output {
        JaggedLittlePolynomialVerifierParams {
            col_prefix_sums: self
                .col_prefix_sums
                .iter()
                .map(|x| <Point<Felt<C::F>> as IntoSymbolic<C>>::as_symbolic(x))
                .collect::<Vec<_>>(),
            max_log_row_count: self.max_log_row_count,
        }
    }
}

pub trait RecursiveJaggedEvalConfig<C: CircuitConfig, Chal>: Sized {
    type JaggedEvalProof;

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    #[allow(clippy::type_complexity)]
    fn jagged_evaluation(
        &self,
        builder: &mut Builder<C>,
        params: &JaggedLittlePolynomialVerifierParams<Felt<C::F>>,
        z_row: Point<Ext<C::F, C::EF>>,
        z_col: Point<Ext<C::F, C::EF>>,
        z_trace: Point<Ext<C::F, C::EF>>,
        proof: &Self::JaggedEvalProof,
        challenger: &mut Chal,
    ) -> (SymbolicExt<C::F, C::EF>, Vec<Felt<C::F>>);
}

pub struct RecursiveTrivialJaggedEvalConfig;

impl<C: CircuitConfig> RecursiveJaggedEvalConfig<C, ()> for RecursiveTrivialJaggedEvalConfig {
    type JaggedEvalProof = ();

    fn jagged_evaluation(
        &self,
        _builder: &mut Builder<C>,
        params: &JaggedLittlePolynomialVerifierParams<Felt<C::F>>,
        z_row: Point<Ext<C::F, C::EF>>,
        z_col: Point<Ext<C::F, C::EF>>,
        z_trace: Point<Ext<C::F, C::EF>>,
        _proof: &Self::JaggedEvalProof,
        _challenger: &mut (),
    ) -> (SymbolicExt<C::F, C::EF>, Vec<Felt<C::F>>) {
        let params_ef = JaggedLittlePolynomialVerifierParams {
            col_prefix_sums: params
                .col_prefix_sums
                .iter()
                .map(|x| x.iter().map(|y| SymbolicExt::from(*y)).collect())
                .collect::<Vec<_>>(),
            max_log_row_count: params.max_log_row_count,
        };
        let z_row = <Point<Ext<C::F, C::EF>> as IntoSymbolic<C>>::as_symbolic(&z_row);
        let z_col = <Point<Ext<C::F, C::EF>> as IntoSymbolic<C>>::as_symbolic(&z_col);
        let z_trace = <Point<Ext<C::F, C::EF>> as IntoSymbolic<C>>::as_symbolic(&z_trace);
        // Need to use a single threaded rayon pool.
        let pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let (result, _) = pool.install(|| {
            params_ef.full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_trace)
        });
        (result, vec![])
    }
}
pub struct RecursiveJaggedEvalSumcheckConfig<SC>(pub PhantomData<SC>);

impl<C: CircuitConfig<F = BabyBear>, SC: BabyBearFriConfigVariable<C>>
    RecursiveJaggedEvalConfig<C, SC::FriChallengerVariable>
    for RecursiveJaggedEvalSumcheckConfig<SC>
{
    type JaggedEvalProof = JaggedSumcheckEvalProof<Ext<C::F, C::EF>>;

    fn jagged_evaluation(
        &self,
        builder: &mut Builder<C>,
        params: &JaggedLittlePolynomialVerifierParams<Felt<C::F>>,
        z_row: Point<Ext<C::F, C::EF>>,
        z_col: Point<Ext<C::F, C::EF>>,
        z_trace: Point<Ext<C::F, C::EF>>,
        proof: &Self::JaggedEvalProof,
        challenger: &mut SC::FriChallengerVariable,
    ) -> (SymbolicExt<C::F, C::EF>, Vec<Felt<C::F>>) {
        let z_row = <Point<Ext<C::F, C::EF>> as IntoSymbolic<C>>::as_symbolic(&z_row);
        let z_col = <Point<Ext<C::F, C::EF>> as IntoSymbolic<C>>::as_symbolic(&z_col);
        let z_trace = <Point<Ext<C::F, C::EF>> as IntoSymbolic<C>>::as_symbolic(&z_trace);

        let JaggedSumcheckEvalProof { branching_program_evals, partial_sumcheck_proof } = proof;
        // Calculate the partial lagrange from z_col point.
        let z_col_partial_lagrange = Mle::blocking_partial_lagrange(&z_col);
        let z_col_partial_lagrange = z_col_partial_lagrange.guts().as_slice();

        // Calculate the jagged eval from the branching program eval claims.
        let jagged_eval = z_col_partial_lagrange
            .iter()
            .zip(branching_program_evals.iter())
            .map(|(partial_lagrange, branching_program_eval)| {
                *partial_lagrange * *branching_program_eval
            })
            .sum::<SymbolicExt<C::F, C::EF>>();

        // Verify the jagged eval proof.
        builder.cycle_tracker_v2_enter("jagged eval - verify sumcheck");
        verify_sumcheck::<C, SC>(builder, challenger, partial_sumcheck_proof);
        builder.cycle_tracker_v2_exit();
        let proof_point = <Point<Ext<C::F, C::EF>> as IntoSymbolic<C>>::as_symbolic(
            &partial_sumcheck_proof.point_and_eval.0,
        );
        let (first_half_z_index, second_half_z_index) =
            proof_point.split_at(proof_point.dimension() / 2);
        assert!(first_half_z_index.len() == second_half_z_index.len());

        // Compute the jagged eval sc expected eval and assert it matches the proof's eval.
        let current_column_prefix_sums = params.col_prefix_sums.iter();
        let next_column_prefix_sums = params.col_prefix_sums.iter().skip(1);
        let mut prefix_sum_felts = Vec::new();
        builder.cycle_tracker_v2_enter("jagged eval - calculate expected eval");
        let mut jagged_eval_sc_expected_eval = current_column_prefix_sums
            .zip(next_column_prefix_sums)
            .zip(z_col_partial_lagrange.iter())
            .map(|((current_column_prefix_sum, next_column_prefix_sum), z_col_eq_val)| {
                let mut merged_prefix_sum = current_column_prefix_sum.clone();
                merged_prefix_sum.extend(next_column_prefix_sum);

                let (full_lagrange_eval, felt) = C::prefix_sum_checks(
                    builder,
                    merged_prefix_sum.to_vec(),
                    partial_sumcheck_proof.point_and_eval.0.to_vec(),
                );
                prefix_sum_felts.push(felt);
                *z_col_eq_val * full_lagrange_eval
            })
            .sum::<SymbolicExt<C::F, C::EF>>();
        builder.cycle_tracker_v2_exit();
        let branching_program = BranchingProgram::new(z_row.clone(), z_trace.clone());
        jagged_eval_sc_expected_eval *=
            branching_program.eval(&first_half_z_index, &second_half_z_index);

        builder
            .assert_ext_eq(jagged_eval_sc_expected_eval, partial_sumcheck_proof.point_and_eval.1);

        (jagged_eval, prefix_sum_felts)
    }
}
