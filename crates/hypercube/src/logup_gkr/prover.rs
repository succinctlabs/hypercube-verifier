use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    ops::Deref,
};

use futures::future::OptionFuture;
use itertools::Itertools;
use slop_algebra::{ExtensionField, Field};
use slop_alloc::{Backend, CanCopyFromRef, CanCopyIntoRef, CpuBackend, ToHost};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_multilinear::{
    Mle, MleBaseBackend, MleEvaluationBackend, MultilinearPcsChallenger, PaddedMle,
    PartialLagrangeBackend, Point, PointBackend,
};
use slop_tensor::AddAssignBackend;
use tracing::Instrument;

use crate::{air::MachineAir, prover::Traces, Chip, ChipEvaluation};

use super::{
    LogUpEvaluations, LogUpGkrCircuit, LogUpGkrOutput, LogUpGkrTraceGenerator, LogupGkrProof,
    LogupGkrRoundProof,
};

/// TODO
pub trait LogUpGkrProver<GC: IopCtx>: 'static + Send + Sync {
    /// TODO
    type A: MachineAir<GC::F>;
    /// TODO
    type B: Backend;

    /// TODO
    #[allow(clippy::too_many_arguments)]
    fn prove_logup_gkr(
        &self,
        chips: &BTreeSet<Chip<GC::F, Self::A>>,
        preprocessed_traces: Traces<GC::F, Self::B>,
        traces: Traces<GC::F, Self::B>,
        public_values: Vec<GC::F>,
        alpha: GC::EF,
        beta_seed: Point<GC::EF>,
        challenger: &mut GC::Challenger,
    ) -> impl Future<Output = LogupGkrProof<GC::EF>> + Send;
}

/// TODO
pub trait LogUpGkrRoundProver<F: Field, EF: ExtensionField<F>, Challenger, B: Backend>:
    'static + Send + Sync
{
    /// TODO
    type CircuitLayer;

    /// TODO
    fn prove_round(
        &self,
        circuit: Self::CircuitLayer,
        eval_point: &Point<EF>,
        numerator_eval: EF,
        denominator_eval: EF,
        challenger: &mut Challenger,
    ) -> impl Future<Output = LogupGkrRoundProof<EF>> + Send;
}

/// TODO
pub trait LogUpGkrProverComponents<GC: IopCtx>: 'static + Send + Sync {
    /// TODO
    type A: MachineAir<GC::F>;
    /// TODO
    type B: MleBaseBackend<GC::F>
        + MleBaseBackend<GC::EF>
        + MleEvaluationBackend<GC::F, GC::EF>
        + MleEvaluationBackend<GC::EF, GC::EF>
        + MleEvaluationBackend<GC::F, GC::F>
        + PartialLagrangeBackend<GC::EF>
        + PointBackend<GC::EF>
        + AddAssignBackend<GC::EF>
        + CanCopyIntoRef<Mle<GC::EF, Self::B>, CpuBackend, Output = Mle<GC::EF>>
        + CanCopyIntoRef<PaddedMle<GC::F, Self::B>, CpuBackend, Output = PaddedMle<GC::F>>;

    /// TODO
    type CircuitLayer: 'static + Send + Sync;
    /// TODO
    type Circuit: LogUpGkrCircuit<CircuitLayer = Self::CircuitLayer> + 'static + Send + Sync;

    /// TODO
    type TraceGenerator: LogUpGkrTraceGenerator<
        GC::F,
        GC::EF,
        Self::A,
        Self::B,
        Circuit = Self::Circuit,
    >;

    /// TODO
    type RoundProver: LogUpGkrRoundProver<
        GC::F,
        GC::EF,
        GC::Challenger,
        Self::B,
        CircuitLayer = Self::CircuitLayer,
    >;
}

/// TODO
pub struct GkrProverImpl<GC: IopCtx, GkrComponents: LogUpGkrProverComponents<GC>> {
    /// TODO
    trace_generator: GkrComponents::TraceGenerator,
    /// TODO
    round_prover: GkrComponents::RoundProver,
}

/// TODO
impl<GC: IopCtx, GkrComponents: LogUpGkrProverComponents<GC>> GkrProverImpl<GC, GkrComponents> {
    /// TODO
    pub fn new(
        trace_generator: GkrComponents::TraceGenerator,
        round_prover: GkrComponents::RoundProver,
    ) -> Self {
        Self { trace_generator, round_prover }
    }

    /// TODO
    pub async fn prove_gkr_circuit(
        &self,
        numerator_value: GC::EF,
        denominator_value: GC::EF,
        eval_point: Point<GC::EF>,
        mut circuit: GkrComponents::Circuit,
        challenger: &mut GC::Challenger,
    ) -> (Point<GC::EF>, Vec<LogupGkrRoundProof<GC::EF>>) {
        let mut round_proofs = Vec::new();
        // Follow the GKR protocol layer by layer.
        let mut numerator_eval = numerator_value;
        let mut denominator_eval = denominator_value;
        let mut eval_point = eval_point;
        while let Some(layer) = circuit.next().await {
            let round_proof = self
                .round_prover
                .prove_round(layer, &eval_point, numerator_eval, denominator_eval, challenger)
                .await;
            // Observe the prover message.
            challenger.observe_ext_element(round_proof.numerator_0);
            challenger.observe_ext_element(round_proof.numerator_1);
            challenger.observe_ext_element(round_proof.denominator_0);
            challenger.observe_ext_element(round_proof.denominator_1);
            // Get the evaluation point for the claims of the next round.
            eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
            // Sample the last coordinate.
            let last_coordinate = challenger.sample_ext_element::<GC::EF>();
            // Compute the evaluation of the numerator and denominator at the last coordinate.
            numerator_eval = round_proof.numerator_0
                + (round_proof.numerator_1 - round_proof.numerator_0) * last_coordinate;
            denominator_eval = round_proof.denominator_0
                + (round_proof.denominator_1 - round_proof.denominator_0) * last_coordinate;
            eval_point.add_dimension_back(last_coordinate);
            // Add the round proof to the total
            round_proofs.push(round_proof);
        }
        (eval_point, round_proofs)
    }
}

impl<GC: IopCtx, GkrComponents: LogUpGkrProverComponents<GC>> LogUpGkrProver<GC>
    for GkrProverImpl<GC, GkrComponents>
{
    type A = GkrComponents::A;
    type B = GkrComponents::B;

    async fn prove_logup_gkr(
        &self,
        chips: &BTreeSet<Chip<GC::F, Self::A>>,
        preprocessed_traces: Traces<GC::F, Self::B>,
        traces: Traces<GC::F, Self::B>,
        public_values: Vec<GC::F>,
        alpha: GC::EF,
        beta_seed: Point<GC::EF>,
        challenger: &mut GC::Challenger,
    ) -> LogupGkrProof<GC::EF> {
        let num_interactions =
            chips.iter().map(|chip| chip.sends().len() + chip.receives().len()).sum::<usize>();
        let num_interaction_variables = num_interactions.next_power_of_two().ilog2();

        #[cfg(sp1_debug_constraints)]
        {
            use crate::{
                air::InteractionScope, debug_interactions_with_all_chips, InteractionKind,
            };

            let mut host_preprocessed_traces = BTreeMap::new();

            for (name, preprocessed_trace) in preprocessed_traces.iter() {
                let host_preprocessed_trace =
                    Self::B::copy_to_dst(&CpuBackend, preprocessed_trace).await.unwrap();
                host_preprocessed_traces.insert(name.clone(), host_preprocessed_trace);
            }

            let mut host_traces = BTreeMap::new();
            for (name, trace) in traces.iter() {
                let host_trace = Self::B::copy_to_dst(&CpuBackend, trace).await.unwrap();
                host_traces.insert(name.clone(), host_trace);
            }

            let host_traces = Traces { named_traces: host_traces };

            let host_preprocessed_traces = Traces { named_traces: host_preprocessed_traces };

            debug_interactions_with_all_chips::<GC::F, Self::A>(
                &chips.iter().cloned().collect::<Vec<_>>(),
                &host_preprocessed_traces,
                &host_traces,
                public_values.clone(),
                InteractionKind::all_kinds(),
                InteractionScope::Local,
            );
        }

        // Run the GKR circuit and get the output.
        let (output, circuit) = self
            .trace_generator
            .generate_gkr_circuit(
                chips,
                preprocessed_traces.clone(),
                traces.clone(),
                public_values,
                alpha,
                beta_seed,
            )
            .instrument(tracing::info_span!("generate GKR circuit"))
            .await;

        let LogUpGkrOutput { numerator, denominator } = &output;

        let host_numerator = numerator.to_host().await.unwrap();
        let host_denominator = denominator.to_host().await.unwrap();
        // Observe the output claims.
        for (n, d) in host_numerator
            .guts()
            .as_slice()
            .iter()
            .zip_eq(host_denominator.guts().as_slice().iter())
        {
            challenger.observe_ext_element(*n);
            challenger.observe_ext_element(*d);
        }
        let output_host =
            LogUpGkrOutput { numerator: host_numerator, denominator: host_denominator };

        // TODO: instead calculate from number of interactions.
        let initial_number_of_variables = numerator.num_variables();
        assert_eq!(initial_number_of_variables, num_interaction_variables + 1);
        let first_eval_point = challenger.sample_point::<GC::EF>(initial_number_of_variables);

        // Follow the GKR protocol layer by layer.
        let first_point = numerator.backend().copy_to(&first_eval_point).await.unwrap();
        let first_point_eq = Mle::partial_lagrange(&first_point).await;
        let first_numerator_eval =
            numerator.eval_at_eq(&first_point_eq).await.to_host().await.unwrap()[0];
        let first_denominator_eval =
            denominator.eval_at_eq(&first_point_eq).await.to_host().await.unwrap()[0];

        let (eval_point, round_proofs) = self
            .prove_gkr_circuit(
                first_numerator_eval,
                first_denominator_eval,
                first_eval_point,
                circuit,
                challenger,
            )
            .instrument(tracing::info_span!("prove GKR circuit"))
            .await;

        // Get the evaluations for each chip at the evaluation point of the last round.
        let mut chip_evaluations = BTreeMap::new();

        let trace_dimension = traces.values().next().unwrap().num_variables();
        let eval_point = eval_point.last_k(trace_dimension as usize);
        let eval_point_b = numerator.backend().copy_to(&eval_point).await.unwrap();
        let eval_point_eq = Mle::partial_lagrange(&eval_point_b).await;

        for chip in chips.iter() {
            let name = chip.name();
            let main_trace = traces.get(&name).unwrap();
            let preprocessed_trace = preprocessed_traces.get(&name);

            let main_evaluation = main_trace.eval_at_eq(&eval_point, &eval_point_eq).await;
            let preprocessed_evaluation = OptionFuture::from(
                preprocessed_trace.as_ref().map(|t| t.eval_at_eq(&eval_point, &eval_point_eq)),
            )
            .await;
            let main_evaluation = main_evaluation.to_host().await.unwrap();
            let preprocessed_evaluation = OptionFuture::from(
                preprocessed_evaluation.as_ref().map(|e| async { e.to_host().await.unwrap() }),
            )
            .await;
            let openings = ChipEvaluation {
                main_trace_evaluations: main_evaluation,
                preprocessed_trace_evaluations: preprocessed_evaluation,
            };
            // Observe the openings.
            if let Some(prep_eval) = openings.preprocessed_trace_evaluations.as_ref() {
                for eval in prep_eval.deref().iter() {
                    challenger.observe_ext_element(*eval);
                }
            }
            for eval in openings.main_trace_evaluations.deref().iter() {
                challenger.observe_ext_element(*eval);
            }

            chip_evaluations.insert(name, openings);
        }

        let logup_evaluations =
            LogUpEvaluations { point: eval_point, chip_openings: chip_evaluations };

        LogupGkrProof { circuit_output: output_host, round_proofs, logup_evaluations }
    }
}
