use crate::{MainTraceData, ShardData};
use csl_air::air_block::BlockAir;
use csl_air::SymbolicProverFolder;
use csl_basefold::{BasefoldCudaProverComponents, DeviceGrindingChallenger};
use csl_cuda::{partial_lagrange, TaskScope, ToDevice};
use csl_jagged::JaggedAssistSumAsPolyGPUImpl;
use csl_tracegen::CudaTracegenAir;
use cslpc_basefold::{ProverCleanFriCudaProver, ProverCleanStackedPcsProverData};
use cslpc_jagged_sumcheck::{generate_jagged_sumcheck_poly, jagged_sumcheck};
use cslpc_logup_gkr::{prove_logup_gkr, Interactions};
use cslpc_merkle_tree::{SingleLayerMerkleTreeProverError, TcsProverClean};
use cslpc_tracegen::{full_tracegen_permit, main_tracegen_permit, CudaShardProverData};
use cslpc_utils::{Ext, Felt, JaggedTraceMle};
use cslpc_zerocheck::zerocheck;
use cslpc_zerocheck::CudaEvalResult;
use slop_algebra::AbstractField;
use slop_alloc::{Buffer, CanCopyFromRef, HasBackend, ToHost};
use slop_basefold::BasefoldProof;
use slop_challenger::{CanObserve, FieldChallenger, FromChallenger, IopCtx};
use slop_commit::Rounds;
use slop_futures::queue::{Worker, WorkerQueue};
use slop_jagged::{
    JaggedConfig, JaggedEvalProver, JaggedEvalSumcheckProver, JaggedLittlePolynomialProverParams,
    JaggedPcsProof, JaggedProverData, JaggedProverError,
};
use slop_multilinear::{Evaluations, Mle, MleEval, MultilinearPcsVerifier, Point};
use slop_stacked::StackedPcsProof;
use sp1_hypercube::prover::ZerocheckAir;
use sp1_hypercube::{
    air::{MachineAir, MachineProgram},
    prover::{AirProver, PreprocessedData, ProverPermit, ProverSemaphore, ProvingKey},
    Machine, MachineVerifyingKey, ShardProof,
};
use std::collections::BTreeMap;
use std::iter::once;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::{marker::PhantomData, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::Instrument;

pub trait ProverCleanProverComponents<GC: IopCtx>: Send + Sync + 'static {
    type P: TcsProverClean<GC>;
    type BC: BasefoldCudaProverComponents<GC> + Send + Sync + 'static;
    type Air: CudaTracegenAir<GC::F>
        + ZerocheckAir<Felt, Ext>
        + for<'a> BlockAir<SymbolicProverFolder<'a>>;
    type C: JaggedConfig<GC> + Send + Sync;
}
/// A prover for the hypercube STARK, given a configuration.
pub struct CudaShardProver<GC: IopCtx, PC: ProverCleanProverComponents<GC>> {
    #[allow(clippy::type_complexity)]
    pub trace_buffers: Arc<WorkerQueue<Pin<Box<[MaybeUninit<GC::F>]>>>>,
    pub max_log_row_count: u32,
    pub basefold_prover: ProverCleanFriCudaProver<GC, PC::P, GC::F>,
    pub machine: Machine<GC::F, PC::Air>,
    pub max_trace_size: usize,
    pub backend: TaskScope,
    pub all_interactions: BTreeMap<String, Arc<Interactions<GC::F, TaskScope>>>,
    pub all_zerocheck_programs: BTreeMap<String, CudaEvalResult>,
    pub _marker: PhantomData<GC>,
}

impl<GC: IopCtx<F = Felt, EF = Ext>, PC: ProverCleanProverComponents<GC>> CudaShardProver<GC, PC> {
    pub async fn get_buffer(&self) -> (usize, Worker<Pin<Box<[MaybeUninit<Felt>]>>>) {
        let mut guard = self.trace_buffers.clone().pop().await.expect("buffer pool exhausted");
        let whole: &mut [MaybeUninit<GC::F>] = Pin::get_mut(Pin::as_mut(&mut *guard));
        let base_ptr = whole.as_mut_ptr() as usize;
        (base_ptr, guard)
    }
}

impl<GC: IopCtx<F = Felt, EF = Ext>, PC: ProverCleanProverComponents<GC>>
    AirProver<GC, PC::C, PC::Air> for CudaShardProver<GC, PC>
where
    GC::Challenger: DeviceGrindingChallenger<Witness = GC::F>,
    GC::Challenger: cslpc_basefold::DeviceGrindingChallenger<Witness = GC::F>,
    GC::Challenger: slop_challenger::FieldChallenger<
        <GC::Challenger as slop_challenger::GrindingChallenger>::Witness,
    >,
    StackedPcsProof<BasefoldProof<GC>, GC::EF>:
        Into<<<PC::C as JaggedConfig<GC>>::PcsVerifier as MultilinearPcsVerifier<GC>>::Proof>,
    TaskScope: csl_jagged::BranchingProgramKernel<
        GC::F,
        GC::EF,
        <GC::Challenger as DeviceGrindingChallenger>::OnDeviceChallenger,
    >,
    <GC::Challenger as DeviceGrindingChallenger>::OnDeviceChallenger:
        FromChallenger<GC::Challenger, TaskScope> + Clone,
{
    type PreprocessedData = Mutex<CudaShardProverData<GC, PC::Air>>;

    fn machine(&self) -> &Machine<GC::F, PC::Air> {
        &self.machine
    }

    /// Setup a shard, using a verifying key if provided.
    async fn setup_from_vk(
        &self,
        program: Arc<<PC::Air as MachineAir<GC::F>>::Program>,
        vk: Option<MachineVerifyingKey<GC, PC::C>>,
        prover_permits: ProverSemaphore,
    ) -> (PreprocessedData<ProvingKey<GC, PC::C, PC::Air, Self>>, MachineVerifyingKey<GC, PC::C>)
    {
        if let Some(vk) = vk {
            let initial_global_cumulative_sum = vk.initial_global_cumulative_sum;
            self.setup_with_initial_global_cumulative_sum(
                program,
                initial_global_cumulative_sum,
                prover_permits,
            )
            .await
        } else {
            let program_sent = program.clone();
            let initial_global_cumulative_sum =
                tokio::task::spawn_blocking(move || program_sent.initial_global_cumulative_sum())
                    .await
                    .unwrap();
            self.setup_with_initial_global_cumulative_sum(
                program,
                initial_global_cumulative_sum,
                prover_permits,
            )
            .await
        }
    }

    /// Setup and prove a shard.
    async fn setup_and_prove_shard(
        &self,
        program: Arc<<PC::Air as MachineAir<GC::F>>::Program>,
        record: <PC::Air as MachineAir<GC::F>>::Record,
        vk: Option<MachineVerifyingKey<GC, PC::C>>,
        prover_permits: ProverSemaphore,
        challenger: &mut GC::Challenger,
    ) -> (MachineVerifyingKey<GC, PC::C>, ShardProof<GC, PC::C>, ProverPermit) {
        // Get the initial global cumulative sum and pc start.
        let pc_start = program.pc_start();
        let enable_untrusted_programs = program.enable_untrusted_programs();
        let initial_global_cumulative_sum = if let Some(vk) = vk {
            vk.initial_global_cumulative_sum
        } else {
            let program = program.clone();
            tokio::task::spawn_blocking(move || program.initial_global_cumulative_sum())
                .instrument(tracing::debug_span!("initial_global_cumulative_sum"))
                .await
                .unwrap()
        };

        let (base_ptr, guard) = self.get_buffer().await;

        let record = Arc::new(record);

        // Generate trace.
        let (public_values, trace_data, chip_set, permit, _) = full_tracegen_permit(
            &self.machine,
            program,
            record,
            base_ptr,
            guard,
            self.max_trace_size,
            self.basefold_prover.log_height,
            self.max_log_row_count,
            &self.backend,
            prover_permits,
        )
        .instrument(tracing::debug_span!("generate all traces"))
        .await;

        let (pk, vk) = self
            .setup_from_preprocessed_data_and_traces(
                pc_start,
                initial_global_cumulative_sum,
                trace_data,
                enable_untrusted_programs,
            )
            .instrument(tracing::debug_span!("setup_from_preprocessed_data_and_traces"))
            .await;

        let trace_data = Mutex::new(pk);

        let pk = ProvingKey { vk: vk.clone(), preprocessed_data: trace_data };

        let pk = Arc::new(pk);

        let main_trace_data =
            MainTraceData { traces: pk, public_values, shard_chips: chip_set, permit };

        // Observe the preprocessed information.
        vk.observe_into(challenger);

        let shard_data = ShardData { main_trace_data };

        let (shard_proof, permit) = self
            .prove_shard_with_data(shard_data, challenger)
            .instrument(tracing::debug_span!("prove shard with data"))
            .await;

        (vk, shard_proof, permit)
    }

    /// Prove a shard with a given proving key.
    async fn prove_shard_with_pk(
        &self,
        pk: Arc<ProvingKey<GC, PC::C, PC::Air, Self>>,
        record: <PC::Air as MachineAir<GC::F>>::Record,
        prover_permits: ProverSemaphore,
        challenger: &mut GC::Challenger,
    ) -> (ShardProof<GC, PC::C>, ProverPermit) {
        // Generate the traces.
        let record = Arc::new(record);

        let (base_ptr, guard) = self.get_buffer().await;

        let (public_values, chip_set, permit, _) = main_tracegen_permit(
            &self.machine,
            record,
            &pk.preprocessed_data,
            base_ptr,
            guard,
            self.basefold_prover.log_height,
            self.max_log_row_count,
            &self.backend,
            prover_permits,
        )
        .instrument(tracing::debug_span!("generate main traces"))
        .await;

        let shard_data = ShardData {
            main_trace_data: MainTraceData {
                traces: pk.clone(),
                public_values,
                shard_chips: chip_set,
                permit,
            },
        };

        self.prove_shard_with_data(shard_data, challenger)
            .instrument(tracing::debug_span!("prove shard with data"))
            .await
    }
}

// An error type for cuda jagged prover
#[derive(Debug, Error)]
pub enum CudaShardProverError {}

impl<GC: IopCtx<F = Felt, EF = Ext>, PC: ProverCleanProverComponents<GC>> CudaShardProver<GC, PC> {
    /// Commit to a batch of padded multilinears.
    ///
    /// The jagged polynomial commitments scheme is able to commit to sparse polynomials having
    /// very few or no real rows.
    /// **Note** the padding values will be ignored and treated as though they are zero.
    pub async fn commit_multilinears(
        &self,
        multilinears: &JaggedTraceMle<Felt, TaskScope>,
        use_preprocessed_data: bool,
    ) -> Result<
        (GC::Digest, JaggedProverData<GC, ProverCleanStackedPcsProverData<GC>>),
        JaggedProverError<SingleLayerMerkleTreeProverError>,
    > {
        cslpc_commit::commit_multilinears::<GC, PC::P>(
            multilinears,
            self.max_log_row_count,
            use_preprocessed_data,
            &self.basefold_prover,
        )
        .await
        .map_err(JaggedProverError::BatchPcsProverError)
    }

    pub async fn round_stacked_evaluations(
        &self,
        stacked_point: &Point<Ext>,
        jagged_trace_mle: &JaggedTraceMle<Felt, TaskScope>,
    ) -> Rounds<Evaluations<Ext, TaskScope>> {
        let backend = jagged_trace_mle.backend();
        let log_stacking_height = stacked_point.len();
        let stacking_height = 1 << log_stacking_height;
        let preprocessed_stacked_size =
            jagged_trace_mle.dense().preprocessed_offset / stacking_height;
        let total_preprocessed_size = stacking_height * preprocessed_stacked_size;

        let device_point = stacked_point.to_device_in(backend).await.unwrap();

        // todo: remove this assert, it's kinda useless
        assert!(total_preprocessed_size == jagged_trace_mle.dense().preprocessed_offset);
        let lagrange = Mle::new(partial_lagrange(Arc::new(device_point)).await);

        let main_virtual_tensor =
            jagged_trace_mle.dense().main_virtual_tensor(log_stacking_height as u32);

        let preprocessed_virtual_tensor =
            jagged_trace_mle.dense().preprocessed_virtual_tensor(log_stacking_height as u32);

        let preprocessed_evaluations = MleEval::new(csl_cuda::dot_along_dim_view(
            preprocessed_virtual_tensor,
            lagrange.guts().as_view(),
            1,
        ));

        let main_evaluations = MleEval::new(csl_cuda::dot_along_dim_view(
            main_virtual_tensor,
            lagrange.guts().as_view(),
            1,
        ));

        let preprocessed_evaluations =
            Evaluations { round_evaluations: vec![preprocessed_evaluations] };

        let main_evaluations = Evaluations { round_evaluations: vec![main_evaluations] };

        Rounds::from_iter([preprocessed_evaluations, main_evaluations])
    }

    /// Prove trusted evaluations.
    pub async fn prove_trusted_evaluations(
        &self,
        eval_point: Point<Ext>,
        evaluation_claims: Rounds<Evaluations<Ext, TaskScope>>,
        all_mles: &JaggedTraceMle<Felt, TaskScope>,
        prover_data: Rounds<&JaggedProverData<GC, ProverCleanStackedPcsProverData<GC>>>,
        challenger: &mut GC::Challenger,
    ) -> Result<JaggedPcsProof<GC, PC::C>, JaggedProverError<CudaShardProverError>>
    where
        GC::Challenger: DeviceGrindingChallenger<Witness = GC::F>,
        GC::Challenger: cslpc_basefold::DeviceGrindingChallenger<Witness = GC::F>,
        GC::Challenger: slop_challenger::FieldChallenger<
            <GC::Challenger as slop_challenger::GrindingChallenger>::Witness,
        >,
        StackedPcsProof<BasefoldProof<GC>, GC::EF>:
            Into<<<PC::C as JaggedConfig<GC>>::PcsVerifier as MultilinearPcsVerifier<GC>>::Proof>,
        TaskScope: csl_jagged::BranchingProgramKernel<
            GC::F,
            GC::EF,
            <GC::Challenger as DeviceGrindingChallenger>::OnDeviceChallenger,
        >,
        <GC::Challenger as DeviceGrindingChallenger>::OnDeviceChallenger:
            FromChallenger<GC::Challenger, TaskScope> + Clone,
    {
        let num_col_variables = prover_data
            .iter()
            .map(|data| data.column_counts.iter().sum::<usize>())
            .sum::<usize>()
            .next_power_of_two()
            .ilog2();
        let z_col = (0..num_col_variables)
            .map(|_| challenger.sample_ext_element::<Ext>())
            .collect::<Point<_>>();

        let z_row = eval_point.clone();

        let backend = evaluation_claims[0][0].backend().clone();

        // First, allocate a buffer for all of the column claims on device.
        let total_column_claims = evaluation_claims
            .iter()
            .map(|evals| evals.iter().map(|evals| evals.num_polynomials()).sum::<usize>())
            .sum::<usize>();

        // Add in the dummy padding columns added during the stacked PCS commitment.
        let total_len = total_column_claims
            + prover_data.iter().map(|data| data.padding_column_count).sum::<usize>();

        let mut column_claims: Buffer<Ext, TaskScope> =
            Buffer::with_capacity_in(total_len, backend.clone());

        // Then, copy the column claims from the evaluation claims into the buffer, inserting extra
        // zeros for the dummy columns.
        for (column_claim_round, data) in evaluation_claims.into_iter().zip(prover_data.iter()) {
            for column_claim in column_claim_round.into_iter() {
                column_claims
                    .extend_from_device_slice(column_claim.into_evaluations().as_buffer())?;
            }
            column_claims
                .extend_from_host_slice(vec![Ext::zero(); data.padding_column_count].as_slice())?;
        }

        assert!(prover_data
            .iter()
            .flat_map(|data| data.row_counts.iter())
            .all(|x| *x <= 1 << self.max_log_row_count));

        // Collect the jagged polynomial parameters.
        let params = JaggedLittlePolynomialProverParams::new(
            prover_data
                .iter()
                .flat_map(|data| {
                    data.row_counts
                        .iter()
                        .copied()
                        .zip(data.column_counts.iter().copied())
                        .flat_map(|(row_count, column_count)| {
                            std::iter::repeat_n(row_count, column_count)
                        })
                })
                .collect(),
            self.max_log_row_count as usize,
        );

        // Generate the jagged sumcheck proof.
        let z_row_backend = z_row.copy_into(&backend);
        let z_col_backend = z_col.copy_into(&backend);

        let eq_z_row = Mle::partial_lagrange(&z_row_backend).await;
        let eq_z_col = Mle::partial_lagrange(&z_col_backend).await;

        // The overall evaluation claim of the sparse polynomial is inferred from the individual
        // table claims.
        let column_claims: Mle<Ext, TaskScope> = Mle::from_buffer(column_claims);

        let sumcheck_claims = column_claims.eval_at(&z_col_backend).await;
        let sumcheck_claims_host = sumcheck_claims.to_host().await.unwrap();
        let sumcheck_claim = sumcheck_claims_host[0];

        let sumcheck_poly = generate_jagged_sumcheck_poly(all_mles, eq_z_col, eq_z_row);

        let (sumcheck_proof, component_poly_evals) =
            jagged_sumcheck(sumcheck_poly, challenger, sumcheck_claim)
                .instrument(tracing::debug_span!("jagged sumcheck"))
                .await;

        let final_eval_point = sumcheck_proof.point_and_eval.0.clone();

        let jagged_eval_prover: JaggedEvalSumcheckProver<
            Felt,
            JaggedAssistSumAsPolyGPUImpl<Felt, Ext, GC::Challenger>,
            _,
            _,
        > = JaggedEvalSumcheckProver::default();

        let jagged_eval_proof = jagged_eval_prover
            .prove_jagged_evaluation(
                &params,
                &z_row,
                &z_col,
                &final_eval_point,
                challenger,
                backend.clone(),
            )
            .instrument(tracing::debug_span!("jagged evaluation proof"))
            .await;

        let (row_counts, column_counts): (Rounds<_>, Rounds<_>) = prover_data
            .iter()
            .map(|data| {
                (Clone::clone(data.row_counts.as_ref()), Clone::clone(data.column_counts.as_ref()))
            })
            .unzip();

        let original_commitments: Rounds<_> =
            prover_data.iter().map(|data| data.original_commitment).collect();

        let stacked_prover_data =
            prover_data.into_iter().map(|data| &data.pcs_prover_data).collect::<Rounds<_>>();

        let final_eval_point = sumcheck_proof.point_and_eval.0.clone();

        let (_, stack_point) = final_eval_point
            .split_at(final_eval_point.dimension() - self.basefold_prover.log_height as usize);
        // let stack_point = stack_point.copy_into(&backend);

        let batch_evaluations = self.round_stacked_evaluations(&stack_point, all_mles).await;

        let mut host_batch_evaluations = Rounds::new();
        for round_evals in batch_evaluations.iter() {
            let mut host_round_evals = vec![];
            for eval in round_evals.iter() {
                let host_eval = eval.to_host().await.unwrap();
                host_round_evals.extend(host_eval);
            }
            let host_round_evals = Evaluations::new(vec![host_round_evals.into()]);
            host_batch_evaluations.push(host_round_evals);
        }

        for round in batch_evaluations.iter() {
            for claim in round.iter() {
                let host_claim = claim.to_host().await.unwrap();
                for evaluation in host_claim.iter() {
                    challenger.observe_ext_element(*evaluation);
                }
            }
        }

        let pcs_proof = self
            .basefold_prover
            .prove_trusted_evaluations_basefold(
                stack_point,
                batch_evaluations,
                all_mles,
                stacked_prover_data,
                challenger,
            )
            .await
            .unwrap();

        let row_counts_and_column_counts: Rounds<Vec<(usize, usize)>> = row_counts
            .into_iter()
            .zip(column_counts.into_iter())
            .map(|(r, c)| r.into_iter().zip(c.into_iter()).collect())
            .collect();

        let host_batch_evaluations = host_batch_evaluations
            .into_iter()
            .map(|round| round.into_iter().flatten().collect::<MleEval<_>>())
            .collect::<Rounds<_>>();

        let stacked_pcs_proof =
            StackedPcsProof { pcs_proof, batch_evaluations: host_batch_evaluations };

        Ok(JaggedPcsProof {
            pcs_proof: stacked_pcs_proof.into(),
            sumcheck_proof,
            jagged_eval_proof,
            params: params.into_verifier_params(),
            row_counts_and_column_counts,
            merkle_tree_commitments: original_commitments,
            expected_eval: component_poly_evals[0],
        })
    }

    async fn commit_traces(
        &self,
        traces: &JaggedTraceMle<GC::F, TaskScope>,
        use_preprocessed: bool,
    ) -> (GC::Digest, JaggedProverData<GC, ProverCleanStackedPcsProverData<GC>>) {
        self.commit_multilinears(traces, use_preprocessed).await.unwrap()
    }

    pub fn num_pv_elts(&self) -> usize {
        self.machine.num_pv_elts()
    }

    #[allow(clippy::type_complexity)]
    pub async fn prove_shard_with_data(
        &self,
        data: ShardData<GC, PC>,
        challenger: &mut GC::Challenger,
    ) -> (ShardProof<GC, PC::C>, ProverPermit)
    where
        GC::Challenger: DeviceGrindingChallenger<Witness = GC::F>,
        GC::Challenger: cslpc_basefold::DeviceGrindingChallenger<Witness = GC::F>,
        GC::Challenger: slop_challenger::FieldChallenger<
            <GC::Challenger as slop_challenger::GrindingChallenger>::Witness,
        >,
        StackedPcsProof<BasefoldProof<GC>, GC::EF>:
            Into<<<PC::C as JaggedConfig<GC>>::PcsVerifier as MultilinearPcsVerifier<GC>>::Proof>,
        TaskScope: csl_jagged::BranchingProgramKernel<
            GC::F,
            GC::EF,
            <GC::Challenger as DeviceGrindingChallenger>::OnDeviceChallenger,
        >,
        <GC::Challenger as DeviceGrindingChallenger>::OnDeviceChallenger:
            FromChallenger<GC::Challenger, TaskScope> + Clone,
    {
        let ShardData { main_trace_data } = data;
        let MainTraceData { traces, public_values, shard_chips, permit } = main_trace_data;

        let shard_chips = self.machine().smallest_cluster(&shard_chips).unwrap();

        // Observe the public values.
        challenger.observe_slice(&public_values);

        let locked_preprocessed_data = traces.preprocessed_data.lock().await;
        let traces = &locked_preprocessed_data.preprocessed_traces;
        let preprocessed_data = &locked_preprocessed_data.preprocessed_data;

        // Commit to the traces.
        let (main_commit, main_data) = self
            .commit_traces(traces, false)
            .instrument(tracing::debug_span!("commit traces"))
            .await;
        // Observe the commitments.
        <GC::Challenger as CanObserve<GC::Digest>>::observe(challenger, main_commit);
        challenger.observe(GC::F::from_canonical_usize(shard_chips.len()));

        for (chip_name, chip_height) in traces.dense().main_table_index.iter() {
            let chip_height = chip_height.poly_size;
            challenger.observe(GC::F::from_canonical_usize(chip_height));
            challenger.observe(GC::F::from_canonical_usize(chip_name.len()));
            for byte in chip_name.as_bytes() {
                challenger.observe(GC::F::from_canonical_u8(*byte));
            }
        }

        let max_interaction_arity = shard_chips
            .iter()
            .flat_map(|c| c.sends().iter().chain(c.receives().iter()))
            .map(|i| i.values.len() + 1)
            .max()
            .unwrap();
        let beta_seed_dim = max_interaction_arity.next_power_of_two().ilog2();

        // Sample the logup challenges.
        let alpha = challenger.sample_ext_element::<GC::EF>();

        let beta_seed = (0..beta_seed_dim)
            .map(|_| challenger.sample_ext_element::<GC::EF>())
            .collect::<Point<_>>();
        let _pv_challenge = challenger.sample_ext_element::<GC::EF>();

        let logup_gkr_proof = prove_logup_gkr(
            shard_chips,
            self.all_interactions.clone(),
            traces,
            self.max_log_row_count,
            alpha,
            beta_seed,
            challenger,
        )
        .instrument(tracing::debug_span!("logup gkr proof"))
        .await;
        // Get the challenge for batching constraints.
        let batching_challenge = challenger.sample_ext_element::<GC::EF>();
        // Get the challenge for batching the evaluations from the GKR proof.
        let gkr_opening_batch_challenge = challenger.sample_ext_element::<GC::EF>();

        // Generate the zerocheck proof.
        let (shard_open_values, zerocheck_partial_sumcheck_proof) = zerocheck(
            shard_chips,
            &self.all_zerocheck_programs,
            traces,
            batching_challenge,
            gkr_opening_batch_challenge,
            &logup_gkr_proof.logup_evaluations,
            public_values.clone(),
            challenger,
            self.max_log_row_count,
        )
        .instrument(tracing::debug_span!("zerocheck"))
        .await;

        // Get the evaluation point for the trace polynomials.
        let evaluation_point = zerocheck_partial_sumcheck_proof.point_and_eval.0.clone();
        let mut preprocessed_evaluation_claims: Option<Evaluations<GC::EF, TaskScope>> = None;
        let mut main_evaluation_claims = Evaluations::new(vec![]);

        let alloc = self.backend.clone();

        for (_, open_values) in shard_open_values.chips.iter() {
            let prep_local = &open_values.preprocessed.local;
            let main_local = &open_values.main.local;
            if !prep_local.is_empty() {
                let preprocessed_evals =
                    alloc.copy_to(&MleEval::from(prep_local.clone())).await.unwrap();
                if let Some(preprocessed_claims) = preprocessed_evaluation_claims.as_mut() {
                    preprocessed_claims.push(preprocessed_evals);
                } else {
                    let evals = Evaluations::new(vec![preprocessed_evals]);
                    preprocessed_evaluation_claims = Some(evals);
                }
            }
            let main_evals = alloc.copy_to(&MleEval::from(main_local.clone())).await.unwrap();
            main_evaluation_claims.push(main_evals);
        }

        let round_evaluation_claims = preprocessed_evaluation_claims
            .into_iter()
            .chain(once(main_evaluation_claims))
            .collect::<Rounds<_>>();

        let round_prover_data =
            once(preprocessed_data).chain(once(&main_data)).collect::<Rounds<_>>();

        // Generate the evaluation proof.
        let evaluation_proof = self
            .prove_trusted_evaluations(
                evaluation_point,
                round_evaluation_claims,
                traces,
                round_prover_data,
                challenger,
            )
            .instrument(tracing::debug_span!("prove evaluation claims"))
            .await
            .unwrap();

        let proof = ShardProof {
            main_commitment: main_commit,
            opened_values: shard_open_values,
            logup_gkr_proof,
            evaluation_proof,
            zerocheck_proof: zerocheck_partial_sumcheck_proof,
            public_values,
        };

        (proof, permit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csl_air::codegen_cuda_eval;
    use csl_cuda::run_in_place;
    use cslpc_merkle_tree::Poseidon2KoalaBear16CudaProver;
    use cslpc_tracegen::test_utils::tracegen_setup::{
        self, CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
    };
    use cslpc_tracegen::{full_tracegen, CORE_MAX_TRACE_SIZE};
    use cslpc_utils::TestGC;
    use cslpc_zerocheck::primitives::round_batch_evaluations;
    use serial_test::serial;
    use slop_basefold::{BasefoldVerifier, Poseidon2KoalaBear16BasefoldConfig};
    use slop_jagged::JaggedPcsVerifier;
    use slop_multilinear::MultilinearPcsChallenger;
    use slop_tensor::Tensor;
    use sp1_core_machine::riscv::RiscvAir;
    use sp1_hypercube::SP1CoreJaggedConfig;
    use sp1_primitives::fri_params::core_fri_config;
    use std::mem::MaybeUninit;

    pub struct ProverCleanTestProverComponentsImpl {}

    impl ProverCleanProverComponents<TestGC> for ProverCleanTestProverComponentsImpl {
        type P = Poseidon2KoalaBear16CudaProver;
        type BC = Poseidon2KoalaBear16BasefoldConfig;
        type Air = RiscvAir<Felt>;
        type C = SP1CoreJaggedConfig;
    }

    #[tokio::test]
    #[serial]
    async fn test_prove_trusted_evaluations() {
        let (machine, record, program) = tracegen_setup::setup().await;
        run_in_place(|scope| async move {
            // *********** Generate traces using the host tracegen. ***********
            let capacity = CORE_MAX_TRACE_SIZE as usize;
            let mut buffer: Vec<MaybeUninit<Felt>> = Vec::with_capacity(capacity);
            unsafe { buffer.set_len(capacity) };
            let boxed: Box<[MaybeUninit<Felt>]> = buffer.into_boxed_slice();
            let buffer = Box::into_pin(boxed);
            let (_public_values, jagged_trace_data, _shard_chips, _permit) = full_tracegen(
                &machine,
                program.clone(),
                Arc::new(record),
                buffer.as_ptr() as usize,
                CORE_MAX_TRACE_SIZE as usize,
                LOG_STACKING_HEIGHT,
                CORE_MAX_LOG_ROW_COUNT,
                &scope,
                ProverSemaphore::new(1),
            )
            .await;

            let jagged_trace_data = Arc::new(jagged_trace_data);

            let verifier = BasefoldVerifier::<TestGC>::new(core_fri_config(), 2);

            let basefold_prover = ProverCleanFriCudaProver::<TestGC, _, Felt>::new(
                Poseidon2KoalaBear16CudaProver::default(),
                verifier.fri_config,
                LOG_STACKING_HEIGHT,
            );

            let mut all_interactions = BTreeMap::new();

            for chip in machine.chips().iter() {
                let host_interactions = Interactions::new(chip.sends(), chip.receives());
                let device_interactions =
                    Interactions::to_device_in(&host_interactions, &scope).await.unwrap();
                all_interactions.insert(chip.name().to_string(), Arc::new(device_interactions));
            }

            let mut cache = BTreeMap::new();
            for chip in machine.chips().iter() {
                let result = codegen_cuda_eval(chip.air.as_ref());
                cache.insert(chip.name(), result);
            }

            let num_workers = 1;
            let mut trace_buffers = Vec::with_capacity(num_workers);
            for _ in 0..num_workers {
                let mut v: Vec<MaybeUninit<Felt>> =
                    Vec::with_capacity(CORE_MAX_TRACE_SIZE as usize);
                unsafe { v.set_len(CORE_MAX_TRACE_SIZE as usize) };
                let boxed: Box<[MaybeUninit<Felt>]> = v.into_boxed_slice();
                let pinned = Box::into_pin(boxed);
                trace_buffers.push(pinned);
            }

            let shard_prover: CudaShardProver<TestGC, ProverCleanTestProverComponentsImpl> =
                CudaShardProver {
                    trace_buffers: Arc::new(WorkerQueue::new(trace_buffers)),
                    all_interactions,
                    all_zerocheck_programs: cache,
                    max_log_row_count: CORE_MAX_LOG_ROW_COUNT,
                    basefold_prover,
                    max_trace_size: CORE_MAX_TRACE_SIZE as usize,
                    machine,
                    backend: scope.clone(),
                    _marker: PhantomData,
                };

            let mut challenger = TestGC::default_challenger();

            let eval_point = challenger.sample_point(CORE_MAX_LOG_ROW_COUNT);

            let evaluation_claims =
                round_batch_evaluations(&eval_point, jagged_trace_data.as_ref()).await;

            let (preprocessed_digest, preprocessed_prover_data) =
                shard_prover.commit_multilinears(jagged_trace_data.as_ref(), true).await.unwrap();

            let (main_digest, main_prover_data) =
                shard_prover.commit_multilinears(jagged_trace_data.as_ref(), false).await.unwrap();

            let prover_data = Rounds::from_iter([&preprocessed_prover_data, &main_prover_data]);

            let mut new_evaluation_claims = Vec::new();

            for round_evals in evaluation_claims.iter() {
                let mut round_claims = Vec::new();
                for eval in round_evals.iter() {
                    let host_eval = eval.to_device_in(&scope).await.unwrap();
                    round_claims.push(host_eval);
                }
                let evals = Evaluations::new(round_claims);
                new_evaluation_claims.push(evals);
            }

            let mut prover_challenger = challenger.clone();
            let proof = shard_prover
                .prove_trusted_evaluations(
                    eval_point.clone(),
                    new_evaluation_claims.into_iter().collect(),
                    jagged_trace_data.as_ref(),
                    prover_data,
                    &mut prover_challenger,
                )
                .await
                .unwrap();

            let jagged_verifier = JaggedPcsVerifier::<_, SP1CoreJaggedConfig>::new(
                core_fri_config(),
                LOG_STACKING_HEIGHT,
                CORE_MAX_LOG_ROW_COUNT as usize,
                2,
            );

            let mut all_evaluations = Vec::new();
            for round_evals in evaluation_claims.iter() {
                let mut host_evals = Vec::new();
                for eval in round_evals.iter() {
                    let host_eval = eval.to_host().await.unwrap();
                    host_evals.extend_from_slice(host_eval.evaluations().as_buffer().as_slice());
                }
                let buf = Buffer::from(host_evals);
                let mle_eval = MleEval::new(Tensor::from(buf));
                all_evaluations.push(mle_eval);
            }

            let mut verifier_challenger = challenger.clone();
            jagged_verifier
                .verify_trusted_evaluations(
                    &[preprocessed_digest, main_digest],
                    eval_point,
                    &all_evaluations,
                    &proof,
                    &mut verifier_challenger,
                )
                .unwrap();
        })
        .await;
    }
}
