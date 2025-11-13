use std::{collections::BTreeSet, sync::Arc};

use anyhow::anyhow;
use slop_air::BaseAir;
use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_futures::pipeline::{
    AsyncEngine, AsyncWorker, Chain, Pipeline, SubmitError, SubmitHandle,
};
use sp1_core_executor::{
    events::{PrecompileEvent, SyscallEvent},
    ExecutionRecord, Program, SP1CoreOpts, SplitOpts,
};
use sp1_core_machine::{executor::trace_chunk, riscv::RiscvAir};
use sp1_hypercube::{
    air::MachineAir,
    prover::{CoreProofShape, MachineProvingKey, ProverSemaphore},
    Machine, MachineProof, MachineVerifier, SP1RecursionProof, ShardProof,
};
use sp1_jit::TraceChunk;
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_prover_types::{
    await_scoped_vec, network_base_types::ProofMode, Artifact, ArtifactClient, ArtifactType,
};
use sp1_recursion_circuit::shard::RecursiveShardVerifier;
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_executor::RecursionProgram;
use tokio::{sync::OnceCell, task::JoinHandle};
use tracing::Instrument;

use crate::{
    components::CoreProver,
    recursion::{normalize_program_from_input, recursive_verifier},
    shapes::{SP1NormalizeCache, SP1NormalizeInputShape, SP1RecursionProofShape},
    worker::{
        AirProverWorker, CommonProverInput, DeferredEvents, GlobalMemoryShard,
        PrecompileArtifactSlice, ProofId, ProverMetrics, RawTaskRequest, SP1RecursionProver,
        TaskContext, TaskError, TaskId, TaskMetadata, TraceData, WorkerClient,
    },
    CoreSC, InnerSC, SP1CircuitWitness, SP1ProverComponents, SP1VerifyingKey,
};

pub struct SetupTask {
    pub id: TaskId,
    pub elf: Artifact,
    pub output: Artifact,
}

pub struct ProveShardTaskRequest {
    /// The elf artifact.
    pub elf: Artifact,
    /// The common input artifact.
    pub common_input: Artifact,
    /// The record artifact.
    pub record: Artifact,
    /// The traces output artifact.
    pub output: Artifact,
    /// The deferred marker task id.
    pub deferred_marker_task: Artifact,
    /// The deferred output artifact.
    pub deferred_output: Artifact,
    /// The task context.
    pub context: TaskContext,
}

impl ProveShardTaskRequest {
    pub fn from_raw(request: RawTaskRequest) -> Result<Self, TaskError> {
        let RawTaskRequest { inputs, outputs, context } = request;
        let elf = inputs[0].clone();
        let common_input = inputs[1].clone();
        let record = inputs[2].clone();
        let deferred_marker_task = inputs[3].clone();

        let output = outputs[0].clone();
        let deferred_output = outputs[1].clone();

        Ok(ProveShardTaskRequest {
            elf,
            common_input,
            record,
            output,
            deferred_marker_task,
            deferred_output,
            context,
        })
    }

    pub fn into_raw(self) -> Result<RawTaskRequest, TaskError> {
        let ProveShardTaskRequest {
            elf,
            common_input,
            record,
            output,
            deferred_marker_task,
            deferred_output,
            context,
        } = self;

        let inputs = vec![elf, common_input, record, deferred_marker_task];
        let outputs = vec![output, deferred_output];
        let raw_task_request = RawTaskRequest { inputs, outputs, context };
        Ok(raw_task_request)
    }
}

/// Generates traces and optionally deferred records for a core shard.
pub struct TracingTask {
    /// The proof id.
    pub proof_id: ProofId,
    /// The elf artifact.
    pub elf: Artifact,
    /// The common input artifact.
    pub common_input: Artifact,
    /// The record artifact.
    pub record: Artifact,
    /// The traces output artifact.
    pub output: Artifact,
    /// The deferred marker task id.
    pub deferred_marker_task: Artifact,
    /// The deferred output artifact.
    pub deferred_output: Artifact,
    /// The metrics for the prover.
    pub metrics: ProverMetrics,
}

struct NormalizeProgramCompiler {
    cache: SP1NormalizeCache,
    recursive_verifier: RecursiveShardVerifier<SP1GlobalContext, RiscvAir<SP1Field>, InnerConfig>,
    reduce_shape: SP1RecursionProofShape,
    verifier: MachineVerifier<SP1GlobalContext, CoreSC, RiscvAir<SP1Field>>,
}

impl NormalizeProgramCompiler {
    pub fn new(
        cache: SP1NormalizeCache,
        recursive_verifier: RecursiveShardVerifier<
            SP1GlobalContext,
            RiscvAir<SP1Field>,
            InnerConfig,
        >,

        reduce_shape: SP1RecursionProofShape,
        machine_verifier: MachineVerifier<SP1GlobalContext, CoreSC, RiscvAir<SP1Field>>,
    ) -> Self {
        Self { cache, recursive_verifier, reduce_shape, verifier: machine_verifier }
    }

    pub fn machine(&self) -> &Machine<SP1Field, RiscvAir<SP1Field>> {
        self.verifier.machine()
    }

    pub fn get_program(
        &self,
        vk: SP1VerifyingKey,
        proof_shape: &CoreProofShape<SP1Field, RiscvAir<SP1Field>>,
    ) -> Arc<RecursionProgram<SP1Field>> {
        let shape = SP1NormalizeInputShape {
            proof_shapes: vec![proof_shape.clone()],
            max_log_row_count: self.verifier.max_log_row_count(),
            log_blowup: self.verifier.fri_config().log_blowup,
            log_stacking_height: self.verifier.log_stacking_height() as usize,
        };
        if let Some(program) = self.cache.get(&shape) {
            return program.clone();
        }

        let input = shape.dummy_input(vk);
        let mut program = normalize_program_from_input(&self.recursive_verifier, &input);
        program.shape = Some(self.reduce_shape.shape.clone());
        let program = Arc::new(program);
        self.cache.push(shape, program.clone());
        program
    }
}

pub struct TracingWorker<A, W> {
    normalize_program_compiler: Arc<NormalizeProgramCompiler>,
    opts: SP1CoreOpts,
    artifact_client: A,
    worker_client: W,
}

impl<A, W> TracingWorker<A, W> {
    fn new(
        normalize_program_compiler: Arc<NormalizeProgramCompiler>,
        opts: SP1CoreOpts,
        artifact_client: A,
        worker_client: W,
    ) -> Self {
        Self { normalize_program_compiler, opts, artifact_client, worker_client }
    }
}

impl<A, W> TracingWorker<A, W> {
    pub fn machine(&self) -> &Machine<SP1Field, RiscvAir<SP1Field>> {
        self.normalize_program_compiler.machine()
    }
}

impl<A, W> AsyncWorker<TracingTask, Result<CoreProveTask, TaskError>> for TracingWorker<A, W>
where
    A: ArtifactClient,
    W: WorkerClient,
{
    async fn call(&self, input: TracingTask) -> Result<CoreProveTask, TaskError> {
        // Save the trace input artifact for later use in the task
        let record_artifact = input.record.clone();
        // Ok to panic because it will send a JoinError.
        let (elf, common_input, record) = tokio::try_join!(
            self.artifact_client.download_program(&input.elf),
            self.artifact_client.download::<CommonProverInput>(&input.common_input),
            self.artifact_client.download::<TraceData>(&input.record),
        )?;

        // Extract precompile artifacts before moving input
        let precompile_artifacts = if let TraceData::Precompile(ref artifacts, _) = record {
            Some(artifacts.clone())
        } else {
            None
        };

        let span = tracing::debug_span!("into_record");
        let (program, mut record, deferred_record) = tokio::task::spawn_blocking({
            let artifact_client = self.artifact_client.clone();
            let opts = self.opts.clone();
            move || {
                let _guard = span.enter();
                {
                    let program = Program::from(&elf).map_err(|e| {
                        TaskError::Fatal(anyhow::anyhow!("failed to disassemble program: {}", e))
                    })?;
                    let program = Arc::new(program);
                    let (record, deferred_record) = match record {
                        TraceData::Core(chunk_bytes) => {
                            let chunk: TraceChunk =
                                bincode::deserialize(&chunk_bytes).map_err(|e| {
                                    TaskError::Fatal(anyhow::anyhow!(
                                        "failed to deserialize chunk: {}",
                                        e
                                    ))
                                })?;
                            tracing::debug!(
                                "tracing chunk at clk range: {}..{}",
                                chunk.clk_start,
                                chunk.clk_end
                            );
                            let record = tracing::info_span!("allocating record").in_scope(|| {
                                ExecutionRecord::new_preallocated(
                                    program.clone(),
                                    common_input.nonce,
                                )
                            });
                            let (_, mut record, _) = trace_chunk::<SP1Field>(
                                program.clone(),
                                opts.clone(),
                                chunk,
                                common_input.nonce,
                                record,
                            )
                            .map_err(|e| {
                                TaskError::Fatal(anyhow::anyhow!("failed to trace chunk: {}", e))
                            })?;

                            let deferred_record = record.defer(&opts.retained_events_presets);

                            (record, Some(deferred_record))
                        }
                        TraceData::Memory(shard) => {
                            tracing::debug!("global memory shard");
                            let GlobalMemoryShard {
                                final_state,
                                initialize_events,
                                finalize_events,
                                previous_init_addr,
                                previous_finalize_addr,
                                previous_init_page_idx,
                                previous_finalize_page_idx,
                                last_init_addr,
                                last_finalize_addr,
                                last_init_page_idx,
                                last_finalize_page_idx,
                            } = *shard;
                            let mut record =
                                ExecutionRecord::new(program.clone(), common_input.nonce);
                            record.global_memory_initialize_events = initialize_events;
                            record.global_memory_finalize_events = finalize_events;

                            let enable_untrusted_programs =
                                common_input.vk.vk.enable_untrusted_programs == SP1Field::one();

                            // Update the public values
                            record.public_values.update_finalized_state(
                                final_state.timestamp,
                                final_state.pc,
                                final_state.exit_code,
                                enable_untrusted_programs as u32,
                                final_state.public_value_digest,
                                common_input.deferred_digest,
                                final_state.proof_nonce,
                            );
                            // Update previous init and finalize addresses and page indices from the
                            // oracle values received from the controller.
                            record.public_values.previous_init_addr = previous_init_addr;
                            record.public_values.previous_finalize_addr = previous_finalize_addr;
                            record.public_values.previous_init_page_idx = previous_init_page_idx;
                            record.public_values.previous_finalize_page_idx =
                                previous_finalize_page_idx;

                            // Update last init and finalize addresses and page indices from the
                            // events of the shard.
                            record.public_values.last_init_addr = last_init_addr;
                            record.public_values.last_finalize_addr = last_finalize_addr;
                            record.public_values.last_init_page_idx = last_init_page_idx;
                            record.public_values.last_finalize_page_idx = last_finalize_page_idx;

                            record.finalize_public_values::<SP1Field>(false);
                            (record, None)
                        }
                        TraceData::Precompile(artifacts, code) => {
                            tracing::debug!("precompile events: code {}", code);
                            let mut main_record =
                                ExecutionRecord::new(program.clone(), common_input.nonce);

                            // [start, end)
                            let mut total_events = 0;
                            let mut indices = Vec::new();
                            for artifact_slice in artifacts.iter() {
                                let PrecompileArtifactSlice { start_idx, end_idx, .. } =
                                    artifact_slice;
                                indices.push(total_events);
                                total_events += end_idx - start_idx;
                            }

                            main_record
                                .precompile_events
                                .events
                                .insert(code, Vec::with_capacity(total_events));

                            // Download all artifacts at once.
                            let mut futures = Vec::new();
                            for artifact_slice in &artifacts {
                                let PrecompileArtifactSlice { artifact, .. } = artifact_slice;
                                let client = artifact_client.clone();
                                futures.push(async move {
                                    client
                                        .download::<Vec<(SyscallEvent, PrecompileEvent)>>(artifact)
                                        .await
                                });
                            }

                            // TODO: Better error handling here?
                            let results = futures::executor::block_on(await_scoped_vec(futures))
                                .map_err(|e| {
                                    TaskError::Fatal(anyhow::anyhow!(
                                        "failed to download precompile events: {}",
                                        e
                                    ))
                                })?;

                            for (i, events) in results.into_iter().enumerate() {
                                // TODO: unwrap
                                let events = events.unwrap();
                                let PrecompileArtifactSlice { start_idx, end_idx, .. } =
                                    artifacts[i];
                                main_record
                                    .precompile_events
                                    .events
                                    .get_mut(&code)
                                    .unwrap()
                                    .append(
                                        &mut events
                                            .into_iter()
                                            .skip(start_idx)
                                            .take(end_idx - start_idx)
                                            .collect(),
                                    );
                            }

                            // Set the precompile shard's public values to the initialized state.
                            main_record.public_values.update_initialized_state(
                                program.pc_start_abs,
                                program.enable_untrusted_programs,
                            );

                            (main_record, None)
                        }
                    };

                    Ok::<_, TaskError>((program, record, deferred_record))
                }
            }
        })
        .await
        .map_err(|e| TaskError::Fatal(e.into()))??;

        // Asynchronously upload the deferred record
        let deferred_upload_handle = deferred_record.map(|deferred_record| {
            let artifact_client = self.artifact_client.clone();
            let worker_client = self.worker_client.clone();
            let output_artifact = input.deferred_output.clone();
            let deferred_marker_task = TaskId::new(input.deferred_marker_task.clone().to_id());
            let opts = self.opts.clone();
            let program = program.clone();
            tokio::spawn(
                async move {
                    let split_opts = SplitOpts::new(&opts, program.instructions.len(), false);
                    let deferred_data =
                        DeferredEvents::defer_record(deferred_record, &artifact_client, split_opts)
                            .await?;

                    artifact_client.upload(&output_artifact, &deferred_data).await?;
                    worker_client
                        .complete_task(
                            input.proof_id,
                            deferred_marker_task,
                            TaskMetadata::default(),
                        )
                        .await?;
                    Ok::<(), TaskError>(())
                }
                .instrument(tracing::debug_span!("deferred upload")),
            )
        });

        // Generate dependencies on the main record.
        let span = tracing::info_span!("generate dependencies");
        let machine_clone = self.machine().clone();
        let record = tokio::task::spawn_blocking(move || {
            let _guard = span.enter();
            let record_iter = std::iter::once(&mut record);
            machine_clone.generate_dependencies(record_iter, None);
            record
        })
        .await
        .map_err(|e| TaskError::Fatal(e.into()))?;

        // If this is not a Core proof request, spawn a task to get the recursion program.
        let span = tracing::info_span!("get recursion program");
        let recursion_program_handle = if common_input.mode != ProofMode::Core {
            let handle = tokio::task::spawn_blocking({
                let normalize_program_compiler = self.normalize_program_compiler.clone();
                let vk = common_input.vk.clone();
                let shape = shape_from_record(&normalize_program_compiler.verifier, &record)
                    .ok_or_else(|| {
                        TaskError::Fatal(anyhow::anyhow!("failed to get shape from record"))
                    })?;
                move || {
                    let _guard = span.enter();
                    normalize_program_compiler.get_program(vk, &shape)
                }
            });
            Some(handle)
        } else {
            None
        };

        Ok(CoreProveTask {
            program,
            recursion_program_handle,
            common_input,
            record,
            output: input.output,
            record_artifact,
            precompile_artifacts,
            deferred_upload_handle,
            metrics: input.metrics,
        })
    }
}

pub struct CoreProveTask {
    program: Arc<Program>,
    recursion_program_handle: Option<tokio::task::JoinHandle<Arc<RecursionProgram<SP1Field>>>>,
    common_input: CommonProverInput,
    record: ExecutionRecord,
    output: Artifact,
    record_artifact: Artifact,
    precompile_artifacts: Option<Vec<PrecompileArtifactSlice>>,
    deferred_upload_handle: Option<JoinHandle<std::result::Result<(), TaskError>>>,
    metrics: ProverMetrics,
}

pub enum SP1CoreShardProof {
    Core(ShardProof<SP1GlobalContext, CoreSC>),
    Recursion(SP1RecursionProof<SP1GlobalContext, InnerSC>),
}

pub struct CoreProveOutput {
    pub id: TaskId,
    pub proof: SP1CoreShardProof,
}

pub type CoreProvingKey<C> =
    MachineProvingKey<SP1GlobalContext, <C as SP1ProverComponents>::CoreComponents>;

/// The Core Proving Key cache is initialized once and shared across all CoreProverWorkers.
pub type CoreProvingKeyCache<C> = Arc<OnceCell<Arc<CoreProvingKey<C>>>>;

pub struct CoreProverWorker<A, C: SP1ProverComponents> {
    artifact_client: A,
    core_prover: Arc<CoreProver<C>>,
    recursion_prover: SP1RecursionProver<A, C>,
    permits: ProverSemaphore,
    /// Optional fixed PK cache shared across workers.
    /// When Some, workers will use get_or_init to ensure only one does setup.
    /// The Arc is needed because OnceCell doesn't implement Clone.
    pk: Option<CoreProvingKeyCache<C>>,
    verify_intermediates: bool,
}

impl<A, C: SP1ProverComponents> CoreProverWorker<A, C> {
    pub fn new(
        artifact_client: A,
        core_prover: Arc<CoreProver<C>>,
        recursion_prover: SP1RecursionProver<A, C>,
        permits: ProverSemaphore,
        pk: Option<CoreProvingKeyCache<C>>,
        verify_intermediates: bool,
    ) -> Self {
        Self { artifact_client, core_prover, recursion_prover, permits, pk, verify_intermediates }
    }
}

impl<A: ArtifactClient, C: SP1ProverComponents>
    AsyncWorker<Result<CoreProveTask, TaskError>, Result<TaskMetadata, TaskError>>
    for CoreProverWorker<A, C>
{
    async fn call(
        &self,
        input: Result<CoreProveTask, TaskError>,
    ) -> Result<TaskMetadata, TaskError> {
        let input = input?;
        let CoreProveTask {
            program,
            recursion_program_handle,
            common_input,
            record,
            output,
            record_artifact,
            precompile_artifacts,
            deferred_upload_handle,
            metrics,
        } = input;
        let mut challenger = SP1GlobalContext::default_challenger();

        let permits = self.permits.clone();

        let (proof, permit) = if let Some(pk_cache) = &self.pk {
            // We have a fixed PK cache - use get_or_init to ensure only one worker does setup
            let pk = pk_cache
                .get_or_init(|| async {
                    tracing::info!("Initializing fixed PK cache");
                    let (pk, _vk) = self
                        .core_prover
                        .setup(program.clone(), permits.clone())
                        .instrument(tracing::debug_span!("core setup"))
                        .await;
                    pk
                })
                .await;

            tracing::debug!("Using fixed PK");
            pk.vk.observe_into(&mut challenger);
            self.core_prover
                .prove_shard_with_pk(pk.clone(), record, permits, &mut challenger)
                .instrument(tracing::debug_span!("core prove with pk"))
                .await
        } else {
            // No fixed PK cache - always do setup and prove
            let (_, proof, permit) = self
                .core_prover
                .setup_and_prove_shard(
                    program.clone(),
                    record,
                    Some(common_input.vk.vk.clone()),
                    permits,
                    &mut challenger,
                )
                .instrument(tracing::debug_span!("core setup and prove"))
                .await;
            (proof, permit)
        };
        // Release the permit and update the metrics
        let duration = permit.release();
        metrics.increment_permit_time(duration);

        let vk_clone = common_input.vk.vk.clone();
        let proof_clone = proof.clone();

        let maybe_verify_future = if self.verify_intermediates {
            Some(tokio::spawn(async move {
                let machine_proof = MachineProof::from(vec![proof_clone]);
                C::core_verifier()
                    .verify(&vk_clone, &machine_proof)
                    .map_err(|e| TaskError::Retryable(anyhow!("shard verification failed: {e}")))
            }))
        } else {
            None
        };

        if common_input.mode != ProofMode::Core {
            let program = recursion_program_handle
                .ok_or_else(|| {
                    TaskError::Fatal(anyhow::anyhow!("recursion program handle not found"))
                })?
                .await
                .map_err(|e| TaskError::Fatal(e.into()))?;
            let input = self.recursion_prover.get_normalize_witness(&common_input, &proof, false);
            let witness = SP1CircuitWitness::Core(input);
            self.recursion_prover
                .submit_prove_shard(program, witness, output, metrics.clone())
                .instrument(tracing::debug_span!("normalize prove shard"))
                .await?
                .await
                .map_err(|e| TaskError::Fatal(e.into()))??;
        } else {
            // Upload the proof
            self.artifact_client.upload(&output, proof).await?;
        }

        // Remove the record artifact since it is no longer needed
        self.artifact_client
            .try_delete(&record_artifact, ArtifactType::UnspecifiedArtifactType)
            .await?;

        // Remove task reference for precompile artifacts only at successful completion
        if let Some(artifacts) = precompile_artifacts {
            for range in artifacts {
                let PrecompileArtifactSlice { artifact, start_idx, end_idx } = range;
                let _ = self
                    .artifact_client
                    .remove_ref(
                        &artifact,
                        ArtifactType::UnspecifiedArtifactType,
                        &format!("{}_{}", start_idx, end_idx),
                    )
                    .await;
            }
        }

        if let Some(deferred_upload_handle) = deferred_upload_handle {
            deferred_upload_handle.await.map_err(|e| TaskError::Fatal(e.into()))??;
        }

        if let Some(maybe_verify_future) = maybe_verify_future {
            maybe_verify_future.await.map_err(|e| TaskError::Retryable(e.into()))??;
        }

        // Get the metadata
        let metadata = metrics.to_metadata();
        Ok(metadata)
    }
}

impl<A: ArtifactClient, C: SP1ProverComponents>
    AsyncWorker<SetupTask, Result<(TaskId, TaskMetadata), TaskError>> for CoreProverWorker<A, C>
{
    async fn call(&self, input: SetupTask) -> Result<(TaskId, TaskMetadata), TaskError> {
        let SetupTask { id, elf, output } = input;

        let elf = self.artifact_client.download_program(&elf).await?;

        let program = Program::from(&elf)?;
        let program = Arc::new(program);

        let permits = self.permits.clone();
        let (_pk, vk) = self.core_prover.setup(program, permits).await;
        tracing::info!("Setup completed for task {}", id);

        // Upload the vk
        self.artifact_client.upload(&output, vk).await.expect("failed to upload vk");
        tracing::info!("Upload completed for artifact {}", output.to_id());

        // TODO: Add the busy time here.
        Ok((id, TaskMetadata::default()))
    }
}

pub type SetupEngine<A, P> =
    Arc<AsyncEngine<SetupTask, Result<(TaskId, TaskMetadata), TaskError>, CoreProverWorker<A, P>>>;

pub type TraceEngine<A, W> =
    Arc<AsyncEngine<TracingTask, Result<CoreProveTask, TaskError>, TracingWorker<A, W>>>;
pub type CoreProveEngine<A, P> = Arc<
    AsyncEngine<
        Result<CoreProveTask, TaskError>,
        Result<TaskMetadata, TaskError>,
        CoreProverWorker<A, P>,
    >,
>;
pub type SP1CoreEngine<A, W, P> = Chain<TraceEngine<A, W>, CoreProveEngine<A, P>>;

pub type CoreProveSubmitHandle<A, W, C> = SubmitHandle<SP1CoreEngine<A, W, C>>;

pub type SetupSubmitHandle<A, C> = SubmitHandle<SetupEngine<A, C>>;

pub struct SP1CoreProver<A, W, C: SP1ProverComponents> {
    prove_shard_engine: Arc<SP1CoreEngine<A, W, C>>,
    setup_engine: SetupEngine<A, C>,
}

impl<A: ArtifactClient, W: WorkerClient, C: SP1ProverComponents> Clone for SP1CoreProver<A, W, C> {
    fn clone(&self) -> Self {
        Self {
            prove_shard_engine: self.prove_shard_engine.clone(),
            setup_engine: self.setup_engine.clone(),
        }
    }
}

impl<A: ArtifactClient, W: WorkerClient, C: SP1ProverComponents> SP1CoreProver<A, W, C> {
    pub async fn submit_prove_shard(
        &self,
        task: RawTaskRequest,
    ) -> Result<CoreProveSubmitHandle<A, W, C>, TaskError> {
        let task = ProveShardTaskRequest::from_raw(task)?;
        let ProveShardTaskRequest {
            elf,
            common_input,
            record,
            output,
            deferred_marker_task,
            deferred_output,
            context,
        } = task;

        let metrics = ProverMetrics::new();
        let tracing_task = TracingTask {
            proof_id: context.proof_id,
            elf,
            common_input,
            record,
            output,
            deferred_marker_task,
            deferred_output,
            metrics,
        };
        let handle = self.prove_shard_engine.submit(tracing_task).await?;
        Ok(handle)
    }

    pub async fn submit_setup(
        &self,
        task: SetupTask,
    ) -> Result<SetupSubmitHandle<A, C>, SubmitError> {
        self.setup_engine.submit(task).await
    }
}

/// Configuration for the core prover.
#[derive(Clone)]
pub struct SP1CoreProverConfig {
    /// The number of trace executor workers.
    pub num_trace_executor_workers: usize,
    /// The buffer size for the trace executor.
    pub trace_executor_buffer_size: usize,
    /// The number of core prover workers.
    pub num_core_prover_workers: usize,
    /// The buffer size for the core prover.
    pub core_prover_buffer_size: usize,
    /// The number of setup workers
    pub num_setup_workers: usize,
    /// The buffer size for the setup.
    pub setup_buffer_size: usize,
    /// The size of the normalize program cache.
    pub normalize_program_cache_size: usize,
    /// Whether to use a fixed public key.
    pub use_fixed_pk: bool,
    /// Whether to verify intermediates.
    pub verify_intermediates: bool,
}

impl<A: ArtifactClient, W: WorkerClient, C: SP1ProverComponents> SP1CoreProver<A, W, C> {
    pub fn new(
        config: SP1CoreProverConfig,
        opts: SP1CoreOpts,
        artifact_client: A,
        worker_client: W,
        air_prover: Arc<CoreProver<C>>,
        permits: ProverSemaphore,
        recursion_prover: SP1RecursionProver<A, C>,
    ) -> Self {
        // Initialize the tracing engine
        let core_verifier = C::core_verifier();

        let normalize_program_cache = SP1NormalizeCache::new(config.normalize_program_cache_size);

        let recursive_core_verifier = recursive_verifier::<SP1GlobalContext, _, CoreSC, InnerConfig>(
            core_verifier.shard_verifier(),
        );

        let reduce_shape = recursion_prover.reduce_shape().clone();
        let normalize_program_compiler = NormalizeProgramCompiler::new(
            normalize_program_cache,
            recursive_core_verifier,
            reduce_shape,
            core_verifier,
        );
        let normalize_program_compiler = Arc::new(normalize_program_compiler);

        let trace_workers = (0..config.num_trace_executor_workers)
            .map(|_| {
                TracingWorker::new(
                    normalize_program_compiler.clone(),
                    opts.clone(),
                    artifact_client.clone(),
                    worker_client.clone(),
                )
            })
            .collect();
        let trace_engine =
            Arc::new(AsyncEngine::new(trace_workers, config.trace_executor_buffer_size));

        // Create a shared fixed PK cache if enabled
        let pk_cache = if config.use_fixed_pk { Some(Arc::new(OnceCell::new())) } else { None };

        // Initialize the core prove engine
        let core_prover_workers = (0..config.num_core_prover_workers)
            .map(|_| {
                CoreProverWorker::new(
                    artifact_client.clone(),
                    air_prover.clone(),
                    recursion_prover.clone(),
                    permits.clone(),
                    pk_cache.clone(),
                    config.verify_intermediates,
                )
            })
            .collect::<Vec<_>>();
        let core_prove_engine =
            Arc::new(AsyncEngine::new(core_prover_workers, config.core_prover_buffer_size));

        // Make the setup engine
        let setup_workers = (0..config.num_setup_workers)
            .map(|_| {
                CoreProverWorker::new(
                    artifact_client.clone(),
                    air_prover.clone(),
                    recursion_prover.clone(),
                    permits.clone(),
                    None,
                    false,
                )
            })
            .collect::<Vec<_>>();
        let setup_engine = Arc::new(AsyncEngine::new(setup_workers, config.setup_buffer_size));

        let prove_shard_engine = Arc::new(Chain::new(trace_engine, core_prove_engine));

        Self { prove_shard_engine, setup_engine }
    }
}

/// Given a record, compute the shape of the resulting shard proof.
fn shape_from_record(
    verifier: &MachineVerifier<SP1GlobalContext, CoreSC, RiscvAir<SP1Field>>,
    record: &ExecutionRecord,
) -> Option<CoreProofShape<SP1Field, RiscvAir<SP1Field>>> {
    let log_stacking_height = verifier.log_stacking_height() as usize;
    let max_log_row_count = verifier.max_log_row_count();
    let airs = verifier.machine().chips();
    let shard_chips: BTreeSet<_> =
        airs.iter().filter(|air| air.included(record)).cloned().collect();
    let preprocessed_multiple = shard_chips
        .iter()
        .map(|air| air.preprocessed_width() * air.num_rows(record).unwrap_or_default())
        .sum::<usize>()
        .div_ceil(1 << log_stacking_height);
    let main_multiple = shard_chips
        .iter()
        .map(|air| air.width() * air.num_rows(record).unwrap_or_default())
        .sum::<usize>()
        .div_ceil(1 << log_stacking_height);

    let main_padding_cols = (main_multiple * (1 << log_stacking_height)
        - shard_chips
            .iter()
            .map(|air| air.width() * air.num_rows(record).unwrap_or_default())
            .sum::<usize>())
    .div_ceil(1 << max_log_row_count);

    let preprocessed_padding_cols = (preprocessed_multiple * (1 << log_stacking_height)
        - shard_chips
            .iter()
            .map(|air| air.preprocessed_width() * air.num_rows(record).unwrap_or_default())
            .sum::<usize>())
    .div_ceil(1 << max_log_row_count);

    let shard_chips = verifier.machine().smallest_cluster(&shard_chips).cloned()?;
    Some(CoreProofShape {
        shard_chips,
        preprocessed_multiple,
        main_multiple,
        preprocessed_padding_cols,
        main_padding_cols,
    })
}
