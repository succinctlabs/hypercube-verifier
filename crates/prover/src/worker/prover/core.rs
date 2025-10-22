use std::sync::Arc;

use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_futures::pipeline::{
    AsyncEngine, AsyncWorker, Chain, Pipeline, SubmitError, TaskHandle, TaskInput,
};
use sp1_core_executor::{ExecutionRecord, Program, SP1CoreOpts};
use sp1_core_machine::{executor::trace_chunk, riscv::RiscvAir};
use sp1_hypercube::{
    prover::{AirProver, MachineProverComponents, ProverSemaphore},
    Machine, SP1RecursionProof, ShardProof,
};
use sp1_jit::TraceChunk;
use sp1_primitives::{SP1Field, SP1GlobalContext};

use crate::{
    components::CoreProver,
    worker::{
        Artifact, ArtifactClient, CommonProverInput, GlobalMemoryShard, TaskId, TraceData,
        WorkerClient,
    },
    CoreSC, InnerSC, SP1ProverComponents,
};

pub struct SetupTask {
    pub id: TaskId,
    pub elf: Artifact,
    pub output: Artifact,
}

impl TaskInput for SetupTask {
    fn weight(&self) -> u32 {
        1
    }
}

pub struct TracingTask {
    pub id: TaskId,
    pub elf: Artifact,
    pub common_input: Artifact,
    pub record: Artifact,
    pub opts: Artifact,
    pub output: Artifact,
}

impl TaskInput for TracingTask {
    fn weight(&self) -> u32 {
        1
    }
}

struct TracingWorker<A, W> {
    machine: Arc<Machine<SP1Field, RiscvAir<SP1Field>>>,
    artifact_client: A,
    _worker_client: W,
}

impl<A, W> TracingWorker<A, W> {
    pub fn new(
        machine: Arc<Machine<SP1Field, RiscvAir<SP1Field>>>,
        artifact_client: A,
        worker_client: W,
    ) -> Self {
        Self { machine, artifact_client, _worker_client: worker_client }
    }
}

impl<A, W> AsyncWorker<TracingTask, CoreProveTask> for TracingWorker<A, W>
where
    A: ArtifactClient,
    W: WorkerClient,
{
    async fn call(&self, input: TracingTask) -> CoreProveTask {
        // Save the trace input artifact for later use in the task
        let record_artifact = input.record.clone();
        // Ok to panic because it will send a JoinError.
        let elf = self
            .artifact_client
            .download::<Vec<u8>>(&input.elf)
            .await
            .expect("failed to download elf");
        let common_input = self
            .artifact_client
            .download::<CommonProverInput>(&input.common_input)
            .await
            .expect("failed to download common input");
        let record = self
            .artifact_client
            .download::<TraceData>(&input.record)
            .await
            .expect("failed to download record");
        let opts = self
            .artifact_client
            .download::<SP1CoreOpts>(&input.opts)
            .await
            .expect("failed to download opts");

        let (program, record) = tokio::task::spawn_blocking({
            let machine = self.machine.clone();
            move || {
                let program = Arc::new(Program::from(&elf).expect("failed to disassemble program"));
                let mut record = match record {
                    TraceData::Core(chunk_bytes) => {
                        // let chunk =
                        let chunk: TraceChunk = bincode::deserialize(&chunk_bytes)
                            .expect("failed to deserialize chunk");
                        tracing::trace!(
                            "tracing chunk at clk range: {}..{}",
                            chunk.clk_start,
                            chunk.clk_end
                        );
                        let (_, record, _) = trace_chunk::<SP1Field>(program.clone(), opts, chunk)
                            .expect("failed to trace chunk");

                        // TODO: defer precompile events

                        record
                    }
                    TraceData::Memory(shard) => {
                        let GlobalMemoryShard { final_state, initialize_events, finalize_events } =
                            *shard;
                        let mut record = ExecutionRecord::new(program.clone());
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

                        record.finalize_public_values::<SP1Field>();

                        record
                    }
                    _ => unimplemented!(),
                };

                // Generate the dependencies
                machine.generate_dependencies([&mut record].into_iter(), None);

                (program, record)
            }
        })
        .await
        .expect("failed to trace chunk");

        CoreProveTask {
            id: input.id,
            program,
            common_input,
            record,
            output: input.output,
            record_artifact,
        }
    }
}

struct CoreProveTask {
    id: TaskId,
    program: Arc<Program>,
    common_input: CommonProverInput,
    record: ExecutionRecord,
    output: Artifact,
    record_artifact: Artifact,
}

impl TaskInput for CoreProveTask {
    fn weight(&self) -> u32 {
        1
    }
}

pub enum SP1CoreShardProof {
    Core(ShardProof<SP1GlobalContext, CoreSC>),
    Recursion(SP1RecursionProof<SP1GlobalContext, InnerSC>),
}

pub struct CoreProveOutput {
    pub id: TaskId,
    pub proof: SP1CoreShardProof,
}

struct CoreProverWorker<A, C: SP1ProverComponents> {
    artifact_client: A,
    core_prover: Arc<<C::CoreComponents as MachineProverComponents<SP1GlobalContext>>::Prover>,
    permits: ProverSemaphore,
}

impl<A, C: SP1ProverComponents> CoreProverWorker<A, C> {
    pub fn new(
        artifact_client: A,
        core_prover: Arc<CoreProver<C>>,
        permits: ProverSemaphore,
    ) -> Self {
        Self { artifact_client, core_prover, permits }
    }
}

impl<A, C> AsyncWorker<CoreProveTask, TaskId> for CoreProverWorker<A, C>
where
    C: SP1ProverComponents,
    A: ArtifactClient,
{
    async fn call(&self, input: CoreProveTask) -> TaskId {
        let CoreProveTask { id, program, common_input, record, output, record_artifact } = input;
        let mut challenger = SP1GlobalContext::default_challenger();

        let permits = self.permits.clone();
        let (_, proof, permit) = self
            .core_prover
            .setup_and_prove_shard(
                program.clone(),
                record,
                Some(common_input.vk.vk),
                permits,
                &mut challenger,
            )
            .await;

        // Drop the permit
        drop(permit);

        // Upload the proof
        self.artifact_client.upload(&output, proof).await.expect("failed to upload proof");

        // Remove the record artifact since it is no longer needed
        self.artifact_client.try_delete(&record_artifact).await;

        id
    }
}

impl<A, C> AsyncWorker<SetupTask, TaskId> for CoreProverWorker<A, C>
where
    C: SP1ProverComponents,
    A: ArtifactClient,
{
    async fn call(&self, input: SetupTask) -> TaskId {
        let SetupTask { id, elf, output } = input;

        let elf =
            self.artifact_client.download::<Vec<u8>>(&elf).await.expect("failed to download elf");

        let program = Program::from(&elf).expect("failed to disassemble program");
        let program = Arc::new(program);

        let permits = self.permits.clone();
        let (_, vk) = self.core_prover.setup(program, permits).await;

        // Upload the vk
        self.artifact_client.upload(&output, vk).await.expect("failed to upload vk");

        id
    }
}

type SetupEngine<A, C> = Arc<AsyncEngine<SetupTask, TaskId, CoreProverWorker<A, C>>>;

type TraceEngine<A, W> = Arc<AsyncEngine<TracingTask, CoreProveTask, TracingWorker<A, W>>>;
type CoreProveEngine<A, C> = Arc<AsyncEngine<CoreProveTask, TaskId, CoreProverWorker<A, C>>>;
type SP1CoreEngine<A, W, C> = Chain<TraceEngine<A, W>, CoreProveEngine<A, C>>;

pub struct SP1CoreProver<A: ArtifactClient, W: WorkerClient, C: SP1ProverComponents> {
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
        task: TracingTask,
    ) -> Result<TaskHandle<TaskId>, SubmitError> {
        self.prove_shard_engine.submit(task).await
    }

    pub async fn submit_setup(&self, task: SetupTask) -> Result<TaskHandle<TaskId>, SubmitError> {
        self.setup_engine.submit(task).await
    }
}

/// Configuration for the core prover.
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
}

impl<A: ArtifactClient, W: WorkerClient, C: SP1ProverComponents> SP1CoreProver<A, W, C> {
    pub fn new(
        config: SP1CoreProverConfig,
        artifact_client: A,
        worker_client: W,
        air_prover: Arc<CoreProver<C>>,
        permits: ProverSemaphore,
        // recursion_air_provers: Vec<Arc<RecursionProver<C>>>,
    ) -> Self {
        // Initialize the tracing engine
        let core_verifier = C::core_verifier();
        let machine = Arc::new(core_verifier.machine().clone());

        let trace_workers = (0..config.num_trace_executor_workers)
            .map(|_| {
                TracingWorker::new(machine.clone(), artifact_client.clone(), worker_client.clone())
            })
            .collect();
        let trace_engine =
            Arc::new(AsyncEngine::new(trace_workers, config.trace_executor_buffer_size));

        // Initialize the core prove engine
        let core_prover_workers = (0..config.num_core_prover_workers)
            .map(|_| {
                CoreProverWorker::new(artifact_client.clone(), air_prover.clone(), permits.clone())
            })
            .collect::<Vec<_>>();
        let core_prove_engine =
            Arc::new(AsyncEngine::new(core_prover_workers, config.core_prover_buffer_size));

        // Make the setup engine
        let setup_workers = (0..config.num_setup_workers)
            .map(|_| {
                CoreProverWorker::new(artifact_client.clone(), air_prover.clone(), permits.clone())
            })
            .collect::<Vec<_>>();
        let setup_engine = Arc::new(AsyncEngine::new(setup_workers, config.setup_buffer_size));

        let prove_shard_engine = Arc::new(Chain::new(trace_engine, core_prove_engine));

        Self { prove_shard_engine, setup_engine }
    }
}
