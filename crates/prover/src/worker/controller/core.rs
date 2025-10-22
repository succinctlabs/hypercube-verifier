use std::sync::{Arc, Mutex, OnceLock};

use futures::{prelude::*, stream::FuturesUnordered};
use hashbrown::HashSet;
use itertools::Itertools;
use opentelemetry::Context;
use serde::{Deserialize, Serialize};
use slop_futures::pipeline::{AsyncEngine, AsyncWorker, Pipeline, TaskInput};
use sp1_core_executor::{
    chunked_memory_init_events,
    events::{MemoryInitializeFinalizeEvent, MemoryRecord},
    CompressedMemory, CoreVM, CycleResult, ExecutionError, MinimalExecutor, Program, SP1CoreOpts,
    SplicedMinimalTrace, SplicingVM, SplitOpts, TraceChunkRaw,
};
use sp1_core_machine::{
    executor::{ExecutionOutput, RecordTask},
    io::SP1Stdin,
};
use sp1_hypercube::air::{PROOF_NONCE_NUM_WORDS, PV_DIGEST_NUM_WORDS};
use sp1_jit::MinimalTrace;

use tokio::{sync::mpsc, task::JoinSet};

use crate::{
    worker::{
        Artifact, ArtifactClient, ArtifactType, ProofId, RawTaskRequest, RequesterId, TaskId,
        TaskKind, WorkerClient,
    },
    SP1VerifyingKey,
};

pub struct ProofData {
    pub task_id: TaskId,
    pub proof: Artifact,
}

#[derive(Serialize, Deserialize)]
pub enum TraceData {
    /// A core record to be proven
    Core(Vec<u8>),
    // Precompile data
    Precompile,
    /// Memory data
    Memory(Box<GlobalMemoryShard>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalMemoryShard {
    pub final_state: FinalVmState,
    pub initialize_events: Vec<MemoryInitializeFinalizeEvent>,
    pub finalize_events: Vec<MemoryInitializeFinalizeEvent>,
}

pub struct ProveShardInput {
    pub elf: Vec<u8>,
    pub common_input: CommonProverInput,
    pub record: TraceData,
    pub opts: SP1CoreOpts,
}

#[repr(C)]
pub struct ProveShardInputArtifacts([Artifact; 4]);

impl ProveShardInputArtifacts {
    #[inline]
    pub const fn new(
        elf: Artifact,
        common_input: Artifact,
        record: Artifact,
        opts: Artifact,
    ) -> Self {
        Self([elf, common_input, record, opts])
    }

    #[inline]
    pub const fn elf(&self) -> &Artifact {
        &self.0[0]
    }

    #[inline]
    pub const fn common_input(&self) -> &Artifact {
        &self.0[1]
    }

    #[inline]
    pub const fn record(&self) -> &Artifact {
        &self.0[2]
    }

    #[inline]
    pub const fn as_slice(&self) -> &[Artifact] {
        &self.0
    }

    #[inline]
    pub const fn opts(&self) -> &Artifact {
        &self.0[3]
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CommonProverInput {
    pub vk: SP1VerifyingKey,
    pub deferred_digest: [u32; 8],
    pub num_deffered_proofs: usize,
}

pub struct SP1CoreExecutor<A, W> {
    splicing_engine: Arc<SplicingEngine<A, W>>,
    elf: Artifact,
    stdin: Artifact,
    common_input: Artifact,
    opts: Artifact,
    proof_id: ProofId,
    parent_id: Option<TaskId>,
    parent_context: Option<Context>,
    requester_id: RequesterId,
    sender: mpsc::UnboundedSender<ProofData>,
    artifact_client: A,
    worker_client: W,
}

impl<A, W> SP1CoreExecutor<A, W> {
    pub fn new(
        splicing_engine: Arc<SplicingEngine<A, W>>,
        elf: Artifact,
        stdin: Artifact,
        common_input: Artifact,
        opts: Artifact,
        proof_id: ProofId,
        parent_id: Option<TaskId>,
        parent_context: Option<Context>,
        requester_id: RequesterId,
        sender: mpsc::UnboundedSender<ProofData>,
        artifact_client: A,
        worker_client: W,
    ) -> Self {
        Self {
            splicing_engine,
            opts,
            elf,
            stdin,
            common_input,
            proof_id,
            parent_id,
            parent_context,
            requester_id,
            sender,
            artifact_client,
            worker_client,
        }
    }
}

impl<A, W> SP1CoreExecutor<A, W>
where
    A: ArtifactClient,
    W: WorkerClient,
{
    pub async fn execute(self) -> anyhow::Result<ExecutionOutput> {
        // Get the program and input from artifacts
        let elf_bytes = self.artifact_client.download::<Vec<u8>>(&self.elf).await?;

        let stdin = self.artifact_client.download::<SP1Stdin>(&self.stdin).await?;

        let opts = self.artifact_client.download::<SP1CoreOpts>(&self.opts).await?;

        // Get the program from the elf. TODO: handle errors.
        let program = Arc::new(Program::from(&elf_bytes).unwrap());

        // Initialize the touched addresses map.
        let all_touched_addresses = TouchedAddresses::new();
        // Initialize the final vm state.
        let final_vm_state = FinalVmStateLock::new();

        // Start the minimal executor.
        let parent = tracing::Span::current();
        // TODO: think about cancellation handling
        let minimal_executor_handle = tokio::task::spawn_blocking({
            let program = program.clone();
            let splicing_engine = self.splicing_engine.clone();
            let elf = self.elf.clone();
            let common_input_artifact = self.common_input.clone();
            let proof_id = self.proof_id.clone();
            let parent_id = self.parent_id.clone();
            let parent_context = self.parent_context.clone();
            let requester_id = self.requester_id.clone();
            let all_touched_addresses = all_touched_addresses.clone();
            let sender = self.sender.clone();
            let final_vm_state = final_vm_state.clone();
            let opts = opts.clone();
            let opts_artifact = self.opts.clone();
            move || {
                let _guard = parent.enter();

                let _minimal_exec_span = tracing::debug_span!("minimal executor task").entered();
                let mut minimal_executor = MinimalExecutor::tracing(program.clone(), None);

                // Write input to the minimal executor.
                for buf in stdin.buffer {
                    minimal_executor.with_input(&buf);
                }

                let splicing_handles = FuturesUnordered::new();
                tracing::trace!("Starting minimal executor");
                while let Some(chunk) = minimal_executor.execute_chunk() {
                    tracing::trace!("program is done?: {}", minimal_executor.is_done());
                    tracing::trace!(
                        "mem reads chunk size bytes {}",
                        chunk.num_mem_reads() * std::mem::size_of::<sp1_jit::MemValue>() as u64
                    );

                    // Create a splicing task
                    let task = SplicingTask {
                        program: program.clone(),
                        chunk,
                        elf_artifact: elf.clone(),
                        common_input_artifact: common_input_artifact.clone(),
                        all_touched_addresses: all_touched_addresses.clone(),
                        final_vm_state: final_vm_state.clone(),
                        prove_shard_tx: sender.clone(),
                        proof_id: proof_id.clone(),
                        parent_id: parent_id.clone(),
                        parent_context: parent_context.clone(),
                        requester_id: requester_id.clone(),
                        opts: opts.clone(),
                        opts_artifact: opts_artifact.clone(),
                    };

                    let splicing_handle = splicing_engine
                        .blocking_submit(task)
                        .expect("failed to submit splicing task");

                    splicing_handles.push(splicing_handle);
                }
                tracing::trace!("minimal executor finished");
                (minimal_executor, splicing_handles)
            }
        });

        let (minimal_executor, splicing_handles) =
            minimal_executor_handle.await.expect("executor task panicked");

        // Wait for splicing tasks to finish, catch any potential errors
        splicing_handles
            .map(|nested| {
                let result = nested.map_err(|e| anyhow::anyhow!("splicing task panicked: {}", e));
                let result =
                    result.and_then(|r| r.map_err(|e| anyhow::anyhow!("execution error: {}", e)));
                result
            })
            .try_collect::<Vec<()>>()
            .await?;
        tracing::trace!("splicing tasks finished");

        let touched_addresses = all_touched_addresses.take();
        let final_state = *final_vm_state.get().expect("final vm state not set");

        let cycles = minimal_executor.global_clk();
        let public_value_stream = minimal_executor.public_values_stream().clone();

        let output = ExecutionOutput { cycles, public_value_stream };

        self.emit_global_memory_shards(
            minimal_executor,
            program,
            final_state,
            touched_addresses,
            opts,
            self.opts.clone(),
        )
        .await?;

        Ok(output)
    }

    async fn emit_global_memory_shards(
        &self,
        minimal_executor: MinimalExecutor,
        program: Arc<Program>,
        final_state: FinalVmState,
        touched_addresses: HashSet<u64>,
        opts: SP1CoreOpts,
        opts_artifact: Artifact,
    ) -> anyhow::Result<()> {
        // Get the split opts
        let split_opts = SplitOpts::new(&opts, program.instructions.len(), false);

        let (shard_data_tx, mut shard_data_rx) = mpsc::channel(1);

        let mut join_set = JoinSet::new();

        // Spawn the task that creates the memory shards
        join_set.spawn_blocking({
            let threshold = split_opts.memory;
            move || {
                let (global_memory_initialize_events, global_memory_finalize_events) =
                    Self::global_memory_events(
                        minimal_executor,
                        program,
                        final_state.registers,
                        touched_addresses,
                    );

                for chunks in global_memory_initialize_events
                    .chunks(threshold)
                    .into_iter()
                    .zip_longest(global_memory_finalize_events.chunks(threshold).into_iter())
                {
                    match chunks {
                        itertools::EitherOrBoth::Left(initialize_events) => {
                            let initialize_events =
                                initialize_events.into_iter().collect::<Vec<_>>();
                            shard_data_tx
                                .blocking_send((initialize_events, vec![]))
                                .expect("failed to send initialize events");
                        }
                        itertools::EitherOrBoth::Right(finalize_events) => {
                            let finalize_events = finalize_events.into_iter().collect::<Vec<_>>();
                            shard_data_tx
                                .blocking_send((vec![], finalize_events))
                                .expect("failed to send finalize events");
                        }
                        itertools::EitherOrBoth::Both(initialize_events, finalize_events) => {
                            let initialize_events =
                                initialize_events.into_iter().collect::<Vec<_>>();
                            let finalize_events = finalize_events.into_iter().collect::<Vec<_>>();
                            shard_data_tx
                                .blocking_send((initialize_events, finalize_events))
                                .expect("failed to send events");
                        }
                    }
                }
            }
        });

        // Spawn the task that creates the proving tasks and submits them to the worker
        join_set.spawn({
            let artifact_client = self.artifact_client.clone();
            let worker_client = self.worker_client.clone();
            let elf_artifact = self.elf.clone();
            let common_input_artifact = self.common_input.clone();
            let proof_id = self.proof_id.clone();
            let parent_id = self.parent_id.clone();
            let parent_context = self.parent_context.clone();
            let requester_id = self.requester_id.clone();
            let prove_shard_tx = self.sender.clone();

            async move {
                let mut counter = 0;
                while let Some((initialize_events, finalize_events)) = shard_data_rx.recv().await {
                    tracing::trace!("Got global memory shard number {counter}");
                    let mem_global_shard =
                        GlobalMemoryShard { final_state, initialize_events, finalize_events };
                    let data = TraceData::Memory(Box::new(mem_global_shard));

                    // Upload the data
                    let data_artifact = artifact_client.create_artifact(ArtifactType::Unspecified);
                    artifact_client
                        .upload(&data_artifact, data)
                        .await
                        .expect("failed to upload record");

                    let inputs = ProveShardInputArtifacts::new(
                        elf_artifact.clone(),
                        common_input_artifact.clone(),
                        data_artifact,
                        opts_artifact.clone(),
                    )
                    .as_slice()
                    .to_vec();

                    // Allocate an artifact for the proof
                    let proof_artifact = artifact_client.create_artifact(ArtifactType::Unspecified);

                    // Prepare the task.
                    let task = RawTaskRequest {
                        inputs,
                        outputs: vec![proof_artifact.clone()],
                        proof_id: proof_id.clone(),
                        parent_id: parent_id.clone(),
                        parent_context: parent_context.clone(),
                        requester_id: requester_id.clone(),
                    };

                    // Send the task to the worker.
                    let task_id = worker_client
                        .submit_task(TaskKind::ProveShard, task)
                        .await
                        .expect("failed to send task");

                    // Send the task data
                    let proof_data = ProofData { task_id, proof: proof_artifact };
                    prove_shard_tx.send(proof_data).expect("failed to send task id");
                    tracing::trace!("Submitted memory global shard {counter}");
                    counter += 1;
                }
            }
        });

        // Wait for the tasks to finish
        join_set.join_all().await;

        Ok(())
    }

    fn global_memory_events(
        minimal_executor: MinimalExecutor,
        program: Arc<Program>,
        final_registers: [MemoryRecord; 32],
        mut touched_addresses: HashSet<u64>,
    ) -> (
        impl Iterator<Item = MemoryInitializeFinalizeEvent>,
        impl Iterator<Item = MemoryInitializeFinalizeEvent>,
    ) {
        // Add all the finalize addresses to the touched addresses.
        touched_addresses.extend(program.memory_image.keys().copied());

        let global_memory_initialize_events = final_registers
            .into_iter()
            .enumerate()
            .filter(|(_, e)| e.timestamp != 0)
            .map(|(i, _)| MemoryInitializeFinalizeEvent::initialize(i as u64, 0));

        let global_memory_finalize_events =
            final_registers.into_iter().enumerate().filter(|(_, e)| e.timestamp != 0).map(
                |(i, entry)| {
                    MemoryInitializeFinalizeEvent::finalize(i as u64, entry.value, entry.timestamp)
                },
            );

        let hint_init_events: Vec<MemoryInitializeFinalizeEvent> = minimal_executor
            .hints()
            .iter()
            .flat_map(|(addr, value)| chunked_memory_init_events(*addr, value))
            .collect::<Vec<_>>();
        let hint_addrs = hint_init_events.iter().map(|event| event.addr).collect::<HashSet<_>>();

        // Initialize the all the hints written during execution.
        let global_memory_initialize_events =
            global_memory_initialize_events.chain(hint_init_events);

        // Initialize the memory addresses that were touched during execution.
        // We don't initialize the memory addresses that were in the program image, since they were
        // initialized in the MemoryProgram chip.
        let hint_addresses = hint_addrs.clone();
        let program_memory_image = minimal_executor.program().memory_image.clone();
        let memory_init_events = touched_addresses
            .clone()
            .into_iter()
            .filter(move |addr| !program_memory_image.contains_key(addr))
            .filter(move |addr| !hint_addresses.contains(addr))
            .map(|addr| MemoryInitializeFinalizeEvent::initialize(addr, 0));
        let global_memory_initialize_events =
            global_memory_initialize_events.chain(memory_init_events);

        // Ensure all the hinted addresses are initialized.
        touched_addresses.extend(hint_addrs);

        // Finalize the memory addresses that were touched during execution.
        let global_memory_finalize_events =
            global_memory_finalize_events.chain(touched_addresses.into_iter().map(move |addr| {
                let entry = minimal_executor.get_memory_value(addr);
                MemoryInitializeFinalizeEvent::finalize(addr, entry.value, entry.clk)
            }));

        (global_memory_initialize_events, global_memory_finalize_events)
    }
}

#[derive(Debug, Clone)]
pub struct TouchedAddresses {
    inner: Arc<Mutex<HashSet<u64>>>,
}

impl TouchedAddresses {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(HashSet::new())) }
    }

    pub fn extend(&self, addresses: impl IntoIterator<Item = u64>) {
        self.inner.lock().unwrap().extend(addresses);
    }

    pub fn take(self) -> HashSet<u64> {
        std::mem::take(&mut *self.inner.lock().unwrap())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct FinalVmState {
    pub registers: [MemoryRecord; 32],
    pub timestamp: u64,
    pub pc: u64,
    pub exit_code: u32,
    pub public_value_digest: [u32; PV_DIGEST_NUM_WORDS],
    pub proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
}

impl FinalVmState {
    pub fn new<'a, 'b>(vm: &'a CoreVM<'b>) -> Self {
        let registers = *vm.registers();
        let timestamp = vm.clk();
        let pc = vm.pc();
        let exit_code = vm.exit_code();
        let public_value_digest = vm.public_value_digest;
        let proof_nonce = vm.proof_nonce;

        Self { registers, timestamp, pc, exit_code, public_value_digest, proof_nonce }
    }
}

#[derive(Debug, Clone)]
pub struct FinalVmStateLock {
    inner: Arc<OnceLock<FinalVmState>>,
}

impl FinalVmStateLock {
    pub fn new() -> Self {
        Self { inner: Arc::new(OnceLock::new()) }
    }

    pub fn set(&self, state: FinalVmState) {
        self.inner.set(state).expect("final vm state already set");
    }

    pub fn get(&self) -> Option<&FinalVmState> {
        self.inner.get()
    }
}

pub type SplicingEngine<A, W> =
    AsyncEngine<SplicingTask, Result<(), ExecutionError>, SplicingWorker<A, W>>;

/// A task for splicing a trace into single shard chunks.
pub struct SplicingTask {
    program: Arc<Program>,
    chunk: TraceChunkRaw,
    elf_artifact: Artifact,
    common_input_artifact: Artifact,
    all_touched_addresses: TouchedAddresses,
    final_vm_state: FinalVmStateLock,
    prove_shard_tx: mpsc::UnboundedSender<ProofData>,
    proof_id: ProofId,
    parent_id: Option<TaskId>,
    parent_context: Option<Context>,
    requester_id: RequesterId,
    opts: SP1CoreOpts,
    opts_artifact: Artifact,
}

impl TaskInput for SplicingTask {
    fn weight(&self) -> u32 {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SplicingWorker<A, W> {
    artifact_client: A,
    worker_client: W,
}

impl<A, W> SplicingWorker<A, W>
where
    A: ArtifactClient,
    W: WorkerClient,
{
    pub fn new(artifact_client: A, worker_client: W) -> Self {
        Self { artifact_client, worker_client }
    }
}

impl<A, W> AsyncWorker<SplicingTask, Result<(), ExecutionError>> for SplicingWorker<A, W>
where
    A: ArtifactClient,
    W: WorkerClient,
{
    async fn call(&self, input: SplicingTask) -> Result<(), ExecutionError> {
        let SplicingTask {
            program,
            chunk,
            all_touched_addresses,
            final_vm_state,
            elf_artifact,
            common_input_artifact,
            prove_shard_tx,
            proof_id,
            parent_id,
            parent_context,
            requester_id,
            opts,
            opts_artifact,
        } = input;

        let (splicing_tx, mut splicing_rx) = mpsc::channel::<RecordTask>(1);

        let mut join_set = JoinSet::<Result<(), ExecutionError>>::new();

        // Spawn the task that proves the shard.
        join_set.spawn({
            let worker_client = self.worker_client.clone();
            let artifact_client = self.artifact_client.clone();

            async move {
                while let Some(record) = splicing_rx.recv().await {
                    let chunk_bytes =
                        bincode::serialize(&record.chunk).expect("failed to serialize record");
                    let data = TraceData::Core(chunk_bytes);
                    // Upload the record
                    let record_artifact =
                        artifact_client.create_artifact(ArtifactType::Unspecified);
                    artifact_client
                        .upload(&record_artifact, data)
                        .await
                        .expect("failed to upload record");

                    // TODO: make the deferred marker task and add it to the inputs.

                    let inputs = ProveShardInputArtifacts::new(
                        elf_artifact.clone(),
                        common_input_artifact.clone(),
                        record_artifact,
                        opts_artifact.clone(),
                    )
                    .as_slice()
                    .to_vec();

                    // Allocate an artifact for the proof
                    let proof_artifact = artifact_client.create_artifact(ArtifactType::Unspecified);

                    // Prepare the task.
                    let task = RawTaskRequest {
                        inputs,
                        outputs: vec![proof_artifact.clone()],
                        proof_id: proof_id.clone(),
                        parent_id: parent_id.clone(),
                        parent_context: parent_context.clone(),
                        requester_id: requester_id.clone(),
                    };

                    // Send the task to the worker.
                    let task_id = worker_client
                        .submit_task(TaskKind::ProveShard, task)
                        .await
                        .expect("failed to send task");

                    // Send the task id
                    let proof_data = ProofData { task_id, proof: proof_artifact };
                    prove_shard_tx.send(proof_data).expect("failed to send task id");
                }

                Ok(())
            }
        });

        // Spawn the task that splices the trace.
        join_set.spawn_blocking(move || {
        let mut touched_addresses = CompressedMemory::new();
        let mut vm = SplicingVM::new(&chunk, program.clone(), &mut touched_addresses, opts);

        let start_num_mem_reads = chunk.num_mem_reads();

        let mut last_splice = SplicedMinimalTrace::new_full_trace(chunk.clone());
        loop {
            tracing::debug!("starting new shard at clk: {} at pc: {}", vm.core.clk(), vm.core.pc());
            match vm.execute()? {
                CycleResult::ShardBoundry => {
                    // Note: Chunk implentations should always be cheap to clone.
                    if let Some(spliced) = vm.splice(chunk.clone()) {
                        tracing::trace!("shard ended at clk: {}", vm.core.clk());
                        tracing::trace!("shard ended at pc: {}", vm.core.pc());
                        tracing::trace!("shard ended at global clk: {}", vm.core.global_clk());
                        tracing::trace!(
                            "shard ended with {} mem reads left ",
                            vm.core.mem_reads.len()
                        );

                        // Set the last splice clk.
                        last_splice.set_last_clk(vm.core.clk());
                        last_splice.set_last_mem_reads_idx(
                            start_num_mem_reads as usize - vm.core.mem_reads.len(),
                        );
                        let splice_to_send = std::mem::replace(&mut last_splice, spliced);

                        // TODO: handle errors.
                        splicing_tx.blocking_send(RecordTask { chunk: splice_to_send }).expect("failed to send splicing task");

                        // Prepare the prove shard task.
                    } else {
                        tracing::trace!("trace ended at clk: {}", vm.core.clk());
                        tracing::trace!("trace ended at pc: {}", vm.core.pc());
                        tracing::trace!("trace ended at global clk: {}", vm.core.global_clk());
                        tracing::trace!(
                            "trace ended with {} mem reads left ",
                            vm.core.mem_reads.len()
                        );

                        last_splice.set_last_clk(vm.core.clk());
                        last_splice.set_last_mem_reads_idx(
                            start_num_mem_reads as usize - vm.core.mem_reads.len(),
                        );

                        splicing_tx.blocking_send(RecordTask { chunk: last_splice }).expect("failed to send splicing task");

                        break;
                    }
                }
                CycleResult::Done(true) => {
                    last_splice.set_last_clk(vm.core.clk());
                    last_splice.set_last_mem_reads_idx(chunk.num_mem_reads() as usize);

                    // Get the last state of the vm execution and set the global final vm state to
                    // this value.
                    let final_state = FinalVmState::new(&vm.core);
                    final_vm_state.set(final_state);

                    // Send the last splice.
                    splicing_tx.blocking_send(RecordTask { chunk: last_splice }).expect("failed to send splicing task");

                    break;
                }
                CycleResult::Done(false) | CycleResult::TraceEnd => {
                    // Note: Trace ends get mapped to shard boundaries.
                    unreachable!("The executor should never return an imcomplete program without a shard boundary");
                }
            }
        }
        // Append the touched addresses from this chunk to the globally tracked touched addresses.
        tracing::trace!("extending all_touched_addresses with touched_addresses");
        all_touched_addresses.extend(touched_addresses.is_set().into_iter());

        Ok(())
        });

        // Wait for the tasks to finish and collect the errors.
        join_set.join_all().await.into_iter().collect::<Result<(), ExecutionError>>()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sp1_core_machine::utils::setup_logger;

    use crate::worker::{InMemoryArtifactClient, TrivialWorkerClient};

    use super::*;

    #[tokio::test]
    #[allow(clippy::print_stdout)]

    async fn test_pure_execution() {
        let elf = test_artifacts::FIBONACCI_ELF;
        setup_logger();

        let num_splicing_workers = 2;
        let splicing_buffer_size = 4;
        let task_capacity = 10;

        let artifact_client = InMemoryArtifactClient::new();
        let worker_client = TrivialWorkerClient::new(task_capacity, artifact_client.clone());

        let splicing_workers = (0..num_splicing_workers)
            .map(|_| SplicingWorker::new(artifact_client.clone(), worker_client.clone()))
            .collect::<Vec<_>>();

        let splicing_engine = Arc::new(SplicingEngine::new(splicing_workers, splicing_buffer_size));

        let opts = SP1CoreOpts::default();
        let stdin = SP1Stdin::default();
        let proof_id = ProofId::new("test_pure_execution");
        let parent_id = None;
        let parent_context = None;
        let requester_id = RequesterId::new("test_pure_execution");
        let common_input = artifact_client.create_artifact(ArtifactType::Unspecified);

        let (sender, mut receiver) = mpsc::unbounded_channel();

        let elf_artifact = artifact_client.create_artifact(ArtifactType::Program);
        let elf_bytes = elf.to_vec();
        artifact_client.upload(&elf_artifact, elf_bytes).await.expect("failed to upload elf");

        let stdin_artifact = artifact_client.create_artifact(ArtifactType::Stdin);
        artifact_client.upload(&stdin_artifact, stdin).await.expect("failed to upload stdin");

        let opts_artifact = artifact_client.create_artifact(ArtifactType::Unspecified);
        artifact_client.upload(&opts_artifact, opts).await.expect("failed to upload opts");

        let executor = SP1CoreExecutor {
            splicing_engine,
            opts: opts_artifact,
            elf: elf_artifact,
            stdin: stdin_artifact,
            common_input,
            proof_id,
            parent_id,
            parent_context,
            requester_id,
            sender,
            artifact_client,
            worker_client,
        };

        let counter_handle = tokio::task::spawn(async move {
            let mut counter = 0;
            while receiver.recv().await.is_some() {
                counter += 1;
            }
            println!("counter: {}", counter);
        });

        // Execute and see the result
        let time = tokio::time::Instant::now();
        let result = executor.execute().await.expect("failed to execute");
        let time = time.elapsed();
        println!(
            "cycles: {}, execution time: {:?}, mhz: {}",
            result.cycles,
            time,
            result.cycles as f64 / (time.as_secs_f64() * 1_000_000.0)
        );

        // Make sure the counter is finished before exiting
        counter_handle.await.expect("counter task panicked");
    }
}
