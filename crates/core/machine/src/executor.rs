use std::{
    io,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use futures::future::try_join_all;
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use slop_algebra::PrimeField32;
use slop_futures::queue::{TryAcquireWorkerError, WorkerQueue};
use sp1_core_executor::{
    events::MemoryRecord, CompressedMemory, ExecutionError, ExecutionRecord, ExecutionReport,
    GasEstimatingVM, Program, SP1Context, SP1CoreOpts, SplicingVM, SplitOpts, TracingVM,
};
use sp1_hypercube::{
    prover::{MemoryPermit, MemoryPermitting},
    Machine, MachineRecord,
};
use sp1_jit::MinimalTrace;
use sp1_primitives::io::SP1PublicValues;
use thiserror::Error;
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    TryAcquireError,
};
use tracing::{Instrument, Level};

use sp1_core_executor::{CycleResult, MinimalExecutor, SplicedMinimalTrace, TraceChunkRaw};

use crate::{io::SP1Stdin, riscv::RiscvAir};

pub struct MachineExecutor<F: PrimeField32> {
    num_record_workers: usize,
    opts: SP1CoreOpts,
    machine: Machine<F, RiscvAir<F>>,
    memory: MemoryPermitting,
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField32> MachineExecutor<F> {
    pub fn new(record_buffer_size: usize, num_record_workers: usize, opts: SP1CoreOpts) -> Self {
        let machine = RiscvAir::<F>::machine();

        Self {
            num_record_workers,
            opts,
            machine,
            memory: MemoryPermitting::new(record_buffer_size),
            _marker: PhantomData,
        }
    }

    /// Get a reference to the core options.
    pub fn opts(&self) -> &SP1CoreOpts {
        &self.opts
    }

    /// Execute a program synchronously and return the same interface as the deprecated core
    /// executor.
    ///
    /// This method mirrors the machine executor's three-stage pipeline:
    /// 1. MinimalExecutor for fast execution and public_values_stream
    /// 2. SplicingVM for ExecutionReport generation
    /// 3. TracingVM for committed_value_digest extraction
    pub fn execute_sync(
        &self,
        program: Arc<Program>,
        stdin: SP1Stdin,
        _context: SP1Context<'static>,
    ) -> Result<(SP1PublicValues, [u8; 32], ExecutionReport), MachineExecutorError> {
        // Phase 1: Use MinimalExecutor for fast execution and public values stream
        const MAX_NUMBER_TRACE_ENTRIES: u64 =
            2147483648 / std::mem::size_of::<sp1_jit::MemValue>() as u64;

        let mut minimal_executor =
            MinimalExecutor::new(program.clone(), false, Some(MAX_NUMBER_TRACE_ENTRIES));

        // Feed stdin buffers to the executor
        for buf in stdin.buffer {
            minimal_executor.with_input(&buf);
        }

        // Execute the program to completion, collecting all trace chunks
        let mut chunks = Vec::new();
        while let Some(chunk) = minimal_executor.execute_chunk() {
            chunks.push(chunk);
        }

        tracing::info!("chunks: {:?}", chunks.len());

        // Extract the public values stream from minimal executor
        let public_value_stream = minimal_executor.into_public_values_stream();
        let public_values = SP1PublicValues::from(&public_value_stream);

        tracing::info!("public_value_stream: {:?}", public_value_stream);

        let mut accumulated_report = ExecutionReport::default();
        let filler: [u8; 32] = [0; 32];

        let mut touched_addresses = CompressedMemory::new();

        for chunk in chunks {
            let mut gas_estimating_vm = GasEstimatingVM::new(
                &chunk,
                program.clone(),
                &mut touched_addresses,
                self.opts.clone(),
            );
            let report = gas_estimating_vm.execute().unwrap();
            accumulated_report += report;
        }

        Ok((public_values, filler, accumulated_report))
    }

    pub async fn execute(
        &self,
        program: Arc<Program>,
        stdin: SP1Stdin,
        _context: SP1Context<'static>,
        record_tx: mpsc::UnboundedSender<(ExecutionRecord, Option<MemoryPermit>)>,
    ) -> Result<ExecutionOutput, MachineExecutorError> {
        let (chunk_tx, mut chunk_rx) = mpsc::unbounded_channel::<TraceChunkRaw>();
        let (last_record_tx, mut last_record_rx) =
            tokio::sync::mpsc::channel::<(ExecutionRecord, [MemoryRecord; 32])>(1);
        let deferred = Arc::new(Mutex::new(ExecutionRecord::new(program.clone())));
        let mut record_worker_channels = Vec::with_capacity(self.num_record_workers);

        // todo: use page protection
        let split_opts = SplitOpts::new(&self.opts, program.instructions.len(), false);

        tracing::debug!("starting {} record worker channels", self.num_record_workers);
        let mut handles = Vec::with_capacity(self.num_record_workers);
        for i in 0..self.num_record_workers {
            let (tx, mut rx) = mpsc::unbounded_channel::<RecordTask>();
            record_worker_channels.push(tx);
            let machine = self.machine.clone();
            let opts = self.opts.clone();
            let program = program.clone();
            let record_tx = record_tx.clone();
            let deferred: Arc<Mutex<ExecutionRecord>> = deferred.clone();
            let last_record_tx = last_record_tx.clone();
            let permitting = self.memory.clone();

            handles.push(tokio::task::spawn(
                async move {
                    while let Some(task) = rx.recv().await {
                        let RecordTask { chunk } = task;
                        tracing::trace!("tracing chunk with worker: {}", i);

                        // Assume a record is 4Gb for now.
                        let permit = permitting.acquire(2 * 1024 * 1024 * 1024).await.unwrap();

                        let program = program.clone();
                        let (done, mut record, registers) = tokio::task::spawn_blocking({
                            let program = program.clone();
                            let opts = opts.clone();
                            move || {
                                let _debug_span =
                                    tracing::trace_span!("tracing chunk blocking task").entered();
                                trace_chunk::<F>(program, opts, chunk)
                            }
                        })
                        .await
                        .expect("error: trace chunk task panicked")
                        .expect("todo: handle error");

                        if done {
                            tracing::trace!("last record");

                            // If this is the last record, we have special handling for the memory
                            // events.
                            last_record_tx.send((record, registers)).await.unwrap();
                        } else {
                            tracing::trace!("defferring record");

                            let deferred_records = {
                                let mut deferred = deferred.lock().unwrap();
                                defer(&mut record, &mut deferred, &split_opts, opts.clone(), done)
                            };
                            start_prove(
                                machine.clone(),
                                record_tx.clone(),
                                Some(permit),
                                record,
                                deferred_records,
                            )
                            .await;
                        };
                    }

                    tracing::trace!("tracing worker finished");
                }
                .instrument(tracing::debug_span!("tracing worker")),
            ));
        }

        let record_worker_channels = Arc::new(WorkerQueue::new(record_worker_channels));

        let minimal_executor_handle = tokio::task::spawn_blocking({
            let program = program.clone();

            move || {
                let _debug_span = tracing::debug_span!("minimal executor task").entered();
                let mut minimal_executor = MinimalExecutor::tracing(program.clone(), None);

                for buf in stdin.buffer {
                    minimal_executor.with_input(&buf);
                }

                tracing::trace!("Starting minimal executor");
                while let Some(chunk) = minimal_executor.execute_chunk() {
                    tracing::trace!("program is done?: {}", minimal_executor.is_done());
                    tracing::trace!(
                        "mem reads chunk size bytes {}",
                        chunk.num_mem_reads() * std::mem::size_of::<sp1_jit::MemValue>() as u64
                    );

                    chunk_tx.send(chunk).unwrap();
                }
                tracing::trace!("minimal executor finished");

                minimal_executor
            }
        });

        let touched_addresses = tokio::task::spawn({
            let program: Arc<Program> = program.clone();
            let opts = self.opts.clone();
            async move {
                let mut splicing_handles = Vec::new();
                let touched_addresses = Arc::new(Mutex::new(HashSet::new()));

                while let Some(chunk) = chunk_rx.recv().await {
                    let splicing_handle = tokio::task::spawn_blocking({
                        let program = program.clone();
                        let touched_addresses = touched_addresses.clone();
                        let record_worker_channels = record_worker_channels.clone();
                        let opts = opts.clone();
                        move || {
                            generate_chunks(
                                program,
                                chunk,
                                record_worker_channels,
                                touched_addresses,
                                opts,
                            )
                        }
                    });

                    splicing_handles.push(splicing_handle);
                }

                try_join_all(splicing_handles).await.expect("error: splicing tasks panicked");

                touched_addresses
            }
            .instrument(tracing::debug_span!("splitting task"))
        })
        .await
        .unwrap();

        // Wait for the minimal executor to finish.
        let minimal_executor = minimal_executor_handle.await.unwrap();
        tracing::debug!("Minimal executor finished");

        // Wait for the record workers to finish.
        try_join_all(handles).await.expect("error: tracing tasks panicked");
        tracing::debug!("All record workers finished");

        // Wait for the last record to be traced.
        let (mut last_record, final_registers) = last_record_rx.recv().await.unwrap();
        tracing::info!(
            "last_record.public_values.committed_value_digest: {:?}",
            last_record.public_values.committed_value_digest
        );
        let deferred_records = tracing::trace_span!("emit globals").in_scope(|| {
            let touched_addresses = std::mem::take(&mut *touched_addresses.lock().unwrap());

            // Insert the global memory events into the last record.
            minimal_executor.emit_globals(&mut last_record, final_registers, touched_addresses);

            let mut deferred = deferred.lock().unwrap();
            // let mut state = state.lock().unwrap();
            tracing::trace_span!("defer last shard").in_scope(|| {
                defer(&mut last_record, &mut deferred, &split_opts, self.opts.clone(), true)
            })
        });

        start_prove(self.machine.clone(), record_tx, None, last_record, deferred_records).await;

        Ok(ExecutionOutput {
            cycles: minimal_executor.global_clk(),
            public_value_stream: minimal_executor.into_public_values_stream(),
        })
    }
}

#[derive(Error, Debug)]
pub enum MachineExecutorError {
    #[error("Failed to execute program: {0}")]
    ExecutionError(ExecutionError),
    #[error("IO error: {0}")]
    IoError(io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(bincode::Error),
    #[error("Executor is already closed")]
    ExecutorClosed,
    #[error("Task failed: {0:?}")]
    ExecutorPanicked(#[from] tokio::task::JoinError),
    #[error("Failed to send record to prover channel")]
    ProverChannelClosed,
}

/// The output of the machine executor.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionOutput {
    pub public_value_stream: Vec<u8>,
    pub cycles: u64,
}

pub struct RecordTask {
    pub chunk: SplicedMinimalTrace<TraceChunkRaw>,
}

/// Generate the chunks (corresponding to shards) and send them to the record workers.
#[tracing::instrument(name = "generate_chunks", skip_all)]
fn generate_chunks(
    program: Arc<Program>,
    chunk: TraceChunkRaw,
    record_worker_channels: Arc<WorkerQueue<UnboundedSender<RecordTask>>>,
    all_touched_addresses: Arc<Mutex<HashSet<u64>>>,
    opts: SP1CoreOpts,
) -> Result<(), ExecutionError> {
    let mut touched_addresses = CompressedMemory::new();
    let mut vm = SplicingVM::new(&chunk, program.clone(), &mut touched_addresses, opts);

    let start_num_mem_reads = chunk.num_mem_reads();

    let mut last_splice = SplicedMinimalTrace::new_full_trace(chunk.clone());
    loop {
        tracing::debug!("starting new shard at clk: {} at pc: {}", vm.core.clk(), vm.core.pc());
        match vm.execute().expect("todo: handle result") {
            CycleResult::ShardBoundry => {
                // Note: Chunk implentations should always be cheap to clone.
                if let Some(spliced) = vm.splice(chunk.clone()) {
                    tracing::trace!("shard ended at clk: {}", vm.core.clk());
                    tracing::trace!("shard ended at pc: {}", vm.core.pc());
                    tracing::trace!("shard ended at global clk: {}", vm.core.global_clk());
                    tracing::trace!("shard ended with {} mem reads left ", vm.core.mem_reads.len());

                    // Set the last splice clk.
                    last_splice.set_last_clk(vm.core.clk());
                    last_splice.set_last_mem_reads_idx(
                        start_num_mem_reads as usize - vm.core.mem_reads.len(),
                    );

                    let splice_to_send = std::mem::replace(&mut last_splice, spliced);
                    send_spliced_trace_blocking(record_worker_channels.clone(), splice_to_send);
                } else {
                    tracing::trace!("trace ended at clk: {}", vm.core.clk());
                    tracing::trace!("trace ended at pc: {}", vm.core.pc());
                    tracing::trace!("trace ended at global clk: {}", vm.core.global_clk());
                    tracing::trace!("trace ended with {} mem reads left ", vm.core.mem_reads.len());

                    last_splice.set_last_clk(vm.core.clk());
                    last_splice.set_last_mem_reads_idx(
                        start_num_mem_reads as usize - vm.core.mem_reads.len(),
                    );

                    send_spliced_trace_blocking(record_worker_channels.clone(), last_splice);

                    break;
                }
            }
            CycleResult::Done(true) => {
                last_splice.set_last_clk(vm.core.clk());
                last_splice.set_last_mem_reads_idx(chunk.num_mem_reads() as usize);

                send_spliced_trace_blocking(record_worker_channels.clone(), last_splice);

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
    all_touched_addresses.lock().unwrap().extend(touched_addresses.is_set().into_iter());

    Ok(())
}

/// Trace a single [`SplicedMinimalTrace`] (corresponding to a shard) and return the execution
/// record.
#[tracing::instrument(
    level = Level::DEBUG,
    name = "trace_chunk",
    skip_all,
)]
pub fn trace_chunk<F: PrimeField32>(
    program: Arc<Program>,
    opts: SP1CoreOpts,
    chunk: impl MinimalTrace,
) -> Result<(bool, ExecutionRecord, [MemoryRecord; 32]), ExecutionError> {
    let mut vm = TracingVM::new(&chunk, program, opts);
    let status = vm.execute()?;
    tracing::trace!("chunk ended at clk: {}", vm.core.clk());
    tracing::trace!("chunk ended at pc: {}", vm.core.pc());

    let mut record = std::mem::take(&mut vm.record);
    let pv = record.public_values;

    // Handle the case where `COMMIT` or `COMMIT_DEFERRED_PROOFS` happens across last two shards.
    //
    // todo: does this actually work in the new regieme? what if the shard is stopped due to the clk
    // limit? if so, does that mean this could be wrong? its unclear!
    if status.is_shard_boundry() && (pv.commit_syscall == 1 || pv.commit_deferred_syscall == 1) {
        tracing::trace!("commit syscall or commit deferred proofs across last two shards");

        loop {
            // Execute until we get a done status.
            if vm.execute()?.is_done() {
                let pv = vm.record.public_values;

                // Update the record.
                record.public_values.commit_syscall = 1;
                record.public_values.commit_deferred_syscall = 1;
                record.public_values.committed_value_digest = pv.committed_value_digest;
                record.public_values.deferred_proofs_digest = pv.deferred_proofs_digest;

                break;
            }
        }
    }

    // Finalize the public values
    record.finalize_public_values::<F>();

    Ok((status.is_done(), record, *vm.core.registers()))
}

#[tracing::instrument(name = "defer", skip_all)]
fn defer(
    record: &mut ExecutionRecord,
    deferred: &mut ExecutionRecord,
    split_opts: &SplitOpts,
    opts: SP1CoreOpts,
    done: bool,
) -> Vec<ExecutionRecord> {
    // Defer events that are too expensive to include in every shard.
    deferred.append(&mut record.defer(&opts.retained_events_presets));

    let can_pack_global_memory = done
        && record.estimated_trace_area <= split_opts.pack_trace_threshold
        && deferred.global_memory_initialize_events.len() <= split_opts.combine_memory_threshold
        && deferred.global_memory_finalize_events.len() <= split_opts.combine_memory_threshold
        && deferred.global_page_prot_initialize_events.len()
            <= split_opts.combine_page_prot_threshold
        && deferred.global_page_prot_finalize_events.len()
            <= split_opts.combine_page_prot_threshold;

    // See if any deferred shards are ready to be committed to.
    let deferred_records = deferred.split(done, record, can_pack_global_memory, split_opts);
    tracing::trace!("split deffered into {} records", deferred_records.len());

    deferred_records
}

/// Generate the dependencies and send the records to the prover channel.
#[tracing::instrument(name = "start_prove", skip_all)]
async fn start_prove<F: PrimeField32>(
    machine: Machine<F, RiscvAir<F>>,
    record_tx: mpsc::UnboundedSender<(ExecutionRecord, Option<MemoryPermit>)>,
    permit: Option<MemoryPermit>,
    mut record: ExecutionRecord,
    mut deferred_records: Vec<ExecutionRecord>,
) {
    tracing::debug!("num deferred records: {:#?}", deferred_records.len());

    // Generate the dependencies.
    tokio::task::spawn_blocking({
        let machine = machine.clone();
        let record_tx = record_tx.clone();

        move || {
            let record_iter = std::iter::once(&mut record);
            machine.generate_dependencies(record_iter, None);
            machine.generate_dependencies(deferred_records.iter_mut(), None);

            // Send the records to the output channel.
            record_tx.send((record, permit)).unwrap();

            // If there are deferred records, send them to the output channel.
            for record in deferred_records {
                record_tx.send((record, None)).unwrap();
            }
        }
    })
    .await
    .expect("failed to send records");
}

/// Send the splice trace to a available record worker.
#[tracing::instrument(name = "send_spliced_trace_blocking", skip_all)]
fn send_spliced_trace_blocking(
    record_worker_channels: Arc<WorkerQueue<UnboundedSender<RecordTask>>>,
    chunk: SplicedMinimalTrace<TraceChunkRaw>,
) {
    loop {
        match record_worker_channels.clone().try_pop() {
            Ok(worker) => {
                worker.send(RecordTask { chunk }).unwrap();
                break;
            }
            Err(TryAcquireWorkerError(TryAcquireError::NoPermits)) => {
                std::hint::spin_loop();
            }
            Err(_) => {
                panic!("failed to send spliced trace to record worker");
            }
        }
    }
}
