use std::{
    borrow::Borrow,
    collections::BTreeMap,
    fs::File,
    io::{self, Seek, SeekFrom},
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedSender};

use crate::{executor::MachineExecutor, riscv::RiscvAir};
use thiserror::Error;

use slop_algebra::PrimeField32;
use slop_challenger::IopCtx;
use sp1_hypercube::{
    air::PublicValues,
    prover::{
        MachineProverBuilder, MachineProverComponents, MachineProvingKey, MemoryPermit,
        ProverSemaphore,
    },
    Machine, MachineProof, MachineRecord, ShardProof, ShardVerifier,
};

use crate::{io::SP1Stdin, utils::concurrency::TurnBasedSync};
use sp1_core_executor::{ExecutionState, SP1CoreOpts, SplitOpts};

use sp1_core_executor::{
    subproof::NoOpSubproofVerifier, ExecutionError, ExecutionRecord, ExecutionReport, Executor,
    Program, SP1Context,
};

pub fn generate_checkpoints(
    mut runtime: Executor,
    checkpoints_tx: Sender<(usize, File, bool, u64)>,
) -> Result<Vec<u8>, SP1CoreProverError> {
    let mut index = 0;
    loop {
        // Enter the span.
        let span = tracing::debug_span!("batch");
        let _span = span.enter();

        // Execute the runtime until we reach a checkpoint.
        let (checkpoint, _, done) =
            runtime.execute_state(false).map_err(SP1CoreProverError::ExecutionError)?;

        // Save the checkpoint to a temp file.
        let mut checkpoint_file = tempfile::tempfile().map_err(SP1CoreProverError::IoError)?;
        checkpoint.save(&mut checkpoint_file).map_err(SP1CoreProverError::IoError)?;

        // Send the checkpoint.
        checkpoints_tx
            .blocking_send((index, checkpoint_file, done, runtime.state.global_clk))
            .unwrap();

        // If we've reached the final checkpoint, break out of the loop.
        if done {
            break Ok(runtime.state.public_values_stream);
        }

        // Update the index.
        index += 1;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn generate_records<F: PrimeField32>(
    machine: &Machine<F, RiscvAir<F>>,
    program: Arc<Program>,
    record_gen_sync: Arc<TurnBasedSync>,
    checkpoints_rx: Arc<Mutex<Receiver<(usize, File, bool, u64)>>>,
    records_tx: UnboundedSender<(ExecutionRecord, Option<MemoryPermit>)>,
    state: Arc<Mutex<PublicValues<u32, u64, u64, u32>>>,
    deferred: Arc<Mutex<ExecutionRecord>>,
    report_aggregate: Arc<Mutex<ExecutionReport>>,
    opts: SP1CoreOpts,
) {
    let split_opts =
        SplitOpts::new(&opts, program.instructions.len(), program.enable_untrusted_programs);
    loop {
        let received = { checkpoints_rx.lock().unwrap().blocking_recv() };
        if let Some((index, mut checkpoint, done, _)) = received {
            let (mut record, report) = tracing::debug_span!("trace checkpoint")
                .in_scope(|| trace_checkpoint(program.clone(), &checkpoint, opts.clone()));

            // Trace the checkpoint and reconstruct the execution records.
            *report_aggregate.lock().unwrap() += report;
            checkpoint.seek(SeekFrom::Start(0)).expect("failed to seek to start of tempfile");

            // Wait for our turn to update the state.
            record_gen_sync.wait_for_turn(index);

            // Update the public values & prover state for the shards which contain
            // "cpu events".
            let mut state = state.lock().unwrap();
            state.is_execution_shard = 1;
            state.pc_start = record.public_values.pc_start;
            state.next_pc = record.public_values.next_pc;
            state.initial_timestamp = record.public_values.initial_timestamp;
            state.last_timestamp = record.public_values.last_timestamp;
            state.is_first_execution_shard = (record.public_values.initial_timestamp == 1) as u32;

            let initial_timestamp_high = (state.initial_timestamp >> 24) as u32;
            let initial_timestamp_low = (state.initial_timestamp & 0xFFFFFF) as u32;
            let last_timestamp_high = (state.last_timestamp >> 24) as u32;
            let last_timestamp_low = (state.last_timestamp & 0xFFFFFF) as u32;

            state.initial_timestamp_inv = if state.initial_timestamp == 1 {
                0
            } else {
                F::from_canonical_u32(initial_timestamp_high + initial_timestamp_low - 1)
                    .inverse()
                    .as_canonical_u32()
            };

            state.last_timestamp_inv =
                F::from_canonical_u32(last_timestamp_high + last_timestamp_low - 1)
                    .inverse()
                    .as_canonical_u32();
            if initial_timestamp_high == last_timestamp_high {
                state.is_timestamp_high_eq = 1;
            } else {
                state.is_timestamp_high_eq = 0;
                state.inv_timestamp_high = (F::from_canonical_u32(last_timestamp_high)
                    - F::from_canonical_u32(initial_timestamp_high))
                .inverse()
                .as_canonical_u32();
            }
            if initial_timestamp_low == last_timestamp_low {
                state.is_timestamp_low_eq = 1;
            } else {
                state.is_timestamp_low_eq = 0;
                state.inv_timestamp_low = (F::from_canonical_u32(last_timestamp_low)
                    - F::from_canonical_u32(initial_timestamp_low))
                .inverse()
                .as_canonical_u32();
            }
            if state.committed_value_digest == [0u32; 8] {
                state.committed_value_digest = record.public_values.committed_value_digest;
            }
            if state.deferred_proofs_digest == [0u32; 8] {
                state.deferred_proofs_digest = record.public_values.deferred_proofs_digest;
            }
            if state.commit_syscall == 0 {
                state.commit_syscall = record.public_values.commit_syscall;
            }
            if state.commit_deferred_syscall == 0 {
                state.commit_deferred_syscall = record.public_values.commit_deferred_syscall;
            }
            if state.exit_code == 0 {
                state.exit_code = record.public_values.exit_code;
            }
            record.public_values = *state;
            state.prev_exit_code = state.exit_code;
            state.prev_commit_syscall = state.commit_syscall;
            state.prev_commit_deferred_syscall = state.commit_deferred_syscall;
            state.prev_committed_value_digest = state.committed_value_digest;
            state.prev_deferred_proofs_digest = state.deferred_proofs_digest;
            state.initial_timestamp = state.last_timestamp;

            // Defer events that are too expensive to include in every shard.
            let mut deferred = deferred.lock().unwrap();
            deferred.append(&mut record.defer(&[]));

            // See if any deferred shards are ready to be committed to.
            let mut deferred = deferred.split(done, &mut record, false, &split_opts);
            tracing::debug!("deferred {} records", deferred.len());

            // Update the public values & prover state for the shards which do not
            // contain "cpu events" before committing to them.
            for record in deferred.iter_mut() {
                state.previous_init_addr = record.public_values.previous_init_addr;
                state.last_init_addr = record.public_values.last_init_addr;
                state.previous_finalize_addr = record.public_values.previous_finalize_addr;
                state.last_finalize_addr = record.public_values.last_finalize_addr;
                state.previous_init_page_idx = record.public_values.previous_init_page_idx;
                state.last_init_page_idx = record.public_values.last_init_page_idx;
                state.previous_finalize_page_idx = record.public_values.previous_finalize_page_idx;
                state.last_finalize_page_idx = record.public_values.last_finalize_page_idx;
                state.pc_start = state.next_pc;
                state.prev_exit_code = state.exit_code;
                state.prev_commit_syscall = state.commit_syscall;
                state.prev_commit_deferred_syscall = state.commit_deferred_syscall;
                state.prev_committed_value_digest = state.committed_value_digest;
                state.prev_deferred_proofs_digest = state.deferred_proofs_digest;
                state.last_timestamp = state.initial_timestamp;
                state.is_timestamp_high_eq = 1;
                state.is_timestamp_low_eq = 1;
                state.is_first_execution_shard = 0;
                state.is_execution_shard = 0;

                let initial_timestamp_high = (state.initial_timestamp >> 24) as u32;
                let initial_timestamp_low = (state.initial_timestamp & 0xFFFFFF) as u32;
                let last_timestamp_high = (state.last_timestamp >> 24) as u32;
                let last_timestamp_low = (state.last_timestamp & 0xFFFFFF) as u32;

                state.is_first_execution_shard =
                    (record.public_values.initial_timestamp == 1) as u32;
                state.initial_timestamp_inv =
                    F::from_canonical_u32(initial_timestamp_high + initial_timestamp_low - 1)
                        .inverse()
                        .as_canonical_u32();
                state.last_timestamp_inv =
                    F::from_canonical_u32(last_timestamp_high + last_timestamp_low - 1)
                        .inverse()
                        .as_canonical_u32();
                record.public_values = *state;
            }

            // Generate the dependencies.
            let mut records = Vec::new();
            records.push(*record);
            records.extend(deferred);
            machine.generate_dependencies(records.iter_mut(), None);

            // Let another worker update the state.
            record_gen_sync.advance_turn();

            // Send the records to the prover.
            for record in records {
                records_tx.send((record, None)).unwrap();
            }
        } else {
            break;
        }
    }
}

pub async fn prove_core<GC, PC>(
    verifier: ShardVerifier<GC, PC::Config, RiscvAir<GC::F>>,
    prover: Arc<PC::Prover>,
    pk: Arc<MachineProvingKey<GC, PC>>,
    program: Arc<Program>,
    stdin: SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context<'static>,
) -> Result<(MachineProof<GC, PC::Config>, u64), SP1CoreProverError>
where
    GC: IopCtx,
    PC: MachineProverComponents<GC, Air = RiscvAir<GC::F>>,
    GC::F: PrimeField32,
{
    let (proof_tx, mut proof_rx) = tokio::sync::mpsc::unbounded_channel();

    let (_, cycles) =
        prove_core_stream::<GC, PC>(verifier, prover, pk, program, stdin, opts, context, proof_tx)
            .await
            .unwrap();

    let mut shard_proofs = BTreeMap::new();
    while let Some(proof) = proof_rx.recv().await {
        let public_values: &PublicValues<[GC::F; 4], [GC::F; 3], [GC::F; 4], GC::F> =
            proof.public_values.as_slice().borrow();
        shard_proofs.insert(
            (
                public_values.initial_timestamp,
                public_values.last_timestamp,
                public_values.previous_init_addr,
                public_values.previous_finalize_addr,
            ),
            proof,
        );
    }
    let shard_proofs = shard_proofs.into_values().collect();
    let proof = MachineProof { shard_proofs };

    Ok((proof, cycles))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn prove_core_stream<GC, PC>(
    // TODO: clean this up
    verifier: ShardVerifier<GC, PC::Config, RiscvAir<GC::F>>,
    prover: Arc<PC::Prover>,
    pk: Arc<MachineProvingKey<GC, PC>>,
    program: Arc<Program>,
    stdin: SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context<'static>,
    proof_tx: UnboundedSender<ShardProof<GC, PC::Config>>,
) -> Result<(Vec<u8>, u64), SP1CoreProverError>
where
    GC: IopCtx,
    PC: MachineProverComponents<GC, Air = RiscvAir<GC::F>>,
    GC::F: PrimeField32,
{
    // TODO: get this from input
    let num_record_workers = 4;
    let num_trace_gen_workers = 4;
    let (records_tx, mut records_rx) =
        mpsc::unbounded_channel::<(ExecutionRecord, Option<MemoryPermit>)>();

    let record_memory = sysinfo::System::new_all().total_memory() / 7;

    let machine_executor = MachineExecutor::<GC::F>::new(
        record_memory.try_into().unwrap_or_else(|_| {
            tracing::warn!(
                "truncating available memory {record_memory} into {}. this is a bug.",
                usize::MAX
            );
            usize::MAX
        }),
        num_record_workers,
        opts.clone(),
    );

    let prover_permits = ProverSemaphore::new(5);
    let prover = MachineProverBuilder::<GC, PC>::new(verifier, vec![prover_permits], vec![prover])
        .num_workers(num_trace_gen_workers)
        .build();

    let prover_handle = tokio::spawn(async move {
        let mut handles = Vec::new();
        while let Some(record) = records_rx.recv().await {
            let handle = prover.prove_shard(pk.clone(), record.0);
            handles.push(handle);
        }
        for handle in handles {
            let proof = handle.await;
            proof_tx.send(proof).unwrap();
        }
    });

    // Run the machine executor.
    let output = machine_executor.execute(program, stdin, context, records_tx).await.unwrap();

    // Wait for the prover to finish.
    prover_handle.await.unwrap();

    let pv_stream = output.public_value_stream;
    let cycles = output.cycles;

    Ok((pv_stream, cycles))
}

pub fn trace_checkpoint(
    program: Arc<Program>,
    file: &File,
    opts: SP1CoreOpts,
) -> (Box<ExecutionRecord>, ExecutionReport) {
    let noop = NoOpSubproofVerifier;

    let mut reader = std::io::BufReader::new(file);
    let state: ExecutionState =
        bincode::deserialize_from(&mut reader).expect("failed to deserialize state");
    let mut runtime = Executor::recover(program, state, opts);

    // We already passed the deferred proof verifier when creating checkpoints, so the proofs were
    // already verified. So here we use a noop verifier to not print any warnings.
    runtime.subproof_verifier = Some(Arc::new(noop));

    // Execute from the checkpoint.
    let (mut record, mut done) = runtime.execute_record(true).unwrap();
    let mut pv = record.public_values;

    // Handle the case where the COMMIT happens across the last two shards.
    if !done && (pv.commit_syscall == 1 || pv.commit_deferred_syscall == 1) {
        // We turn off the `print_report` flag to avoid modifying the report.
        runtime.print_report = false;
        loop {
            runtime.record.public_values = pv;
            let (_, next_pv, is_done) = runtime.execute_state(true).unwrap();
            pv = next_pv;
            done = is_done;
            if done {
                record.public_values.commit_syscall = 1;
                record.public_values.commit_deferred_syscall = 1;
                record.public_values.committed_value_digest = pv.committed_value_digest;
                record.public_values.deferred_proofs_digest = pv.deferred_proofs_digest;
                break;
            }
        }
    }

    (record, runtime.report)
}

#[derive(Error, Debug)]
pub enum SP1CoreProverError {
    #[error("failed to execute program: {0}")]
    ExecutionError(ExecutionError),
    #[error("io error: {0}")]
    IoError(io::Error),
    #[error("serialization error: {0}")]
    SerializationError(bincode::Error),
}
