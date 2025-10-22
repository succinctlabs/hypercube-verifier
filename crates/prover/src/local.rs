use crate::{SP1NormalizeInputShape, CORE_LOG_BLOWUP};
use futures::{
    prelude::*,
    stream::{FuturesOrdered, FuturesUnordered},
};
use slop_algebra::{AbstractField, PrimeField, PrimeField32};
use slop_bn254::Bn254Fr;
use slop_futures::queue::WorkerQueue;
use sp1_core_executor::{
    subproof::SubproofVerifier, ExecutionError, ExecutionRecord, ExecutionReport, Program,
    SP1Context, SP1CoreOpts, SP1RecursionProof,
};
use sp1_core_machine::{executor::MachineExecutor, io::SP1Stdin};
use sp1_hypercube::{
    air::{PublicValues, SP1CorePublicValues, ShardRange},
    prover::{MachineProvingKey, MemoryPermit},
    MachineVerifierConfigError, MachineVerifyingKey, ShardProof,
};
use sp1_primitives::{io::SP1PublicValues, SP1Field, SP1GlobalContext, SP1OuterGlobalContext};
use sp1_recursion_circuit::{
    machine::{SP1DeferredWitnessValues, SP1NormalizeWitnessValues, SP1ShapedWitnessValues},
    utils::{
        koalabear_bytes_to_bn254, koalabears_proof_nonce_to_bn254, koalabears_to_bn254,
        words_to_bytes,
    },
    witness::{OuterWitness, Witnessable},
    InnerSC,
};
use sp1_recursion_executor::{ExecutionRecord as RecursionRecord, RecursionPublicValues};
use sp1_recursion_gnark_ffi::{
    Groth16Bn254Proof, Groth16Bn254Prover, PlonkBn254Proof, PlonkBn254Prover,
};
use std::{borrow::Borrow, env, path::Path, sync::Arc};
use tokio::sync::{
    mpsc::{self},
    oneshot,
};
use tracing::Instrument;

use crate::{
    components::SP1ProverComponents,
    error::SP1ProverError,
    recursion::{CompressTree, ExecuteTask, RecursionProof, SP1RecursionProver},
    CoreSC, HashableKey, OuterSC, SP1CircuitWitness, SP1CoreProof, SP1CoreProofData, SP1Prover,
    SP1VerifyingKey,
};

#[derive(Debug, Clone)]
pub struct LocalProverOpts {
    pub core_opts: SP1CoreOpts,
    pub records_buffer_size: usize,
    pub num_record_workers: usize,
    pub num_recursion_executors: usize,
}

impl Default for LocalProverOpts {
    fn default() -> Self {
        let core_opts = SP1CoreOpts::default();

        let sysinfo = sysinfo::System::new_all();
        let total_memory = sysinfo.total_memory();
        let used_memory = sysinfo.used_memory();
        let free_memory = total_memory - used_memory;

        tracing::info!("Free memory at prover init: {} bytes", free_memory);

        // Allow half the available memory for tracegen by default.
        let records_buffer_size = free_memory / 2;
        let records_buffer_size = records_buffer_size.try_into().unwrap_or_else(|_| {
            tracing::error!(
                "truncating available memory {records_buffer_size} into {}. this is a bug.",
                usize::MAX
            );
            usize::MAX
        });

        // Reserve ~12Gb of memory for records by default.
        let records_buffer_size = env::var("SP1_PROVER_RECORDS_CAPACITY_BUFFER")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(records_buffer_size);

        const DEFAULT_NUM_RECORD_WORKERS: usize = 2;
        let num_record_workers = env::var("SP1_PROVER_NUM_RECORD_WORKERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_NUM_RECORD_WORKERS);

        const DEFAULT_NUM_RECURSION_EXECUTORS: usize = 4;
        let num_recursion_executors = env::var("SP1_PROVER_NUM_RECURSION_EXECUTORS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_NUM_RECURSION_EXECUTORS);

        Self { core_opts, records_buffer_size, num_record_workers, num_recursion_executors }
    }
}

pub struct LocalProver<C: SP1ProverComponents> {
    prover: SP1Prover<C>,
    executor: MachineExecutor<SP1Field>,
    compose_batch_size: usize,
    normalize_batch_size: usize,
    num_recursion_executors: usize,
}

impl<C: SP1ProverComponents> LocalProver<C> {
    pub fn new(prover: SP1Prover<C>, opts: LocalProverOpts) -> Self {
        let executor =
            MachineExecutor::new(opts.records_buffer_size, opts.num_record_workers, opts.core_opts);

        let compose_batch_size = prover.recursion().max_compose_arity();
        let normalize_batch_size = prover.recursion().normalize_batch_size();
        Self {
            prover,
            executor,
            compose_batch_size,
            normalize_batch_size,
            num_recursion_executors: opts.num_recursion_executors,
        }
    }

    pub fn execute(
        self: Arc<Self>,
        elf: &[u8],
        stdin: &SP1Stdin,
        // TODO: Fix
        _context: SP1Context,
    ) -> Result<(SP1PublicValues, [u8; 32], ExecutionReport), ExecutionError> {
        let new_context = SP1Context::default();
        let program = Arc::new(Program::from(elf).unwrap());
        let (public_values, filler, report) = self
            .executor
            .execute_sync(program, stdin.clone(), new_context)
            .map_err(|e| ExecutionError::Other(e.to_string()))?;
        Ok((public_values, filler, report))
    }

    /// Get a reference to the underlying [SP1Prover]
    #[inline]
    #[must_use]
    pub fn prover(&self) -> &SP1Prover<C> {
        &self.prover
    }

    /// Get a reference to the underlying [MachineExecutor]
    #[inline]
    #[must_use]
    pub fn executor(&self) -> &MachineExecutor<SP1Field> {
        &self.executor
    }

    /// Generate shard proofs which split up and prove the valid execution of a RISC-V program with
    /// the core prover. Uses the provided context.
    pub async fn prove_core(
        self: Arc<Self>,
        pk: Arc<MachineProvingKey<SP1GlobalContext, C::CoreComponents>>,
        program: Arc<Program>,
        stdin: SP1Stdin,
        mut context: SP1Context<'static>,
    ) -> Result<SP1CoreProof, SP1ProverError> {
        let dummy_vk = pk.as_ref().vk.clone();

        context.subproof_verifier = Some(Arc::new(self.clone()));

        let (records_tx, mut records_rx) =
            mpsc::unbounded_channel::<(ExecutionRecord, Option<MemoryPermit>)>();

        let prover = self.clone();

        let shard_proofs = tokio::spawn(async move {
            let mut shape_count = 0;
            let mut shard_proofs = Vec::new();
            let mut prove_shard_task = FuturesOrdered::new();
            loop {
                tokio::select! {
                    // Accquire a permit and start the exeuction.
                    Some((record, permit)) = records_rx.recv() => {
                        let shape = prover.prover.core().core_shape_from_record(&record).unwrap();

                        let proof = async {
                            let proof = prover
                                .prover
                                .core()
                                .prove_shard(pk.clone(), record)
                                .await;

                            drop(permit);

                            proof
                        };

                        prove_shard_task.push_back(proof);

                        if shape_count < 3 {
                            let prover = prover.clone();
                            let dummy_vk = dummy_vk.clone();
                            tokio::spawn(async move {
                                let normalize_shape = SP1NormalizeInputShape {
                                    proof_shapes: vec![shape],
                                    max_log_row_count: prover.prover.recursion_prover.core_verifier.max_log_row_count(),
                                    log_blowup: CORE_LOG_BLOWUP,
                                    log_stacking_height: prover.prover.recursion_prover.core_verifier.log_stacking_height() as usize,
                                };
                                let witness = normalize_shape.dummy_input(SP1VerifyingKey { vk: dummy_vk } );
                                prover.prover.recursion_prover.normalize_program(&witness);
                            });
                            shape_count += 1;
                        }
                    }
                    Some(proof) = prove_shard_task.next() => {
                        shard_proofs.push(proof);
                    }
                    else => {
                        break;
                    }
                }
            }
            Result::<_, SP1ProverError>::Ok(shard_proofs)
        }.in_current_span());

        // Run the machine executor with the generated nonce.
        let prover = self.clone();
        let inputs = stdin.clone();

        // Wait for the executor to finish.
        let output = prover
            .executor
            .execute(program, inputs, context, records_tx)
            .await
            .map_err(SP1ProverError::CoreExecutorError)?;

        let pv_stream = output.public_value_stream;
        let cycles = output.cycles;
        let public_values = SP1PublicValues::from(&pv_stream);
        let mut shard_proofs = shard_proofs.await.unwrap()?;
        // Sort the shard proofs by initial and last timestamp, as they come in out of order.
        shard_proofs.sort_by_key(|shard_proof| {
            let public_values: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
                shard_proof.public_values.as_slice().borrow();
            public_values.range()
        });

        // Check for high cycle count.
        Self::check_for_high_cycles(cycles);

        Ok(SP1CoreProof { proof: SP1CoreProofData(shard_proofs), stdin, public_values, cycles })
    }

    fn check_for_high_cycles(cycles: u64) {
        if cycles > 100_000_000 {
            tracing::warn!(
                    "High cycle count detected ({}M cycles). For better performance, consider using the Succinct Prover Network: https://docs.succinct.xyz/generating-proofs/prover-network",
                    cycles / 1_000_000
                );
        }
    }

    /// Generate shard proofs which split up and prove the valid execution of a RISC-V program with
    /// the core prover. Uses the provided context.
    pub async fn compress(
        self: Arc<Self>,
        vk: &SP1VerifyingKey,
        proof: SP1CoreProof,
        deferred_proofs: Vec<SP1RecursionProof<SP1GlobalContext, InnerSC>>,
    ) -> Result<SP1RecursionProof<SP1GlobalContext, InnerSC>, SP1ProverError> {
        // Initialize the recursion tree channels.
        let (compress_tree_tx, mut compress_tree_rx) = mpsc::unbounded_channel::<RecursionProof>();
        // Spawn the executor workers
        let (prove_task_tx, mut prove_task_rx) = mpsc::unbounded_channel::<ProveTask<C>>();
        let mut recursion_executors = Vec::new();
        for _ in 0..self.num_recursion_executors {
            let (executor_tx, mut executor_rx) = mpsc::unbounded_channel();
            recursion_executors.push(executor_tx);
            let prover = self.clone();
            let prove_task_tx = prove_task_tx.clone();
            let parent = tracing::Span::current();
            tokio::task::spawn_blocking(move || {
                let _guard = parent.enter();
                while let Some(task) = executor_rx.blocking_recv() {
                    let ExecuteTask { input, range } = task;
                    let keys = prover.prover().recursion().keys(&input);
                    let span = tracing::debug_span!("execute recursion program").entered();
                    let record = prover.prover().recursion().execute(input).unwrap();
                    span.exit();
                    let prove_task = ProveTask { keys, range, record };
                    prove_task_tx.send(prove_task).unwrap();
                }
            });
        }
        drop(prove_task_tx);
        let recursion_executors = Arc::new(WorkerQueue::new(recursion_executors));

        // Get the first layer inputs
        let inputs = self.get_first_layer_inputs(
            vk,
            &proof.proof.0,
            &deferred_proofs,
            self.normalize_batch_size,
        );

        let full_range = {
            let start = inputs[0].range().start();
            let end = inputs.last().unwrap().range().end();
            (start..end).into()
        };
        let number_of_core_shards = inputs.len();

        // Spawn the recursion tasks for the core shards.
        let executors = recursion_executors.clone();
        tokio::spawn(
            async move {
                for input in inputs.into_iter() {
                    // Get an executor for the input
                    let executor = executors.clone().pop().await.unwrap();
                    let range = input.range();
                    executor.send(ExecuteTask { input, range }).unwrap();
                }
            }
            .in_current_span(),
        );

        // Spawn the prover controller task
        let prover = self.clone();
        let tree_tx = compress_tree_tx.clone();
        tokio::spawn(async move {
            let mut setup_and_prove_tasks = FuturesUnordered::new();
            let mut prove_tasks = FuturesUnordered::new();
            loop {
                tokio::select! {
                    Some(task) = prove_task_rx.recv() => {
                        let ProveTask { keys, range, record } = task;
                        if let Some((pk, vk)) = keys {
                            let span = tracing::debug_span!("prove compress shard").entered();
                            let handle_prover = prover.clone();
                            let handle = async move {
                                let proof = handle_prover.prover().recursion().prove_shard(pk, record).await;
                                let proof = SP1RecursionProof { vk, proof };
                                RecursionProof { shard_range: range, proof }
                            };

                            prove_tasks.push(handle);
                            span.exit();
                        }
                        else {
                            let span = tracing::debug_span!("prove compress shard").entered();
                            let handle_prover = prover.clone();
                            let handle = async move {
                                let (vk, proof) = handle_prover.prover().recursion().setup_and_prove_shard(record.program.clone(), None, record).await;
                                let proof = SP1RecursionProof { vk, proof };
                                RecursionProof { shard_range: range, proof }
                            };

                            setup_and_prove_tasks.push(handle);
                            span.exit();
                        }
                    }
                    Some(proof) = setup_and_prove_tasks.next() => {
                        tree_tx.send(proof).unwrap();
                    }
                    Some(proof) = prove_tasks.next() => {
                        tree_tx.send(proof).unwrap();
                    }
                    else => {
                        break;
                    }
                }
            }
        }.in_current_span());

        // Reduce the proofs in the tree.
        let (full_range_tx, full_range_rx) = oneshot::channel();
        full_range_tx.send(full_range).unwrap();
        let pending_tasks = number_of_core_shards;
        let mut compress_tree = CompressTree::new(self.compose_batch_size);
        compress_tree
            .reduce_proofs(
                full_range_rx,
                &mut compress_tree_rx,
                recursion_executors.clone(),
                pending_tasks,
            )
            .await
    }

    #[tracing::instrument(name = "prove shrink", skip_all)]
    pub async fn shrink(
        &self,
        compressed_proof: SP1RecursionProof<SP1GlobalContext, InnerSC>,
    ) -> Result<SP1RecursionProof<SP1GlobalContext, InnerSC>, SP1ProverError> {
        // Make the compress proof.
        let SP1RecursionProof { vk: compressed_vk, proof: compressed_proof } = compressed_proof;
        let input = SP1ShapedWitnessValues {
            vks_and_proofs: vec![(compressed_vk.clone(), compressed_proof)],
            is_complete: true,
        };

        let input = self.prover.recursion().make_merkle_proofs(input);
        let witness = SP1CircuitWitness::Shrink(input);

        // Run key initialization and witness execution in parallel
        let key_task = async {
            let (_, vk) = self.prover.recursion().get_shrink_keys_async().await;
            Ok::<_, SP1ProverError>(vk)
        };

        let execute_task = async {
            self.prover
                .recursion()
                .execute(witness)
                .map_err(|e| SP1ProverError::Other(format!("Runtime panicked: {e}")))
        };

        let (vk, record) = tokio::try_join!(key_task, execute_task)?;

        let proof = self.prover.recursion().prove_shrink(record).await;

        Ok(SP1RecursionProof { vk, proof })
    }

    #[tracing::instrument(name = "prove wrap", skip_all)]
    pub async fn wrap(
        &self,
        shrunk_proof: SP1RecursionProof<SP1GlobalContext, InnerSC>,
    ) -> Result<SP1RecursionProof<SP1OuterGlobalContext, OuterSC>, SP1ProverError> {
        let SP1RecursionProof { vk: compressed_vk, proof: compressed_proof } = shrunk_proof;
        let input = SP1ShapedWitnessValues {
            vks_and_proofs: vec![(compressed_vk.clone(), compressed_proof)],
            is_complete: true,
        };
        let input = self.prover.recursion().make_merkle_proofs(input);
        let witness = SP1CircuitWitness::Wrap(input);
        // Run key initialization and witness execution in parallel
        let key_task = async {
            let (_, vk) = self.prover.recursion().get_wrap_keys_async().await;
            Ok::<_, SP1ProverError>(vk)
        };

        let execute_task = async {
            self.prover
                .recursion()
                .execute(witness)
                .map_err(|e| SP1ProverError::Other(format!("Runtime panicked: {e}")))
        };

        let (vk, record) = tokio::try_join!(key_task, execute_task)?;

        let proof = self.prover.recursion().prove_wrap(record).await;

        Ok(SP1RecursionProof { vk, proof })
    }

    #[tracing::instrument(name = "prove wrap plonk bn254", skip_all)]
    pub async fn wrap_plonk_bn254(
        &self,
        wrap_proof: SP1RecursionProof<SP1OuterGlobalContext, OuterSC>,
        build_dir: &Path,
    ) -> PlonkBn254Proof {
        let SP1RecursionProof { vk: wrap_vk, proof: wrap_proof } = wrap_proof;
        let input = SP1ShapedWitnessValues {
            vks_and_proofs: vec![(wrap_vk.clone(), wrap_proof.clone())],
            is_complete: true,
        };

        let pv: &RecursionPublicValues<SP1Field> = wrap_proof.public_values.as_slice().borrow();

        let vkey_hash = koalabears_to_bn254(&pv.sp1_vk_digest);
        let committed_values_digest_bytes: [SP1Field; 32] =
            words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
        let committed_values_digest = koalabear_bytes_to_bn254(&committed_values_digest_bytes);
        let exit_code = Bn254Fr::from_canonical_u32(pv.exit_code.as_canonical_u32());
        let vk_root = koalabears_to_bn254(&pv.vk_root);
        let proof_nonce = koalabears_proof_nonce_to_bn254(&pv.proof_nonce);
        let mut witness = OuterWitness::default();
        input.write(&mut witness);
        witness.write_committed_values_digest(committed_values_digest);
        witness.write_vkey_hash(vkey_hash);
        witness.write_exit_code(exit_code);
        witness.write_vk_root(vk_root);
        witness.write_proof_nonce(proof_nonce);
        let prover = PlonkBn254Prover::new();
        let proof = prover.prove(witness, build_dir.to_path_buf());

        // Verify the proof.
        prover
            .verify(
                &proof,
                &vkey_hash.as_canonical_biguint(),
                &committed_values_digest.as_canonical_biguint(),
                &exit_code.as_canonical_biguint(),
                &vk_root.as_canonical_biguint(),
                &proof_nonce.as_canonical_biguint(),
                build_dir,
            )
            .expect("Failed to verify proof");

        proof
    }

    #[tracing::instrument(name = "prove wrap plonk bn254", skip_all)]
    pub async fn wrap_groth16_bn254(
        &self,
        wrap_proof: SP1RecursionProof<SP1OuterGlobalContext, OuterSC>,
        build_dir: &Path,
    ) -> Groth16Bn254Proof {
        let SP1RecursionProof { vk: wrap_vk, proof: wrap_proof } = wrap_proof;
        let input = SP1ShapedWitnessValues {
            vks_and_proofs: vec![(wrap_vk.clone(), wrap_proof.clone())],
            is_complete: true,
        };

        let pv: &RecursionPublicValues<SP1Field> = wrap_proof.public_values.as_slice().borrow();

        let vkey_hash = koalabears_to_bn254(&pv.sp1_vk_digest);
        let committed_values_digest_bytes: [SP1Field; 32] =
            words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
        let committed_values_digest = koalabear_bytes_to_bn254(&committed_values_digest_bytes);
        let exit_code = Bn254Fr::from_canonical_u32(pv.exit_code.as_canonical_u32());
        let proof_nonce = koalabears_proof_nonce_to_bn254(&pv.proof_nonce);
        let vk_root = koalabears_to_bn254(&pv.vk_root);
        let mut witness = OuterWitness::default();
        input.write(&mut witness);
        witness.write_committed_values_digest(committed_values_digest);
        witness.write_vkey_hash(vkey_hash);
        witness.write_exit_code(exit_code);
        witness.write_vk_root(vk_root);
        witness.write_proof_nonce(proof_nonce);
        let prover = Groth16Bn254Prover::new();
        let proof = prover.prove(witness, build_dir.to_path_buf());

        // Verify the proof.
        prover
            .verify(
                &proof,
                &vkey_hash.as_canonical_biguint(),
                &committed_values_digest.as_canonical_biguint(),
                &exit_code.as_canonical_biguint(),
                &vk_root.as_canonical_biguint(),
                &proof_nonce.as_canonical_biguint(),
                build_dir,
            )
            .expect("Failed to verify wrap proof");

        proof
    }

    /// Generate the inputs for the first layer of recursive proofs.
    #[allow(clippy::type_complexity)]
    pub fn get_first_layer_inputs<'a>(
        &'a self,
        vk: &'a SP1VerifyingKey,
        shard_proofs: &[ShardProof<SP1GlobalContext, InnerSC>],
        deferred_proofs: &[SP1RecursionProof<SP1GlobalContext, InnerSC>],
        batch_size: usize,
    ) -> Vec<SP1CircuitWitness> {
        // We arbitrarily grab the page prot and nonce values from the first shard because it should
        // be the same for all shards.
        let pv: &SP1CorePublicValues<SP1Field> = shard_proofs[0].public_values.as_slice().borrow();
        let proof_nonce = pv.proof_nonce;

        let (deferred_inputs, deferred_digest) =
            self.get_deferred_inputs(&vk.vk, deferred_proofs, batch_size, proof_nonce);

        let is_complete = shard_proofs.len() == 1 && deferred_proofs.is_empty();
        let num_deferred_proofs = deferred_proofs.len();
        let core_inputs = self.get_normalize_witnesses(
            vk,
            shard_proofs,
            batch_size,
            is_complete,
            deferred_digest,
            num_deferred_proofs,
        );

        let mut inputs = Vec::new();
        inputs.extend(deferred_inputs.into_iter().map(SP1CircuitWitness::Deferred));
        inputs.extend(core_inputs.into_iter().map(SP1CircuitWitness::Core));
        inputs
    }

    #[inline]
    pub fn get_deferred_inputs<'a>(
        &'a self,
        vk: &'a MachineVerifyingKey<SP1GlobalContext, CoreSC>,
        deferred_proofs: &[SP1RecursionProof<SP1GlobalContext, InnerSC>],
        batch_size: usize,
        proof_nonce: [SP1Field; 4],
    ) -> (Vec<SP1DeferredWitnessValues<SP1GlobalContext, InnerSC>>, [SP1Field; 8]) {
        self.get_deferred_inputs_with_initial_digest(
            vk,
            deferred_proofs,
            [SP1Field::zero(); 8],
            batch_size,
            proof_nonce,
        )
    }

    pub fn get_deferred_inputs_with_initial_digest<'a>(
        &'a self,
        vk: &'a MachineVerifyingKey<SP1GlobalContext, CoreSC>,
        deferred_proofs: &[SP1RecursionProof<SP1GlobalContext, InnerSC>],
        initial_deferred_digest: [SP1Field; 8],
        batch_size: usize,
        proof_nonce: [SP1Field; 4],
    ) -> (Vec<SP1DeferredWitnessValues<SP1GlobalContext, InnerSC>>, [SP1Field; 8]) {
        // Prepare the inputs for the deferred proofs recursive verification.
        let mut deferred_digest = initial_deferred_digest;
        let mut deferred_inputs = Vec::new();

        let mut deferred_proof_index = 0;
        for batch in deferred_proofs.chunks(batch_size) {
            let vks_and_proofs =
                batch.iter().cloned().map(|proof| (proof.vk, proof.proof)).collect::<Vec<_>>();
            let num_deferred_proofs = vks_and_proofs.len();

            let input = SP1ShapedWitnessValues { vks_and_proofs, is_complete: true };
            let input = self.prover.recursion().make_merkle_proofs(input);

            deferred_inputs.push(SP1DeferredWitnessValues {
                vks_and_proofs: input.compress_val.vks_and_proofs,
                vk_merkle_data: input.merkle_val,
                start_reconstruct_deferred_digest: deferred_digest,
                sp1_vk_digest: vk.hash_koalabear(),
                end_pc: vk.pc_start,
                proof_nonce,
                deferred_proof_index: SP1Field::from_canonical_usize(deferred_proof_index),
            });

            deferred_digest = SP1RecursionProver::<C>::hash_deferred_proofs(deferred_digest, batch);
            deferred_proof_index += num_deferred_proofs;
        }
        // Check that we have the correct number of deferred proofs.
        assert_eq!(deferred_proof_index, deferred_proofs.len());
        (deferred_inputs, deferred_digest)
    }

    pub fn get_normalize_witnesses(
        &self,
        vk: &SP1VerifyingKey,
        shard_proofs: &[ShardProof<SP1GlobalContext, CoreSC>],
        batch_size: usize,
        is_complete: bool,
        deferred_digest: [SP1Field; 8],
        num_deferred_proofs: usize,
    ) -> Vec<SP1NormalizeWitnessValues<SP1GlobalContext, CoreSC>> {
        let mut core_inputs = Vec::new();

        // Prepare the inputs for the recursion programs.
        for batch in shard_proofs.chunks(batch_size) {
            let proofs = batch.to_vec();

            core_inputs.push(SP1NormalizeWitnessValues {
                vk: vk.vk.clone(),
                shard_proofs: proofs.clone(),
                is_complete,
                vk_root: self.prover.recursion().recursion_vk_root,
                reconstruct_deferred_digest: deferred_digest,
                num_deferred_proofs: SP1Field::from_canonical_usize(num_deferred_proofs),
            });
        }
        core_inputs
    }
}

impl<C: SP1ProverComponents> SubproofVerifier for LocalProver<C> {
    fn verify_deferred_proof(
        &self,
        proof: &SP1RecursionProof<SP1GlobalContext, InnerSC>,
        vk: &MachineVerifyingKey<SP1GlobalContext, CoreSC>,
        vk_hash: [u64; 4],
        committed_value_digest: [u64; 4],
    ) -> Result<(), MachineVerifierConfigError<SP1GlobalContext, CoreSC>> {
        self.prover.verify_deferred_proof(proof, vk, vk_hash, committed_value_digest)
    }
}

#[allow(clippy::type_complexity)]
struct ProveTask<C: SP1ProverComponents> {
    keys: Option<(
        Arc<MachineProvingKey<SP1GlobalContext, C::RecursionComponents>>,
        MachineVerifyingKey<SP1GlobalContext, InnerSC>,
    )>,
    range: ShardRange,
    record: RecursionRecord<SP1Field>,
}

#[cfg(all(test, feature = "experimental"))]
pub mod tests {
    use sp1_core_executor::RetainedEventsPreset;
    use tracing::Instrument;

    use slop_algebra::PrimeField32;

    use crate::{
        build::{try_build_groth16_bn254_artifacts_dev, try_build_plonk_bn254_artifacts_dev},
        components::CpuSP1ProverComponents,
        SP1ProverBuilder,
    };

    use super::*;

    use anyhow::Result;

    #[cfg(test)]
    use serial_test::serial;
    #[cfg(test)]
    use sp1_core_machine::utils::setup_logger;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Test {
        Core,
        Compress,
        Shrink,
        Wrap,
        OnChain,
    }

    pub async fn test_e2e_prover<C: SP1ProverComponents>(
        prover: Arc<LocalProver<C>>,
        elf: &[u8],
        stdin: SP1Stdin,
        test_kind: Test,
    ) -> Result<()> {
        let (pk, program, vk) = prover
            .prover()
            .core()
            .setup(elf)
            .instrument(tracing::debug_span!("setup").or_current())
            .await;

        let pk = unsafe { pk.into_inner() };

        let core_proof = prover
            .clone()
            .prove_core(pk, program, stdin, SP1Context::default())
            .instrument(tracing::info_span!("prove core"))
            .await
            .unwrap();

        let public_values = core_proof.public_values.clone();

        let cycles = core_proof.cycles as usize;
        let num_shards = core_proof.proof.0.len();
        tracing::info!("Cycles: {}, number of shards: {}", cycles, num_shards);

        // Verify the proof
        let core_proof_data = SP1CoreProofData(core_proof.proof.0.clone());
        prover.prover().verify(&core_proof_data, &vk).unwrap();

        if let Test::Core = test_kind {
            return Ok(());
        }

        // Make the compress proof.
        let compress_proof = prover
            .clone()
            .compress(&vk, core_proof, vec![])
            .instrument(tracing::info_span!("compress"))
            .await
            .unwrap();

        // Verify the compress proof
        prover.prover().verify_compressed(&compress_proof, &vk).unwrap();

        if let Test::Compress = test_kind {
            return Ok(());
        }

        let shrink_proof = prover.clone().shrink(compress_proof).await.unwrap();
        prover.prover().verify_shrink(&shrink_proof, &vk).unwrap();

        if let Test::Shrink = test_kind {
            return Ok(());
        }

        let wrap_proof = prover.clone().wrap(shrink_proof).await.unwrap();
        prover.prover().verify_wrap_bn254(&wrap_proof, &vk).unwrap();

        if let Test::Wrap = test_kind {
            return Ok(());
        }

        let artifacts_dir = try_build_plonk_bn254_artifacts_dev(&wrap_proof.vk, &wrap_proof.proof);
        let plonk_bn254_proof = prover.wrap_plonk_bn254(wrap_proof.clone(), &artifacts_dir).await;

        prover
            .prover()
            .verify_plonk_bn254(&plonk_bn254_proof, &vk, &public_values, &artifacts_dir)
            .unwrap();

        let artifacts_dir =
            try_build_groth16_bn254_artifacts_dev(&wrap_proof.vk, &wrap_proof.proof);
        let groth16_bn254_proof =
            prover.wrap_groth16_bn254(wrap_proof.clone(), &artifacts_dir).await;

        prover
            .prover()
            .verify_groth16_bn254(&groth16_bn254_proof, &vk, &public_values, &artifacts_dir)
            .unwrap();

        Ok(())
    }

    /// Tests an end-to-end workflow of proving a program across the entire proof generation
    /// pipeline.
    #[tokio::test]
    #[serial]
    async fn test_e2e() -> Result<()> {
        let elf = test_artifacts::FIBONACCI_ELF;
        setup_logger();

        let sp1_prover = SP1ProverBuilder::<CpuSP1ProverComponents>::new()
            .without_vk_verification()
            .build()
            .await;
        let opts = LocalProverOpts {
            core_opts: SP1CoreOpts {
                retained_events_presets: [RetainedEventsPreset::Sha256].into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let prover = Arc::new(LocalProver::new(sp1_prover, opts));

        test_e2e_prover::<CpuSP1ProverComponents>(prover, &elf, SP1Stdin::default(), Test::OnChain)
            .await
    }

    #[tokio::test]
    #[serial]
    async fn test_deferred_compress() -> Result<()> {
        setup_logger();

        let sp1_prover = SP1ProverBuilder::<CpuSP1ProverComponents>::new()
            .without_vk_verification()
            .build()
            .await;
        let opts = LocalProverOpts::default();
        let prover = Arc::new(LocalProver::new(sp1_prover, opts));

        // Test program which proves the Keccak-256 hash of various inputs.
        let keccak_elf = test_artifacts::KECCAK256_ELF;

        // Test program which verifies proofs of a vkey and a list of committed inputs.
        let verify_elf = test_artifacts::VERIFY_PROOF_ELF;

        tracing::info!("setup keccak elf");
        let (keccak_pk, keccak_program, keccak_vk) =
            prover.prover().core().setup(&keccak_elf).await;

        let keccak_pk = unsafe { keccak_pk.into_inner() };

        tracing::info!("setup verify elf");
        let (verify_pk, verify_program, verify_vk) =
            prover.prover().core().setup(&verify_elf).await;

        let verify_pk = unsafe { verify_pk.into_inner() };

        tracing::info!("prove subproof 1");
        let mut stdin = SP1Stdin::new();
        stdin.write(&1usize);
        stdin.write(&vec![0u8, 0, 0]);
        let deferred_proof_1 = prover
            .clone()
            .prove_core(keccak_pk.clone(), keccak_program.clone(), stdin, Default::default())
            .await?;
        let pv_1 = deferred_proof_1.public_values.as_slice().to_vec().clone();

        // Generate a second proof of keccak of various inputs.
        tracing::info!("prove subproof 2");
        let mut stdin = SP1Stdin::new();
        stdin.write(&3usize);
        stdin.write(&vec![0u8, 1, 2]);
        stdin.write(&vec![2, 3, 4]);
        stdin.write(&vec![5, 6, 7]);
        let deferred_proof_2 =
            prover.clone().prove_core(keccak_pk, keccak_program, stdin, Default::default()).await?;
        let pv_2 = deferred_proof_2.public_values.as_slice().to_vec().clone();

        // Generate recursive proof of first subproof.
        tracing::info!("compress subproof 1");
        let deferred_reduce_1 =
            prover.clone().compress(&keccak_vk, deferred_proof_1, vec![]).await?;
        prover.prover().verify_compressed(&deferred_reduce_1, &keccak_vk)?;

        // Generate recursive proof of second subproof.
        tracing::info!("compress subproof 2");
        let deferred_reduce_2 =
            prover.clone().compress(&keccak_vk, deferred_proof_2, vec![]).await?;
        prover.prover().verify_compressed(&deferred_reduce_2, &keccak_vk)?;

        // Run verify program with keccak vkey, subproofs, and their committed values.
        let mut stdin = SP1Stdin::new();
        let vkey_digest = keccak_vk.hash_koalabear();
        let vkey_digest: [u32; 8] = vkey_digest
            .iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        stdin.write(&vkey_digest);
        stdin.write(&vec![pv_1.clone(), pv_2.clone(), pv_2.clone()]);
        stdin.write_proof(deferred_reduce_1.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());

        tracing::info!("proving verify program (core)");
        let verify_proof =
            prover.clone().prove_core(verify_pk, verify_program, stdin, Default::default()).await?;

        prover.prover().verify(&verify_proof.proof, &verify_vk)?;

        // Generate recursive proof of verify program
        tracing::info!("compress verify program");
        let verify_reduce = prover
            .clone()
            .compress(
                &verify_vk,
                verify_proof,
                vec![deferred_reduce_1, deferred_reduce_2.clone(), deferred_reduce_2],
            )
            .await?;

        tracing::info!("verify verify program");
        prover.prover().verify_compressed(&verify_reduce, &verify_vk)?;

        Ok(())
    }
}
