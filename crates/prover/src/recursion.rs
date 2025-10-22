use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use slop_algebra::{AbstractField, PrimeField32};
use slop_basefold::BasefoldVerifier;
use slop_challenger::IopCtx;
use slop_stacked::StackedPcsVerifier;
use sp1_core_executor::SP1RecursionProof;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{
    air::{MachineAir, POSEIDON_NUM_WORDS, PROOF_NONCE_NUM_WORDS},
    inner_perm,
    prover::{MachineProver, MachineProverComponents, MachineProvingKey},
    Machine, MachineConfig, MachineVerifier, MachineVerifyingKey, ShardProof, ShardVerifier,
};
use sp1_primitives::{
    hash_deferred_proof, SP1ExtensionField, SP1Field, SP1GlobalContext, SP1OuterGlobalContext,
};
use sp1_recursion_circuit::{
    basefold::{
        merkle_tree::MerkleTree, stacked::RecursiveStackedPcsVerifier, tcs::RecursiveMerkleTreeTcs,
        RecursiveBasefoldVerifier,
    },
    jagged::{RecursiveJaggedEvalSumcheckConfig, RecursiveJaggedPcsVerifier},
    machine::{
        InnerVal, PublicValuesOutputDigest, SP1CompressRootVerifierWithVKey,
        SP1CompressWithVKeyVerifier, SP1CompressWithVKeyWitnessValues, SP1DeferredVerifier,
        SP1DeferredWitnessValues, SP1MerkleProofWitnessValues, SP1NormalizeWitnessValues,
        SP1RecursiveVerifier, SP1ShapedWitnessValues,
    },
    shard::RecursiveShardVerifier,
    witness::Witnessable,
    CircuitConfig, SP1FieldConfigVariable, WrapConfig as CircuitWrapConfig,
};
use sp1_recursion_compiler::{
    circuit::AsmCompiler,
    config::InnerConfig,
    ir::{Builder, DslIrProgram},
};
use sp1_recursion_executor::{
    shape::RecursionShape, ExecutionRecord, Executor, RecursionProgram, RecursionPublicValues,
    DIGEST_SIZE,
};

use crate::{
    components::SP1ProverComponents,
    shapes::{SP1NormalizeCache, SP1NormalizeInputShape, SP1RecursionProofShape},
    utils::words_to_bytes,
    CompressAir, CoreSC, HashableKey, InnerSC, OuterSC, SP1CircuitWitness, SP1RecursionProverError,
    WrapAir,
};

pub mod components;
mod tree;
pub use components::*;
pub use tree::*;

type RecursionConfig<C> =
    <<C as SP1ProverComponents>::RecursionComponents as MachineProverComponents<
        SP1GlobalContext,
    >>::Config;

// type SP1Field = SP1Field;

type WrapConfig<C> = <<C as SP1ProverComponents>::WrapComponents as MachineProverComponents<
    SP1OuterGlobalContext,
>>::Config;

#[allow(clippy::type_complexity)]
pub struct SP1RecursionProver<C: SP1ProverComponents> {
    pub(crate) prover: MachineProver<SP1GlobalContext, C::RecursionComponents>,
    pub(crate) shrink_prover: MachineProver<SP1GlobalContext, C::RecursionComponents>,
    wrap_prover: MachineProver<SP1OuterGlobalContext, C::WrapComponents>,
    pub(crate) core_verifier: MachineVerifier<SP1GlobalContext, CoreSC, RiscvAir<SP1Field>>,
    pub(crate) normalize_program_cache: SP1NormalizeCache,
    reduce_shape: SP1RecursionProofShape,
    compose_programs: BTreeMap<usize, Arc<RecursionProgram<SP1Field>>>,
    compose_keys: BTreeMap<
        usize,
        (
            Arc<MachineProvingKey<SP1GlobalContext, C::RecursionComponents>>,
            MachineVerifyingKey<SP1GlobalContext, RecursionConfig<C>>,
        ),
    >,
    deferred_program: Option<Arc<RecursionProgram<SP1Field>>>,
    deferred_keys: Option<(
        Arc<MachineProvingKey<SP1GlobalContext, C::RecursionComponents>>,
        MachineVerifyingKey<SP1GlobalContext, RecursionConfig<C>>,
    )>,
    shrink_program: Arc<RecursionProgram<SP1Field>>,
    shrink_keys: Mutex<
        Option<(
            Arc<MachineProvingKey<SP1GlobalContext, C::RecursionComponents>>,
            MachineVerifyingKey<SP1GlobalContext, RecursionConfig<C>>,
        )>,
    >,
    wrap_program: Arc<RecursionProgram<SP1Field>>,
    wrap_keys: Mutex<
        Option<(
            Arc<MachineProvingKey<SP1OuterGlobalContext, C::WrapComponents>>,
            MachineVerifyingKey<SP1OuterGlobalContext, WrapConfig<C>>,
        )>,
    >,
    pub recursive_core_verifier:
        RecursiveShardVerifier<SP1GlobalContext, RiscvAir<SP1Field>, InnerConfig>,
    pub(crate) recursive_compress_verifier:
        RecursiveShardVerifier<SP1GlobalContext, CompressAir<InnerVal>, InnerConfig>,
    /// The root of the allowed recursion verification keys.
    pub recursion_vk_root: <SP1GlobalContext as IopCtx>::Digest,
    /// The allowed vks and their corresponding indices.
    pub recursion_vk_map: BTreeMap<<SP1GlobalContext as IopCtx>::Digest, usize>,
    /// The merkle root of allowed vks.
    pub recursion_vk_tree: MerkleTree<SP1GlobalContext>,
    /// Whether to verify the vk.
    vk_verification: bool,
    maximum_compose_arity: usize,
    normalize_batch_size: usize,
}

impl<C: SP1ProverComponents> SP1RecursionProver<C> {
    pub async fn new(
        core_verifier: ShardVerifier<SP1GlobalContext, CoreSC, RiscvAir<SP1Field>>,
        prover: MachineProver<SP1GlobalContext, C::RecursionComponents>,
        shrink_prover: MachineProver<SP1GlobalContext, C::RecursionComponents>,
        wrap_prover: MachineProver<SP1OuterGlobalContext, C::WrapComponents>,
        normalize_programs_cache_size: usize,
        normalize_programs: BTreeMap<SP1NormalizeInputShape, Arc<RecursionProgram<SP1Field>>>,
        max_compose_arity: usize,
        vk_verification: bool,
        compute_recursion_vks_at_initialization: bool,
        vk_map_path: Option<String>,
    ) -> Self {
        let recursive_core_verifier =
            recursive_verifier::<SP1GlobalContext, _, CoreSC, InnerConfig>(&core_verifier);

        let recursive_compress_verifier =
            recursive_verifier::<SP1GlobalContext, _, InnerSC, InnerConfig>(
                prover.verifier().shard_verifier(),
            );

        let recursive_shrink_verifier =
            recursive_verifier::<SP1GlobalContext, _, InnerSC, CircuitWrapConfig>(
                shrink_prover.verifier().shard_verifier(),
            );

        // Instantiate the cache.
        let normalize_program_cache = SP1NormalizeCache::new(normalize_programs_cache_size);
        for (shape, program) in normalize_programs {
            normalize_program_cache.push(shape, program);
        }

        // Get the reduce shape.
        let reduce_shape =
            SP1RecursionProofShape::compress_proof_shape_from_arity(max_compose_arity)
                .expect("arity not supported");

        // Make the reduce programs and keys.
        let mut compose_programs = BTreeMap::new();
        let mut compose_keys = BTreeMap::new();

        let file = std::fs::File::open(vk_map_path.unwrap_or("./src/vk_map.bin".to_string())).ok();

        let allowed_vk_map: BTreeMap<[SP1Field; DIGEST_SIZE], usize> = if vk_verification {
            file.and_then(|file| bincode::deserialize_from(file).ok()).unwrap_or_else(|| {
                (0..1 << 18)
                    .map(|i| ([SP1Field::from_canonical_u32(i as u32); DIGEST_SIZE], i))
                    .collect()
            })
        } else {
            // Dummy merkle tree when vk_verification is false.
            (0..1 << 18)
                .map(|i| ([SP1Field::from_canonical_u32(i as u32); DIGEST_SIZE], i))
                .collect()
        };

        let (root, merkle_tree) = MerkleTree::commit(allowed_vk_map.keys().copied().collect());
        if compute_recursion_vks_at_initialization {
            for arity in 1..=max_compose_arity {
                let dummy_input =
                    dummy_compose_input(&prover, &reduce_shape, arity, merkle_tree.height);
                let mut program = compose_program_from_input(
                    &recursive_compress_verifier,
                    vk_verification,
                    &dummy_input,
                );
                program.shape = Some(reduce_shape.shape.clone());
                let program = Arc::new(program);

                // Make the reduce keys.
                let (pk, vk) = prover.setup(program.clone(), None).await;
                let pk = unsafe { pk.into_inner() };
                compose_keys.insert(arity, (pk, vk));
                compose_programs.insert(arity, program);
            }
        }
        let shrink_input = dummy_compose_input(&prover, &reduce_shape, 1, merkle_tree.height);
        let shrink_program =
            shrink_program_from_input(&recursive_compress_verifier, vk_verification, &shrink_input);
        let shrink_program = Arc::new(shrink_program);

        let (pk, _) = shrink_prover.setup(shrink_program.clone(), None).await;

        let pk: Arc<MachineProvingKey<SP1GlobalContext, C::RecursionComponents>> =
            unsafe { pk.into_inner() };

        let shrink_proof_shape = SP1RecursionProofShape {
            shape: RecursionShape::new(<C::RecursionComponents as MachineProverComponents<
                SP1GlobalContext,
            >>::preprocessed_table_heights(pk).await),
        };

        let wrap_input =
            dummy_compose_input(&shrink_prover, &shrink_proof_shape, 1, merkle_tree.height);

        let wrap_program =
            wrap_program_from_input(&recursive_shrink_verifier, vk_verification, &wrap_input);
        let wrap_program = Arc::new(wrap_program);

        //  Make the deferred program and proving key.
        let deferred_input = dummy_deferred_input(&prover, &reduce_shape, merkle_tree.height);
        let mut program = deferred_program_from_input(
            &recursive_compress_verifier,
            vk_verification,
            &deferred_input,
        );
        program.shape = Some(reduce_shape.shape.clone());
        let program = Arc::new(program);

        let shrink_keys = Mutex::new(None);
        let wrap_keys = Mutex::new(None);

        // Make the deferred keys.
        let (pk, vk) = prover.setup(program.clone(), None).await;
        let pk = unsafe { pk.into_inner() };
        let deferred_keys = Some((pk, vk));
        let deferred_program = Some(program);

        Self {
            prover,
            shrink_prover,
            wrap_prover,
            core_verifier: MachineVerifier::new(core_verifier),
            recursive_core_verifier,
            recursive_compress_verifier,
            normalize_program_cache,
            reduce_shape,
            compose_keys,
            compose_programs,
            deferred_program,
            deferred_keys,
            shrink_program,
            shrink_keys,
            wrap_program,
            wrap_keys,
            maximum_compose_arity: max_compose_arity,
            normalize_batch_size: 1,
            recursion_vk_map: allowed_vk_map,
            recursion_vk_root: root,
            recursion_vk_tree: merkle_tree,
            vk_verification,
        }
    }

    pub fn make_merkle_proofs(
        &self,
        input: SP1ShapedWitnessValues<SP1GlobalContext, CoreSC>,
    ) -> SP1CompressWithVKeyWitnessValues<CoreSC> {
        let num_vks = self.recursion_vk_map.len();
        let (vk_indices, vk_digest_values): (Vec<_>, Vec<_>) = if self.vk_verification {
            input
                .vks_and_proofs
                .iter()
                .map(|(vk, _)| {
                    let vk_digest = vk.hash_koalabear();
                    let index = self.recursion_vk_map.get(&vk_digest).expect("vk not allowed");
                    (index, vk_digest)
                })
                .unzip()
        } else {
            input
                .vks_and_proofs
                .iter()
                .map(|(vk, _)| {
                    let vk_digest = vk.hash_koalabear();
                    let index = (vk_digest[0].as_canonical_u32() as usize) % num_vks;
                    (index, [SP1Field::from_canonical_usize(index); 8])
                })
                .unzip()
        };

        let proofs = vk_indices
            .iter()
            .map(|index| {
                let (value, proof) = MerkleTree::open(&self.recursion_vk_tree, *index);

                MerkleTree::verify(proof.clone(), value, self.recursion_vk_root)
                    .expect("invalid proof");
                proof
            })
            .collect();

        let merkle_val = SP1MerkleProofWitnessValues {
            root: self.recursion_vk_root,
            values: vk_digest_values,
            vk_merkle_proofs: proofs,
        };

        SP1CompressWithVKeyWitnessValues { compress_val: input, merkle_val }
    }

    pub fn verifier(
        &self,
    ) -> &MachineVerifier<SP1GlobalContext, RecursionConfig<C>, CompressAir<SP1Field>> {
        self.prover.verifier()
    }

    pub fn vk_verification(&self) -> bool {
        self.vk_verification
    }

    pub fn shrink_verifier(
        &self,
    ) -> &MachineVerifier<SP1GlobalContext, RecursionConfig<C>, CompressAir<SP1Field>> {
        self.shrink_prover.verifier()
    }

    pub fn wrap_verifier(
        &self,
    ) -> &MachineVerifier<SP1OuterGlobalContext, WrapConfig<C>, WrapAir<SP1Field>> {
        self.wrap_prover.verifier()
    }

    pub fn machine(&self) -> &Machine<SP1Field, CompressAir<SP1Field>> {
        self.prover.machine()
    }

    /// Get the maximum compose arity supported by the prover.
    pub fn max_compose_arity(&self) -> usize {
        self.maximum_compose_arity
    }

    #[inline]
    #[must_use]
    pub async fn prove_shard(
        &self,
        pk: Arc<MachineProvingKey<SP1GlobalContext, C::RecursionComponents>>,
        record: ExecutionRecord<SP1Field>,
    ) -> ShardProof<SP1GlobalContext, InnerSC> {
        self.prover.prove_shard(pk, record).await
    }

    #[inline]
    #[must_use]
    pub async fn prove_shrink(
        &self,
        record: ExecutionRecord<SP1Field>,
    ) -> ShardProof<SP1GlobalContext, InnerSC> {
        let shrink_keys = self.get_shrink_keys();
        self.shrink_prover.prove_shard(shrink_keys.0, record).await
    }

    #[inline]
    #[must_use]
    pub async fn prove_wrap(
        &self,
        record: ExecutionRecord<SP1Field>,
    ) -> ShardProof<SP1OuterGlobalContext, OuterSC> {
        let wrap_keys = self.get_wrap_keys();
        self.wrap_prover.prove_shard(wrap_keys.0, record).await
    }

    #[inline]
    #[must_use]
    pub async fn setup_and_prove_shard(
        &self,
        program: Arc<RecursionProgram<SP1Field>>,
        vk: Option<MachineVerifyingKey<SP1GlobalContext, InnerSC>>,
        record: ExecutionRecord<SP1Field>,
    ) -> (MachineVerifyingKey<SP1GlobalContext, InnerSC>, ShardProof<SP1GlobalContext, InnerSC>)
    {
        self.prover.setup_and_prove_shard(program, vk, record).await
    }

    #[inline]
    pub fn normalize_batch_size(&self) -> usize {
        self.normalize_batch_size
    }

    pub fn normalize_program(
        &self,
        input: &SP1NormalizeWitnessValues<SP1GlobalContext, CoreSC>,
    ) -> Arc<RecursionProgram<SP1Field>> {
        let proof_shapes = input
            .shard_proofs
            .iter()
            .map(|proof| self.core_verifier.shape_from_proof(proof))
            .collect::<Vec<_>>();
        let shape = SP1NormalizeInputShape {
            proof_shapes,
            max_log_row_count: self.core_verifier.max_log_row_count(),
            log_blowup: self.core_verifier.fri_config().log_blowup,
            log_stacking_height: self.core_verifier.log_stacking_height() as usize,
        };
        if let Some(program) = self.normalize_program_cache.get(&shape) {
            return program.clone();
        }

        let mut program = normalize_program_from_input(&self.recursive_core_verifier, input);
        program.shape = Some(self.reduce_shape.shape.clone());
        let program = Arc::new(program);
        self.normalize_program_cache.push(shape, program.clone());
        program
    }

    pub fn compress_program(
        &self,
        input: &SP1CompressWithVKeyWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<SP1Field>> {
        let arity = input.compress_val.vks_and_proofs.len();
        self.compose_programs[&arity].clone()
    }

    pub fn normalize_program_cache_stats(&self) -> (usize, usize, f64) {
        self.normalize_program_cache.stats()
    }

    #[inline]
    #[must_use]
    pub fn compose_program_from_input(
        &self,
        input: &SP1CompressWithVKeyWitnessValues<InnerSC>,
    ) -> RecursionProgram<SP1Field> {
        compose_program_from_input(&self.recursive_compress_verifier, self.vk_verification, input)
    }

    pub fn dummy_reduce_input(&self, arity: usize) -> SP1CompressWithVKeyWitnessValues<InnerSC> {
        self.dummy_reduce_input_with_shape(arity, &self.reduce_shape)
    }

    pub fn dummy_reduce_input_with_shape(
        &self,
        arity: usize,
        shape: &SP1RecursionProofShape,
    ) -> SP1CompressWithVKeyWitnessValues<InnerSC> {
        dummy_compose_input(&self.prover, shape, arity, self.recursion_vk_tree.height)
    }

    #[inline]
    #[allow(clippy::type_complexity)]
    pub fn keys(
        &self,
        input: &SP1CircuitWitness,
    ) -> Option<(
        Arc<MachineProvingKey<SP1GlobalContext, C::RecursionComponents>>,
        MachineVerifyingKey<SP1GlobalContext, RecursionConfig<C>>,
    )> {
        match input {
            SP1CircuitWitness::Core(_) => None,
            SP1CircuitWitness::Deferred(_) => self.deferred_keys(),
            SP1CircuitWitness::Compress(input) => self.reduce_keys(input.vks_and_proofs.len()),
            SP1CircuitWitness::Shrink(_) => Some(self.get_shrink_keys()),
            SP1CircuitWitness::Wrap(_) => None,
        }
    }

    pub fn execute(
        &self,
        input: SP1CircuitWitness,
    ) -> Result<ExecutionRecord<SP1Field>, SP1RecursionProverError> {
        let (program, witness_stream) = tracing::debug_span!("get program and witness stream")
            .in_scope(|| match input {
                SP1CircuitWitness::Core(input) => {
                    let mut witness_stream = Vec::new();
                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                    (self.normalize_program(&input), witness_stream)
                }
                SP1CircuitWitness::Deferred(input) => {
                    let mut witness_stream = Vec::new();
                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                    (self.deferred_program(), witness_stream)
                }
                SP1CircuitWitness::Compress(input) => {
                    let mut witness_stream = Vec::new();
                    let input_with_merkle = self.make_merkle_proofs(input);
                    Witnessable::<InnerConfig>::write(&input_with_merkle, &mut witness_stream);
                    (self.compress_program(&input_with_merkle), witness_stream)
                }
                SP1CircuitWitness::Shrink(input) => {
                    let mut witness_stream = Vec::new();
                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                    (self.shrink_program.clone(), witness_stream)
                }
                SP1CircuitWitness::Wrap(input) => {
                    let mut witness_stream = Vec::new();
                    Witnessable::<CircuitWrapConfig>::write(&input, &mut witness_stream);

                    (self.wrap_program.clone(), witness_stream)
                }
            });

        // Execute the runtime.
        let runtime_span = tracing::debug_span!("execute runtime").entered();
        let mut runtime =
            Executor::<SP1Field, SP1ExtensionField, _>::new(program.clone(), inner_perm());
        runtime.witness_stream = witness_stream.into();
        runtime.run().map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))?;
        let mut record = runtime.record;
        runtime_span.exit();

        // Generate the dependencies.
        tracing::debug_span!("generate dependencies")
            .in_scope(|| self.machine().generate_dependencies(std::iter::once(&mut record), None));
        Ok(record)
    }

    pub async fn get_shrink_keys_async(
        &self,
    ) -> (
        Arc<MachineProvingKey<SP1GlobalContext, C::RecursionComponents>>,
        MachineVerifyingKey<SP1GlobalContext, RecursionConfig<C>>,
    ) {
        {
            let guard = self.shrink_keys.lock().unwrap();
            if let Some(ref keys) = *guard {
                return keys.clone();
            }
        }

        // Initialize keys asynchronously
        let (shrink_pk, shrink_vk) =
            self.shrink_prover.setup(self.shrink_program.clone(), None).await;
        let keys = (unsafe { shrink_pk.into_inner() }, shrink_vk);

        {
            let mut guard = self.shrink_keys.lock().unwrap();
            *guard = Some(keys.clone());
        }
        keys
    }

    #[allow(clippy::type_complexity)]
    pub fn get_shrink_keys(
        &self,
    ) -> (
        Arc<MachineProvingKey<SP1GlobalContext, C::RecursionComponents>>,
        MachineVerifyingKey<SP1GlobalContext, RecursionConfig<C>>,
    ) {
        let guard = self.shrink_keys.lock().unwrap();
        if let Some(ref keys) = *guard {
            return keys.clone();
        }

        // If keys aren't initialized yet, we need to be in an async context
        // This should only be called after async initialization
        panic!("Shrink keys not initialized - call get_shrink_keys_async first")
    }

    pub async fn get_wrap_keys_async(
        &self,
    ) -> (
        Arc<MachineProvingKey<SP1OuterGlobalContext, C::WrapComponents>>,
        MachineVerifyingKey<SP1OuterGlobalContext, WrapConfig<C>>,
    ) {
        {
            let guard = self.wrap_keys.lock().unwrap();
            if let Some(ref keys) = *guard {
                return keys.clone();
            }
        }

        // Initialize keys asynchronously
        let (wrap_pk, wrap_vk) = self.wrap_prover.setup(self.wrap_program.clone(), None).await;
        let keys = (unsafe { wrap_pk.into_inner() }, wrap_vk);

        {
            let mut guard = self.wrap_keys.lock().unwrap();
            *guard = Some(keys.clone());
        }
        keys
    }

    #[allow(clippy::type_complexity)]
    pub fn get_wrap_keys(
        &self,
    ) -> (
        Arc<MachineProvingKey<SP1OuterGlobalContext, C::WrapComponents>>,
        MachineVerifyingKey<SP1OuterGlobalContext, WrapConfig<C>>,
    ) {
        let guard = self.wrap_keys.lock().unwrap();
        if let Some(ref keys) = *guard {
            return keys.clone();
        }

        // If keys aren't initialized yet, we need to be in an async context
        // This should only be called after async initialization
        panic!("Wrap keys not initialized - call get_wrap_keys_async first")
    }

    #[inline]
    #[allow(clippy::type_complexity)]
    pub fn deferred_keys(
        &self,
    ) -> Option<(
        Arc<MachineProvingKey<SP1GlobalContext, C::RecursionComponents>>,
        MachineVerifyingKey<SP1GlobalContext, RecursionConfig<C>>,
    )> {
        self.deferred_keys.clone()
    }

    pub fn deferred_program(&self) -> Arc<RecursionProgram<SP1Field>> {
        self.deferred_program.clone().unwrap()
    }

    #[inline]
    #[allow(clippy::type_complexity)]
    pub fn reduce_keys(
        &self,
        arity: usize,
    ) -> Option<(
        Arc<MachineProvingKey<SP1GlobalContext, C::RecursionComponents>>,
        MachineVerifyingKey<SP1GlobalContext, RecursionConfig<C>>,
    )> {
        self.compose_keys.get(&arity).cloned()
    }

    pub fn hash_deferred_proofs(
        prev_digest: [SP1Field; DIGEST_SIZE],
        deferred_proofs: &[SP1RecursionProof<SP1GlobalContext, InnerSC>],
    ) -> [SP1Field; 8] {
        let mut digest = prev_digest;
        for proof in deferred_proofs.iter() {
            let pv: &RecursionPublicValues<SP1Field> =
                proof.proof.public_values.as_slice().borrow();
            let committed_values_digest = words_to_bytes(&pv.committed_value_digest);

            digest = hash_deferred_proof(
                &digest,
                &pv.sp1_vk_digest,
                &committed_values_digest.try_into().unwrap(),
            );
        }
        digest
    }
}

/// The program that proves the correct execution of the verifier of a single shard of the core
/// (RISC-V) machine.
pub fn normalize_program_from_input(
    recursive_verifier: &RecursiveShardVerifier<SP1GlobalContext, RiscvAir<SP1Field>, InnerConfig>,
    input: &SP1NormalizeWitnessValues<SP1GlobalContext, CoreSC>,
) -> RecursionProgram<SP1Field> {
    // Get the operations.
    let builder_span = tracing::debug_span!("build recursion program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    let input_variable = input.read(&mut builder);
    SP1RecursiveVerifier::<InnerConfig>::verify(&mut builder, recursive_verifier, input_variable);
    let block = builder.into_root_block();
    // SAFETY: The circuit is well-formed. It does not use synchronization primitives
    // (or possibly other means) to violate the invariants.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block) };
    builder_span.exit();

    // Compile the program.
    let compiler_span = tracing::debug_span!("compile recursion program").entered();
    let mut compiler = AsmCompiler::default();
    let program = compiler.compile(dsl_program);
    compiler_span.exit();
    program
}

/// The deferred program.
pub(crate) fn deferred_program_from_input(
    recursive_verifier: &RecursiveShardVerifier<
        SP1GlobalContext,
        CompressAir<InnerVal>,
        InnerConfig,
    >,
    vk_verification: bool,
    input: &SP1DeferredWitnessValues<SP1GlobalContext, InnerSC>,
) -> RecursionProgram<SP1Field> {
    // Get the operations.
    let operations_span = tracing::debug_span!("get operations for the deferred program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    let input_read_span = tracing::debug_span!("Read input values").entered();
    let input = input.read(&mut builder);
    input_read_span.exit();
    let verify_span = tracing::debug_span!("Verify deferred program").entered();

    // Verify the proof.
    SP1DeferredVerifier::verify(&mut builder, recursive_verifier, input, vk_verification);
    verify_span.exit();
    let block = builder.into_root_block();
    operations_span.exit();
    // SAFETY: The circuit is well-formed. It does not use synchronization primitives
    // (or possibly other means) to violate the invariants.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block) };

    let compiler_span = tracing::debug_span!("compile deferred program").entered();
    let mut compiler = AsmCompiler::default();
    let program = compiler.compile(dsl_program);
    compiler_span.exit();
    program
}

/// The "compose" program, which verifies some number of normalized shard proofs.
pub(crate) fn compose_program_from_input(
    recursive_verifier: &RecursiveShardVerifier<
        SP1GlobalContext,
        CompressAir<InnerVal>,
        InnerConfig,
    >,
    vk_verification: bool,
    input: &SP1CompressWithVKeyWitnessValues<InnerSC>,
) -> RecursionProgram<SP1Field> {
    let builder_span = tracing::debug_span!("build compress program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    // read the input.
    let input = input.read(&mut builder);

    // Verify the proof.
    SP1CompressWithVKeyVerifier::<InnerConfig, InnerSC, _>::verify(
        &mut builder,
        recursive_verifier,
        input,
        vk_verification,
        PublicValuesOutputDigest::Reduce,
    );
    let block = builder.into_root_block();
    builder_span.exit();
    // SAFETY: The circuit is well-formed. It does not use synchronization primitives
    // (or possibly other means) to violate the invariants.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block) };

    // Compile the program.
    let compiler_span = tracing::debug_span!("compile compress program").entered();
    let mut compiler = AsmCompiler::default();
    let program = compiler.compile(dsl_program);
    compiler_span.exit();
    program
}

/// The "shrink" program, which only verifies the single root shard.
pub(crate) fn shrink_program_from_input(
    recursive_verifier: &RecursiveShardVerifier<
        SP1GlobalContext,
        CompressAir<InnerVal>,
        InnerConfig,
    >,
    vk_verification: bool,
    input: &SP1CompressWithVKeyWitnessValues<InnerSC>,
) -> RecursionProgram<SP1Field> {
    let builder_span = tracing::debug_span!("build shrink program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    // read the input.
    let input = input.read(&mut builder);

    // Verify the root proof.
    SP1CompressRootVerifierWithVKey::<InnerConfig, _>::verify(
        &mut builder,
        recursive_verifier,
        input,
        vk_verification,
        PublicValuesOutputDigest::Reduce,
    );

    let block = builder.into_root_block();
    builder_span.exit();
    // SAFETY: The circuit is well-formed. It does not use synchronization primitives
    // (or possibly other means) to violate the invariants.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block) };

    // Compile the program.
    let compiler_span = tracing::debug_span!("compile shrink program").entered();
    let mut compiler = AsmCompiler::default();
    let program = compiler.compile(dsl_program);
    compiler_span.exit();

    program
}

/// The "wrap" program, which only verifies the single root shard.
fn wrap_program_from_input(
    recursive_verifier: &RecursiveShardVerifier<
        SP1GlobalContext,
        CompressAir<InnerVal>,
        CircuitWrapConfig,
    >,
    vk_verification: bool,
    input: &SP1CompressWithVKeyWitnessValues<InnerSC>,
) -> RecursionProgram<SP1Field> {
    let builder_span = tracing::debug_span!("build wrap program").entered();
    let mut builder = Builder::<CircuitWrapConfig>::default();
    // read the input.
    let input = input.read(&mut builder);

    // Verify the root proof.
    SP1CompressRootVerifierWithVKey::<CircuitWrapConfig, _>::verify(
        &mut builder,
        recursive_verifier,
        input,
        vk_verification,
        PublicValuesOutputDigest::Root,
    );

    let block = builder.into_root_block();
    builder_span.exit();
    // SAFETY: The circuit is well-formed. It does not use synchronization primitives
    // (or possibly other means) to violate the invariants.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block) };

    // Compile the program.
    let compiler_span = tracing::debug_span!("compile wrap program").entered();
    let mut compiler = AsmCompiler::default();
    let program = compiler.compile(dsl_program);
    compiler_span.exit();

    program
}

pub(crate) fn dummy_compose_input<C: RecursionProverComponents>(
    prover: &MachineProver<SP1GlobalContext, C>,
    shape: &SP1RecursionProofShape,
    arity: usize,
    height: usize,
) -> SP1CompressWithVKeyWitnessValues<InnerSC> {
    let chips = prover
        .verifier()
        .shard_verifier()
        .machine()
        .chips()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    let max_log_row_count = prover.verifier().max_log_row_count();
    let log_blowup = prover.verifier().fri_config().log_blowup();
    let log_stacking_height = prover.verifier().log_stacking_height() as usize;

    shape.dummy_input(arity, height, chips, max_log_row_count, log_blowup, log_stacking_height)
}

pub(crate) fn dummy_deferred_input<C: RecursionProverComponents>(
    prover: &MachineProver<SP1GlobalContext, C>,
    shape: &SP1RecursionProofShape,
    height: usize,
) -> SP1DeferredWitnessValues<SP1GlobalContext, InnerSC> {
    let chips = prover
        .verifier()
        .shard_verifier()
        .machine()
        .chips()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    let max_log_row_count = prover.verifier().max_log_row_count();
    let log_blowup = prover.verifier().fri_config().log_blowup();
    let log_stacking_height = prover.verifier().log_stacking_height() as usize;

    let compress_input =
        shape.dummy_input(1, height, chips, max_log_row_count, log_blowup, log_stacking_height);

    SP1DeferredWitnessValues {
        vks_and_proofs: compress_input.compress_val.vks_and_proofs,
        vk_merkle_data: compress_input.merkle_val,
        start_reconstruct_deferred_digest: [SP1Field::zero(); POSEIDON_NUM_WORDS],
        sp1_vk_digest: [SP1Field::zero(); DIGEST_SIZE],
        end_pc: [SP1Field::zero(); 3],
        proof_nonce: [SP1Field::zero(); PROOF_NONCE_NUM_WORDS],
        deferred_proof_index: SP1Field::zero(),
    }
}

pub(crate) fn recursive_verifier<GC, A, SC, C>(
    shard_verifier: &ShardVerifier<GC, SC, A>,
) -> RecursiveShardVerifier<GC, A, C>
where
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + SP1FieldConfigVariable<C>,
    SC: MachineConfig<GC, PcsVerifier = StackedPcsVerifier<GC, BasefoldVerifier<GC>>>,
    A: MachineAir<GC::F>,
    C: CircuitConfig,
{
    let log_stacking_height = shard_verifier.log_stacking_height();
    let max_log_row_count = shard_verifier.max_log_row_count();
    let machine = shard_verifier.machine().clone();
    let pcs_verifier = RecursiveBasefoldVerifier {
        fri_config: shard_verifier.jagged_pcs_verifier.pcs_verifier.pcs_verifier.fri_config,
        tcs: RecursiveMerkleTreeTcs::<C, GC>(PhantomData),
    };
    let recursive_verifier = RecursiveStackedPcsVerifier::new(pcs_verifier, log_stacking_height);

    let recursive_jagged_verifier = RecursiveJaggedPcsVerifier {
        stacked_pcs_verifier: recursive_verifier,
        max_log_row_count,
        jagged_evaluator: RecursiveJaggedEvalSumcheckConfig::<GC>(PhantomData),
    };

    RecursiveShardVerifier {
        machine,
        pcs_verifier: recursive_jagged_verifier,
        _phantom: std::marker::PhantomData,
    }
}
