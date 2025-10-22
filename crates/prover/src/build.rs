#![allow(clippy::print_stdout)] // okay to print to stdout: this is a build script

use itertools::Itertools;
use slop_algebra::{AbstractField, PrimeField32};
use slop_bn254::Bn254Fr;
use sp1_core_machine::io::SP1Stdin;
use sp1_hypercube::{MachineVerifyingKey, ShardProof};
use sp1_primitives::{SP1Field, SP1OuterGlobalContext};
use sp1_recursion_circuit::{
    hash::FieldHasherVariable,
    machine::{SP1ShapedWitnessValues, SP1WrapVerifier},
    utils::{koalabear_bytes_to_bn254, koalabears_proof_nonce_to_bn254, koalabears_to_bn254},
};
use sp1_recursion_compiler::{
    config::OuterConfig,
    constraints::{Constraint, ConstraintCompiler},
    ir::Builder,
};
use sp1_recursion_executor::RecursionPublicValues;
use sp1_recursion_gnark_ffi::{Groth16Bn254Prover, PlonkBn254Prover};
use std::{borrow::Borrow, path::PathBuf};

pub use sp1_recursion_circuit::witness::{OuterWitness, Witnessable};

use crate::{
    components::{CpuSP1ProverComponents, SP1ProverComponents},
    local::{LocalProver, LocalProverOpts},
    utils::words_to_bytes,
    OuterSC, SP1ProverBuilder,
};

/// Tries to build the PLONK artifacts inside the development directory.
pub fn try_build_plonk_bn254_artifacts_dev(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext, OuterSC>,
    template_proof: &ShardProof<SP1OuterGlobalContext, OuterSC>,
) -> PathBuf {
    let build_dir = plonk_bn254_artifacts_dev_dir();
    println!("[sp1] building plonk bn254 artifacts in development mode");
    build_plonk_bn254_artifacts(template_vk, template_proof, &build_dir);
    build_dir
}

/// Tries to build the groth16 bn254 artifacts in the current environment.
pub fn try_build_groth16_bn254_artifacts_dev(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext, OuterSC>,
    template_proof: &ShardProof<SP1OuterGlobalContext, OuterSC>,
) -> PathBuf {
    let build_dir = groth16_bn254_artifacts_dev_dir();
    println!("[sp1] building groth16 bn254 artifacts in development mode");
    build_groth16_bn254_artifacts(template_vk, template_proof, &build_dir);
    build_dir
}

/// Gets the directory where the PLONK artifacts are installed in development mode.
pub fn plonk_bn254_artifacts_dev_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".sp1").join("circuits").join("dev")
}

/// Gets the directory where the groth16 artifacts are installed in development mode.
pub fn groth16_bn254_artifacts_dev_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".sp1").join("circuits").join("dev")
}

/// Build the plonk bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_plonk_bn254_artifacts(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext, OuterSC>,
    template_proof: &ShardProof<SP1OuterGlobalContext, OuterSC>,
    build_dir: impl Into<PathBuf>,
) {
    let build_dir = build_dir.into();
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    PlonkBn254Prover::build(constraints, witness, build_dir);
}

/// Build the groth16 bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_groth16_bn254_artifacts(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext, OuterSC>,
    template_proof: &ShardProof<SP1OuterGlobalContext, OuterSC>,
    build_dir: impl Into<PathBuf>,
) {
    let build_dir = build_dir.into();
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    Groth16Bn254Prover::build(constraints, witness, build_dir);
}

/// Builds the plonk bn254 artifacts to the given directory.
///
/// This may take a while as it needs to first generate a dummy proof and then it needs to compile
/// the circuit.
pub async fn build_plonk_bn254_artifacts_with_dummy(build_dir: impl Into<PathBuf>) {
    let (wrap_vk, wrapped_proof) = dummy_proof().await;
    let wrap_vk_bytes = bincode::serialize(&wrap_vk).unwrap();
    let wrapped_proof_bytes = bincode::serialize(&wrapped_proof).unwrap();
    std::fs::write("wrap_vk.bin", wrap_vk_bytes).unwrap();
    std::fs::write("wrapped_proof.bin", wrapped_proof_bytes).unwrap();
    let wrap_vk_bytes = std::fs::read("wrap_vk.bin").unwrap();
    let wrapped_proof_bytes = std::fs::read("wrapped_proof.bin").unwrap();
    let wrap_vk = bincode::deserialize(&wrap_vk_bytes).unwrap();
    let wrapped_proof = bincode::deserialize(&wrapped_proof_bytes).unwrap();
    crate::build::build_plonk_bn254_artifacts(&wrap_vk, &wrapped_proof, build_dir.into());
}

/// Builds the groth16 bn254 artifacts to the given directory.
///
/// This may take a while as it needs to first generate a dummy proof and then it needs to compile
/// the circuit.
pub async fn build_groth16_bn254_artifacts_with_dummy(build_dir: impl Into<PathBuf>) {
    let (wrap_vk, wrapped_proof) = dummy_proof().await;
    let wrap_vk_bytes = bincode::serialize(&wrap_vk).unwrap();
    let wrapped_proof_bytes = bincode::serialize(&wrapped_proof).unwrap();
    std::fs::write("wrap_vk.bin", wrap_vk_bytes).unwrap();
    std::fs::write("wrapped_proof.bin", wrapped_proof_bytes).unwrap();
    let wrap_vk_bytes = std::fs::read("wrap_vk.bin").unwrap();
    let wrapped_proof_bytes = std::fs::read("wrapped_proof.bin").unwrap();
    let wrap_vk = bincode::deserialize(&wrap_vk_bytes).unwrap();
    let wrapped_proof = bincode::deserialize(&wrapped_proof_bytes).unwrap();
    crate::build::build_groth16_bn254_artifacts(&wrap_vk, &wrapped_proof, build_dir.into());
}

/// Build the verifier constraints and template witness for the circuit.
pub fn build_constraints_and_witness(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext, OuterSC>,
    template_proof: &ShardProof<SP1OuterGlobalContext, OuterSC>,
) -> (Vec<Constraint>, OuterWitness<OuterConfig>) {
    tracing::info!("building verifier constraints");
    let template_input = SP1ShapedWitnessValues {
        vks_and_proofs: vec![(template_vk.clone(), template_proof.clone())],
        is_complete: true,
    };
    let constraints =
        tracing::info_span!("wrap circuit").in_scope(|| build_outer_circuit(&template_input));

    let pv: &RecursionPublicValues<SP1Field> = template_proof.public_values.as_slice().borrow();
    let vkey_hash = koalabears_to_bn254(&pv.sp1_vk_digest);
    let committed_values_digest_bytes: [SP1Field; 32] =
        words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
    let committed_values_digest = koalabear_bytes_to_bn254(&committed_values_digest_bytes);
    let exit_code = Bn254Fr::from_canonical_u32(pv.exit_code.as_canonical_u32());
    let vk_root = koalabears_to_bn254(&pv.vk_root);
    let proof_nonce = koalabears_proof_nonce_to_bn254(&pv.proof_nonce);
    tracing::info!("building template witness");
    let mut witness = OuterWitness::default();
    template_input.write(&mut witness);
    witness.write_committed_values_digest(committed_values_digest);
    witness.write_vkey_hash(vkey_hash);
    witness.write_exit_code(exit_code);
    witness.write_vk_root(vk_root);
    witness.write_proof_nonce(proof_nonce);
    (constraints, witness)
}

/// Generate a dummy proof that we can use to build the circuit. We need this to know the shape of
/// the proof.
pub async fn dummy_proof(
) -> (MachineVerifyingKey<SP1OuterGlobalContext, OuterSC>, ShardProof<SP1OuterGlobalContext, OuterSC>)
{
    let elf = include_bytes!("../elf/riscv64im-succinct-zkvm-elf");

    tracing::info!("initializing prover");
    let prover = SP1ProverBuilder::new().build().await;
    let local_prover = LocalProver::new(prover, LocalProverOpts::default());
    let prover = std::sync::Arc::new(local_prover);

    tracing::info!("setup elf");
    let (pk, program, vk) = prover.prover().core().setup(elf).await;
    let pk = unsafe { pk.into_inner() };

    tracing::info!("prove core");
    let mut stdin = SP1Stdin::new();
    stdin.write(&500u32);
    let core_proof =
        prover.clone().prove_core(pk, program, stdin, Default::default()).await.unwrap();

    tracing::info!("compress");
    let compressed_proof = prover.clone().compress(&vk, core_proof, vec![]).await.unwrap();

    tracing::info!("shrink");
    let shrink_proof = prover.shrink(compressed_proof).await.unwrap();

    tracing::info!("wrap");
    let wrapped_proof = prover.wrap(shrink_proof).await.unwrap();

    (wrapped_proof.vk, wrapped_proof.proof)
}

fn build_outer_circuit(
    template_input: &SP1ShapedWitnessValues<SP1OuterGlobalContext, OuterSC>,
) -> Vec<Constraint> {
    let wrap_verifier = CpuSP1ProverComponents::wrap_verifier();
    let wrap_verifier = wrap_verifier.shard_verifier();
    let recursive_wrap_verifier =
        crate::recursion::recursive_verifier::<_, _, OuterSC, OuterConfig>(wrap_verifier);

    let wrap_span = tracing::debug_span!("build wrap circuit").entered();
    let mut builder = Builder::<OuterConfig>::default();

    // Get the value of the vk.
    let template_vk = template_input.vks_and_proofs.first().unwrap().0.clone();
    // Get an input variable.
    let input = template_input.read(&mut builder);

    // Fix the `wrap_vk` value to be the same as the template `vk`. Since the chip information and
    // the ordering is already a constant, we just need to constrain the commitment and pc_start.

    // Get the vk variable from the input.
    let vk = &input.vks_and_proofs.first().unwrap().0;
    // Get the expected commitment.
    let expected_commitment: [_; 1] = template_vk.preprocessed_commit.into();
    let expected_commitment = expected_commitment.map(|x| builder.eval(x));
    // Constrain `commit` to be the same as the template `vk`.
    SP1OuterGlobalContext::assert_digest_eq(
        &mut builder,
        expected_commitment,
        vk.preprocessed_commit,
    );
    // Constrain `pc_start` to be the same as the template `vk`.
    for (vk_pc, template_vk_pc) in vk.pc_start.iter().zip_eq(template_vk.pc_start.iter()) {
        builder.assert_felt_eq(*vk_pc, *template_vk_pc);
    }
    // Constrain the preprocessed heights to be the same as template `vk`.
    for ((vk_chip, vk_dimension), (template_vk_chip, template_vk_dimension)) in vk
        .preprocessed_chip_information
        .iter()
        .zip_eq(template_vk.preprocessed_chip_information.iter())
    {
        assert_eq!(vk_chip, template_vk_chip);
        builder.assert_felt_eq(vk_dimension.height, template_vk_dimension.height);
        builder.assert_felt_eq(vk_dimension.num_polynomials, template_vk_dimension.num_polynomials);
    }
    // Verify the proof.
    SP1WrapVerifier::verify(&mut builder, &recursive_wrap_verifier, input);

    let mut backend = ConstraintCompiler::<OuterConfig>::default();
    let operations = backend.emit(builder.into_operations());
    wrap_span.exit();

    operations
}
