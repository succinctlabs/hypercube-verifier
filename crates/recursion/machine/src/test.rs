use std::sync::Arc;

use slop_algebra::extension::BinomialExtensionField;
use sp1_hypercube::{
    inner_perm, prover::CpuProverBuilder, Machine, MachineProof, MachineVerifier,
    MachineVerifierConfigError, SP1CoreJaggedConfig, ShardVerifier,
};
use sp1_primitives::{SP1DiffusionMatrix, SP1Field, SP1GlobalContext};
use sp1_recursion_executor::{
    linear_program, Block, ExecutionRecord, Executor, Instruction, RecursionProgram, D,
};
use tracing::Instrument;

use crate::machine::RecursionAir;

/// Runs the given program on machines that use the wide and skinny Poseidon2 chips.
pub async fn run_recursion_test_machines(
    program: RecursionProgram<SP1Field>,
    witness: Vec<Block<SP1Field>>,
) {
    type A = RecursionAir<SP1Field, 3, 2>;

    let mut executor =
        Executor::<SP1Field, BinomialExtensionField<SP1Field, D>, SP1DiffusionMatrix>::new(
            Arc::new(program.clone()),
            inner_perm(),
        );
    executor.witness_stream = witness.into();
    executor.run().unwrap();

    // Run with the poseidon2 wide chip.
    let machine = A::compress_machine();
    run_test_recursion(vec![executor.record.clone()], machine, program.clone()).await.unwrap();
}

/// Constructs a linear program and runs it on machines that use the wide and skinny Poseidon2
/// chips.
pub async fn test_recursion_linear_program(instrs: Vec<Instruction<SP1Field>>) {
    run_recursion_test_machines(linear_program(instrs).unwrap(), Vec::new()).await;
}

pub async fn run_test_recursion<const DEGREE: usize, const VAR_EVENTS_PER_ROW: usize>(
    records: Vec<ExecutionRecord<SP1Field>>,
    machine: Machine<SP1Field, RecursionAir<SP1Field, DEGREE, VAR_EVENTS_PER_ROW>>,
    program: RecursionProgram<SP1Field>,
) -> Result<
    MachineProof<SP1GlobalContext, SP1CoreJaggedConfig>,
    MachineVerifierConfigError<SP1GlobalContext, SP1CoreJaggedConfig>,
> {
    let log_blowup = 1;
    let log_stacking_height = 22;
    let max_log_row_count = 21;
    let verifier = ShardVerifier::from_basefold_parameters(
        log_blowup,
        log_stacking_height,
        max_log_row_count,
        machine,
    );
    let prover = CpuProverBuilder::simple(verifier.clone()).build();

    let (pk, vk) = prover
        .setup(Arc::new(program), None)
        .instrument(tracing::debug_span!("setup").or_current())
        .await;

    let pk = unsafe { pk.into_inner() };
    let mut shard_proofs = Vec::with_capacity(records.len());
    for record in records {
        let proof = prover.prove_shard(pk.clone(), record).await;
        shard_proofs.push(proof);
    }

    assert!(shard_proofs.len() == 1);

    let proof = MachineProof { shard_proofs };

    let machine_verifier = MachineVerifier::new(verifier);
    tracing::debug_span!("verify the proof").in_scope(|| machine_verifier.verify(&vk, &proof))?;
    Ok(proof)
}
