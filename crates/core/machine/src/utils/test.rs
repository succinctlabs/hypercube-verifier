use std::sync::Arc;

use sp1_core_executor::{Executor, Program, SP1Context, SP1CoreOpts, Trace};
use sp1_hypercube::{
    prover::{AirProver, CpuMachineProverComponents, CpuShardProver, ProverSemaphore},
    MachineProof, MachineVerifier, MachineVerifierConfigError, SP1CoreJaggedConfig,
    SP1CpuJaggedProverComponents, ShardVerifier,
};
use sp1_primitives::{io::SP1PublicValues, SP1Field, SP1GlobalContext};
use tracing::Instrument;

use crate::{io::SP1Stdin, riscv::RiscvAir};

use super::prove_core;

// /// This type is the function signature used for malicious trace and public values generators for
// /// failure test cases.
// pub(crate) type MaliciousTracePVGeneratorType<Val, P> =
//     Box<dyn Fn(&P, &mut ExecutionRecord) -> Vec<(String, RowMajorMatrix<Val>)> + Send + Sync>;

/// The canonical entry point for testing a [`Program`] and [`SP1Stdin`] with a [`MachineProver`].
pub async fn run_test(
    program: Arc<Program>,
    inputs: SP1Stdin,
) -> Result<SP1PublicValues, MachineVerifierConfigError<SP1GlobalContext, SP1CoreJaggedConfig>> {
    let mut runtime = Executor::new(program, SP1CoreOpts::default());
    runtime.write_vecs(&inputs.buffer);
    runtime.run::<Trace>().unwrap();
    let public_values = SP1PublicValues::from(&runtime.state.public_values_stream);

    let _ = run_test_core(runtime, inputs).await?;
    Ok(public_values)
}

// pub fn run_malicious_test<P: MachineProver<SP1CoreJaggedConfig, RiscvAir<SP1Field>>>(
//     mut program: Program,
//     inputs: SP1Stdin,
//     malicious_trace_pv_generator: MaliciousTracePVGeneratorType<SP1Field, P>,
// ) -> Result<SP1PublicValues, MachineVerificationError<SP1CoreJaggedConfig>> {
//     let shape_config = CoreShapeConfig::<SP1Field>::default();
//     shape_config.fix_preprocessed_shape(&mut program).unwrap();

//     let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
//         let mut runtime = Executor::new(program, SP1CoreOpts::default());
//         runtime.maximal_shapes = Some(
//             shape_config
//                 .maximal_core_shapes(SP1CoreOpts::default().shard_size.ilog2() as usize)
//                 .into_iter()
//                 .collect(),
//         );
//         runtime.write_vecs(&inputs.buffer);
//         runtime.run::<Trace>().unwrap();
//         runtime
//     });
//     let public_values = SP1PublicValues::from(&runtime.state.public_values_stream);

//     let result = run_test_core::<P>(
//         runtime,
//         inputs,
//         Some(&shape_config),
//         Some(malicious_trace_pv_generator),
//     );
//     if let Err(verification_error) = result {
//         Err(verification_error)
//     } else {
//         Ok(public_values)
//     }
// }

#[allow(unused_variables)]
pub async fn run_test_core(
    runtime: Executor<'static>,
    inputs: SP1Stdin,
) -> Result<
    MachineProof<SP1GlobalContext, SP1CoreJaggedConfig>,
    MachineVerifierConfigError<SP1GlobalContext, SP1CoreJaggedConfig>,
> {
    let log_blowup = 1;
    let log_stacking_height = 21;
    let max_log_row_count = 22;
    let machine = RiscvAir::machine();

    let verifier = ShardVerifier::from_basefold_parameters(
        log_blowup,
        log_stacking_height,
        max_log_row_count,
        machine,
    );
    let prover =
        CpuShardProver::<SP1GlobalContext, SP1CpuJaggedProverComponents, _>::new(verifier.clone());
    let setup_permit = ProverSemaphore::new(1);
    let (pk, vk) = prover
        .setup(runtime.program.clone(), setup_permit.clone())
        .instrument(tracing::debug_span!("setup").or_current())
        .await;
    let pk = unsafe { pk.into_inner() };
    let challenger = verifier.jagged_pcs_verifier.challenger();
    let (proof, _) = prove_core::<
        SP1GlobalContext,
        CpuMachineProverComponents<
            SP1GlobalContext,
            SP1CpuJaggedProverComponents,
            RiscvAir<SP1Field>,
        >,
    >(
        verifier.clone(),
        Arc::new(prover),
        pk,
        runtime.program.clone(),
        inputs,
        SP1CoreOpts::default(),
        SP1Context::default(),
    )
    .instrument(tracing::debug_span!("prove core"))
    .await
    .unwrap();

    let machine_verifier = MachineVerifier::new(verifier);
    tracing::debug_span!("verify the proof").in_scope(|| machine_verifier.verify(&vk, &proof))?;
    Ok(proof)
}

// #[allow(unused_variables)]
// pub fn run_test_machine_with_prover<SC, A, P: MachineProver<SC, A>>(
//     prover: &P,
//     records: Vec<A::Record>,
//     pk: P::DeviceProvingKey,
//     vk: StarkVerifyingKey<SC>,
// ) -> Result<MachineProof<SC>, MachineVerificationError<SC>>
// where
//     A: MachineAir<SC::Val>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Val, SC::Challenge>>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Challenge, SC::Challenge>>
//         + Air<InteractionBuilder<Val<SC>>>
//         + for<'a> Air<VerifierConstraintFolder<'a, SC>>
//         + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
//         + Air<SymbolicAirBuilder<SC::Val>>,
//     A::Record: MachineRecord<Config = SP1CoreOpts>,
//     SC: StarkGenericConfig,
//     SC::Val: p3_field::PrimeField32,
//     SC::Challenger: Clone,
//     Com<SC>: Send + Sync,
//     PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
//     OpeningProof<SC>: Send + Sync,
// {
//     let mut challenger = prover.config().challenger();
//     let prove_span = tracing::debug_span!("prove").entered();

//     #[cfg(feature = "debug")]
//     prover.machine().debug_constraints(
//         &prover.pk_to_host(&pk),
//         records.clone(),
//         &mut challenger.clone(),
//     );

//     let proof = prover.prove(&pk, records, &mut challenger, SP1CoreOpts::default()).unwrap();
//     prove_span.exit();
//     let nb_bytes = bincode::serialize(&proof).unwrap().len();

//     let mut challenger = prover.config().challenger();
//     prover.machine().verify(&vk, &proof, &mut challenger)?;

//     Ok(proof)
// }

// #[allow(unused_variables)]
// pub fn run_test_machine<SC, A>(
//     records: Vec<A::Record>,
//     machine: StarkMachine<SC, A>,
//     pk: StarkProvingKey<SC>,
//     vk: StarkVerifyingKey<SC>,
// ) -> Result<MachineProof<SC>, MachineVerificationError<SC>>
// where
//     A: MachineAir<SC::Val>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Val, SC::Challenge>>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Challenge, SC::Challenge>>
//         + Air<InteractionBuilder<Val<SC>>>
//         + for<'a> Air<VerifierConstraintFolder<'a, SC>>
//         + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
//         + Air<SymbolicAirBuilder<SC::Val>>,
//     A::Record: MachineRecord<Config = SP1CoreOpts>,
//     SC: StarkGenericConfig,
//     SC::Val: p3_field::PrimeField32,
//     SC::Challenger: Clone,
//     Com<SC>: Send + Sync,
//     PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
//     OpeningProof<SC>: Send + Sync,
// {
//     let prover = CpuProver::new(machine);
//     run_test_machine_with_prover::<SC, A, CpuProver<_, _>>(&prover, records, pk, vk)
// }

// pub fn setup_test_machine<SC, A>(
//     machine: StarkMachine<SC, A>,
// ) -> (StarkProvingKey<SC>, StarkVerifyingKey<SC>)
// where
//     A: MachineAir<SC::Val, Program = Program>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Val, SC::Challenge>>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Challenge, SC::Challenge>>
//         + Air<InteractionBuilder<Val<SC>>>
//         + for<'a> Air<VerifierConstraintFolder<'a, SC>>
//         + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
//         + Air<SymbolicAirBuilder<SC::Val>>,
//     A::Record: MachineRecord<Config = SP1CoreOpts>,
//     SC: StarkGenericConfig,
//     SC::Val: p3_field::PrimeField32,
//     SC::Challenger: Clone,
//     Com<SC>: Send + Sync,
//     PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
//     OpeningProof<SC>: Send + Sync,
// {
//     let prover = CpuProver::new(machine);
//     let empty_program = Program::new(vec![], 0, 0);
//     let (pk, vk) = prover.setup(&empty_program);

//     (pk, vk)
// }
