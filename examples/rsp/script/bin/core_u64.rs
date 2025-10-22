use sp1_build::include_elf;
use sp1_core_executor::{Executor, Program, RetainedEventsPreset, SP1Context, SP1CoreOpts};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::SP1CoreProofData;
use sp1_prover::{
    components::CpuSP1ProverComponents,
    local::{LocalProver, LocalProverOpts},
    SP1ProverBuilder,
};
use std::sync::Arc;
use tracing::Instrument;
use sp1_core_machine::utils::setup_logger;
use sp1_sdk::prelude::*;

use alloy_primitives::B256;
use clap::Parser;
use rsp_client_executor::{io::ClientExecutorInput, CHAIN_ID_ETH_MAINNET};
use std::path::PathBuf;




/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("rsp-program");

#[derive(Parser, Debug)]
struct Args {
    /// Whether or not to generate a proof.
    #[arg(long, default_value_t = false)]
    prove: bool,
}

fn load_input_from_cache(chain_id: u64, block_number: u64) -> ClientExecutorInput {
    let cache_path = PathBuf::from(format!("./input/{}/{}.bin", chain_id, block_number));
    let mut cache_file = std::fs::File::open(cache_path).unwrap();
    let client_input: ClientExecutorInput = bincode::deserialize_from(&mut cache_file).unwrap();

    client_input
}

#[tokio::main]
async fn main() {
    setup_logger();

    let client_input = load_input_from_cache(CHAIN_ID_ETH_MAINNET, 21740164);
    let mut stdin = SP1Stdin::default();
    let buffer = bincode::serialize(&client_input).unwrap();
    stdin.write_vec(buffer);

    let sp1_prover = SP1ProverBuilder::<CpuSP1ProverComponents>::new().build().await;
    let opts = LocalProverOpts {
        core_opts: SP1CoreOpts {
            retained_events_presets: [RetainedEventsPreset::Sha256].into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let prover = Arc::new(LocalProver::new(sp1_prover, opts));


    let (pk, program, vk) = prover.prover().core()
        .setup(&ELF)
        .instrument(tracing::debug_span!("setup").or_current())
        .await;

    let pk = unsafe { pk.into_inner() };

    let core_proof = prover
        .clone()
        .prove_core(pk, program, stdin, SP1Context::default())
        .instrument(tracing::info_span!("prove core"))
        .await
        .unwrap();

    // Verify the proof
    let core_proof_data = SP1CoreProofData(core_proof.proof.0.clone());
    prover.prover().verify(&core_proof_data, &vk).unwrap();
}
