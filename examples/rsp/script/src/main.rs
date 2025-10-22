// use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};
use sp1_core_executor::{RetainedEventsPreset, SP1CoreOpts, SP1Context, Executor, Program};
use sp1_prover::{
    local::{LocalProver, LocalProverOpts},
    components::CpuSP1ProverComponents,
    SP1ProverBuilder,
};
use sp1_build::Elf;
use sp1_core_machine::io::SP1Stdin;
use sp1_build::include_elf;
use std::sync::Arc;
use sp1_primitives::io::SP1PublicValues;
use sp1_core_machine::utils::setup_logger;

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
    // Load the input from the cache.
    let client_input = load_input_from_cache(CHAIN_ID_ETH_MAINNET, 21740137);
    let mut stdin = SP1Stdin::default();
    let buffer = bincode::serialize(&client_input).unwrap();
    stdin.write_vec(buffer);

    let opts = SP1CoreOpts::default();
    let program = Arc::new(Program::from(&ELF).unwrap());
    let mut runtime = Executor::with_context(program, opts, SP1Context::default());
    runtime.maybe_setup_profiler(&ELF);

    runtime.write_vecs(&stdin.buffer);
    let now = std::time::Instant::now();
    runtime.run_fast().unwrap();

    println!("total elapsed: {:?}", now.elapsed());

    println!("Full execution report:\n{:?}", runtime.report);
    println!("Cycles: {:?}", runtime.report.total_instruction_count());

    let mut public_values = SP1PublicValues::from(&runtime.state.public_values_stream); 

    let block_hash = public_values.read::<B256>();
    println!("success: block_hash={block_hash}");
}
