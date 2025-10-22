use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

pub const ELF: Elf = include_elf!("bls12381-program");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let stdin = SP1Stdin::new();

    let client = ProverClient::from_env().await;
    let (_public_values, report) = client.execute(ELF, stdin).await.expect("failed to prove");

    println!("executed: {}", report);
}
