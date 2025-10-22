use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

/// The ELF we want to execute inside the zkVM.
const REPORT_ELF: Elf = include_elf!("report");
const NORMAL_ELF: Elf = include_elf!("normal");

#[tokio::main]
async fn main() {
    // Setup a tracer for logging.
    sp1_sdk::utils::setup_logger();

    // Execute the normal program.
    let client = ProverClient::from_env().await;
    let (_, _) = client.execute(NORMAL_ELF, Default::default()).await.expect("proving failed");

    // Execute the report program.
    let (_, report) = client.execute(REPORT_ELF, Default::default()).await.expect("proving failed");

    // Get the "setup" cycle count from the report program.
    let setup_cycles = report.cycle_tracker.get("setup").unwrap();
    println!(
        "Using cycle-tracker-report saves the number of cycles to the cycle-tracker mapping in the report.\nHere's the number of cycles used by the setup: {}",
        setup_cycles
    );
}
