//! A script that generates a Groth16 proof for the Fibonacci program, and verifies the
//! Groth16 proof in SP1.

use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

/// The ELF for the Groth16 verifier program.
const GROTH16_ELF: Elf = include_elf!("groth16-verifier-program");

/// The ELF for the Fibonacci program.
const FIBONACCI_ELF: Elf = include_elf!("fibonacci-program");

/// Generates the proof, public values, and vkey hash for the Fibonacci program in a format that
/// can be read by `sp1-verifier`.
///
/// Returns the proof bytes, public values, and vkey hash.
async fn generate_fibonacci_proof() -> (Vec<u8>, Vec<u8>, String) {
    // Create an input stream and write '20' to it.
    let n = 20u32;

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Create a `ProverClient`.
    let client = ProverClient::from_env().await;

    // Generate the groth16 proof for the Fibonacci program.
    let pk = client.setup(FIBONACCI_ELF).await.unwrap();
    println!("vk: {:?}", pk.verifying_key().bytes32());
    let proof = client.prove(&pk, stdin).groth16().await.unwrap();
    (proof.bytes(), proof.public_values.to_vec(), pk.verifying_key().bytes32())
}

#[tokio::main]
async fn main() {
    // Setup logging.
    sp1_sdk::utils::setup_logger();

    // Generate the Fibonacci proof, public values, and vkey hash.
    let (fibonacci_proof, fibonacci_public_values, vk) = generate_fibonacci_proof().await;

    // Write the proof, public values, and vkey hash to the input stream.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(fibonacci_proof);
    stdin.write_vec(fibonacci_public_values);
    stdin.write(&vk);

    // Create a `ProverClient`.
    let client = ProverClient::from_env().await;

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(GROTH16_ELF, stdin).await.unwrap();
    println!("executed groth16 program with {} cycles", report.total_instruction_count());
    println!("{}", report);
}
