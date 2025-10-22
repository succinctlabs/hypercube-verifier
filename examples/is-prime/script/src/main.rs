//! A program that takes a number `n` as input, and writes if `n` is prime as an output.
use sp1_sdk::ProverClient;
use sp1_sdk::prelude::*;

const ELF: Elf = include_elf!("is-prime-program");

#[tokio::main]
async fn main() {
    // Setup a tracer for logging.
    sp1_sdk::utils::setup_logger();

    let mut stdin = SP1Stdin::new();

    // Create an input stream and write '29' to it
    let n = 29u64;
    stdin.write(&n);

    // Generate and verify the proof
    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let mut proof = client.prove(&pk, stdin).await.unwrap();

    let is_prime = proof.public_values.read::<bool>();
    println!("Is 29 prime? {}", is_prime);

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-is-prime.bin").expect("saving proof failed");
    let deserialized_proof =
        SP1ProofWithPublicValues::load("proof-with-is-prime.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, pk.verifying_key(), None).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}