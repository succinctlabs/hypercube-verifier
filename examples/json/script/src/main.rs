//! A simple script to generate and verify the proof of a given program.

use lib::{Account, Transaction};
use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

const JSON_ELF: Elf = include_elf!("json-program");

#[tokio::main]
async fn main() {
    // setup tracer for logging.
    sp1_sdk::utils::setup_logger();

    // Generate proof.
    let mut stdin = SP1Stdin::new();

    // Generic sample JSON (as a string input).
    let data_str = r#"
            {
                "name": "Jane Doe",
                "age": "25",
                "net_worth" : "$1000000"
            }"#
    .to_string();
    let key = "net_worth".to_string();

    // Custom struct example.
    let initial_account_state = Account { account_name: "John".to_string(), balance: 200 };
    let transactions = vec![
        Transaction { from: "John".to_string(), to: "Uma".to_string(), amount: 50 },
        Transaction { from: "Uma".to_string(), to: "John".to_string(), amount: 100 },
    ];

    stdin.write(&data_str);
    stdin.write(&key);
    stdin.write(&initial_account_state);
    stdin.write(&transactions);

    let client = ProverClient::from_env().await;
    let pk = client.setup(JSON_ELF).await.unwrap();
    let mut proof = client.prove(&pk, stdin).await.unwrap();

    // Read output.
    let val = proof.public_values.read::<String>();
    println!("Value of {} is {}", key, val);

    let account_state = proof.public_values.read::<Account>();
    println!("Final account state: {}", serde_json::to_string(&account_state).unwrap());

    // Verify proof.
    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-io.bin").expect("saving proof failed");
    let deserialized_proof =
        SP1ProofWithPublicValues::load("proof-with-io.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, pk.verifying_key(), None).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
