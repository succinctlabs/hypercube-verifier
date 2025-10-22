use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

const ELF: Elf = include_elf!("chess-program");

#[tokio::main]
async fn main() {
    let mut stdin = SP1Stdin::new();

    // FEN representation of a chessboard in its initial state
    let fen = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1".to_string();
    stdin.write(&fen);

    // SAN representation Queen's pawn opening
    let san = "d4".to_string();
    stdin.write(&san);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let mut proof = client.prove(&pk, stdin).await.unwrap();

    // Read output.
    let is_valid_move = proof.public_values.read::<bool>();
    println!("is_valid_move: {}", is_valid_move);

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
