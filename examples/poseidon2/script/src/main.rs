use sp1_sdk::{
    include_elf, utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey,
    SP1ProofWithPublicValues, SP1Stdin,
};

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("poseidon2-program");

#[tokio::main]
async fn main() {
    // Setup logging.
    utils::setup_logger();

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();

    // Create a `ProverClient` method.
    let client = ProverClient::builder().cpu().build().await;

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    
let (_, report) = client.execute(ELF, stdin.clone()).await.unwrap();
    println!("executed program {:?} ", report);
 

    // Generate the proof for the given program and input.
    let pk = client.setup(ELF).await.unwrap();
    let mut proof = client.prove(&pk, stdin.clone()).core().await.unwrap();
    println!("generated proof");
    
    // Verify proof and public values
    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    println!("verified proof");
    
}
