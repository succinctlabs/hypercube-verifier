use sp1_cuda::CudaProver;
use sp1_sdk::prelude::*;

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("fibonacci-cuda-program");

#[tokio::main]
async fn main() {
    // Setup logging.
    sp1_sdk::utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 1000u32;

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Create a `ProverClient` method.
    let client = CudaProver::new().await.unwrap();
    let client2 = CudaProver::new().await.unwrap();

    let handle = tokio::spawn({
        let stdin = stdin.clone();
        async move {
            let pk = client2.setup(ELF).await.unwrap();
            let proof = client2.core(&pk, stdin.clone(), [0; 4]).await.unwrap();
            let _compressed = client2.compress(&pk.verifying_key(), proof, vec![]).await.unwrap();
            // let shrink = client2.shrink(compressed).await.unwrap();
        }
    });

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    // let (_, report) = client.execute(ELF, stdin.clone()).await.unwrap();
    // println!("executed program with {} cycles", report.total_instruction_count());

    // Generate the proof for the given program and input.
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.core(&pk, stdin.clone(), [0; 4]).await.unwrap();
    let _compressed = client.compress(&pk.verifying_key(), proof, vec![]).await.unwrap();

    handle.await.unwrap();



    println!("generated proof");

    // // Read and verify the output.
    // //
    // // Note that this output is read from values committed to in the program using
    // // `sp1_zkvm::io::commit`.
    // let _ = proof.public_values.read::<u32>();
    // let a = proof.public_values.read::<u32>();
    // let b = proof.public_values.read::<u32>();

    // println!("a: {}", a);
    // println!("b: {}", b);

    // // Verify proof and public values
    // client.verify(&proof, pk.verifying_key(), None).expect("verification failed");

    // // Test a round trip of proof serialization and deserialization.
    // proof.save("proof-with-pis.bin").expect("saving proof failed");
    // let deserialized_proof =
    //     SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // // Verify the deserialized proof.
    // client.verify(&deserialized_proof, pk.verifying_key(), None).expect("verification failed");

    // println!("successfully generated and verified proof for the program!")
}
