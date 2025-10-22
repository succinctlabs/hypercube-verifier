use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;
use sp1_core_executor::SP1CoreOpts;
use rand::{thread_rng, Rng};
use elliptic_curve::sec1::ToEncodedPoint;

const ELF: Elf = include_elf!("secp256k1-program");

#[tokio::main]
async fn main() {
    // Generate proof.
    // utils::setup_tracer();
    sp1_sdk::utils::setup_logger();

    let mut rng = thread_rng();
    let secret_key = k256::SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(false);
    let decompressed = encoded.as_bytes();
    let compressed = public_key.to_sec1_bytes();

    let stdin = SP1Stdin::from(&compressed);
    
    let mut opts = SP1CoreOpts::default();
    // Uncomment to test page protect.
    // opts.page_protect = true;
    let client = ProverClient::builder().cpu().core_opts(opts).build().await;
    let pk = client.setup(ELF).await.expect("setup failed");
    let proof = client.prove(&pk, stdin).core().await.expect("proving failed");

    // Verify proof.
    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");

    // // Test a round trip of proof serialization and deserialization.
    // proof.save("proof-with-pis.bin").expect("saving proof failed");
    // let deserialized_proof =
    //     SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    // client.verify(&deserialized_proof, pk.verifying_key(), None).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}

