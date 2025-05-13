use core::panic;
use std::{borrow::Borrow, fs::File, path::PathBuf};

use itertools::Itertools;
use p3_field::PrimeField32;

use clap::Parser;
use hypercube_recursion_machine::{verify_compressed, SP1Proof, SP1ProofWithPublicValues};
use hypercube_stark::{blake3_hash, sha256_hash, MachineVerifyingKey, PublicValues, Word};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    proof_dir: PathBuf,
    #[clap(short, long)]
    vk_dir: PathBuf,
}

fn main() {
    let args = Args::parse();

    let path = args.proof_dir;

    let mut file = File::open(path).unwrap();

    let proof: SP1ProofWithPublicValues = bincode::deserialize_from(&mut file).unwrap();

    let mut file = File::open(args.vk_dir).unwrap();
    let vk: MachineVerifyingKey<_> = bincode::deserialize_from(&mut file).unwrap();

    if let SP1Proof::Compressed(inner_proof) = &proof.proof {
        let public_values: &PublicValues<[_; 4], Word<_>, _> =
            inner_proof.proof.public_values.as_slice().borrow();

        // Get the committed value digest bytes.
        let committed_value_digest_bytes = public_values
            .committed_value_digest
            .iter()
            .flat_map(|w| w.iter().map(|x| x.as_canonical_u32() as u8))
            .collect_vec();

        // Make sure the committed value digest matches the public values hash.
        // It is computationally infeasible to find two distinct inputs, one processed with
        // SHA256 and the other with Blake3, that yield the same hash value.
        if committed_value_digest_bytes != sha256_hash(proof.public_values.as_byte_slice())
            && committed_value_digest_bytes != blake3_hash(proof.public_values.as_byte_slice())
        {
            panic!("Committed value digest does not match public values hash");
        }
    } else {
        panic!("not a compressed proof");
    }

    let proof = proof.proof;
    let proof = match proof {
        SP1Proof::Compressed(proof) => proof,
        _ => panic!("not a compressed proof"),
    };

    let result = verify_compressed(&proof, &vk);

    assert!(result.is_ok(), "Failed to verify compressed proof");

    let mut file = File::open("message.bin").unwrap();

    let message: String = bincode::deserialize_from(&mut file).unwrap();

    println!("{}", message);
}
