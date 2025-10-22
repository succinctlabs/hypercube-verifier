//! This is a test program that takes in a sp1_core vkey and a list of inputs, and then verifies the
//! SP1 proof for each input.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use sp1_zkvm::lib::verify::verify_sp1_proof;

pub fn main() {
    let vkey = sp1_zkvm::io::read::<[u32; 8]>();
    println!("Read vkey: {:?}", hex::encode(bytemuck::cast_slice(&vkey)));
    let inputs = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    inputs.iter().for_each(|input| {
        // Get expected pv_digest hash: sha256(input)
        let pv_digest = Sha256::digest(input);
        println!("PV digest len: {}", pv_digest.len());
        println!("Verifying proof for digest: {:?}", pv_digest);
        verify_sp1_proof(&vkey, &<[u8; 32]>::try_from(pv_digest).unwrap());

        println!("Verified proof for digest: {:?}", hex::encode(pv_digest));
        println!("Verified input: {:?}", hex::encode(input));
    });
}
