//! Internal constants and types that determine the verifier configuration.

use alloc::vec::Vec;
use core::borrow::Borrow;

use slop_algebra::{AbstractField, PrimeField32};
use slop_symmetric::CryptographicHasher;
use sp1_hypercube::{MachineVerifier, MachineVerifierError, SP1RecursionProof, ShardVerifier};
use sp1_primitives::poseidon2_hasher;
use sp1_recursion_executor::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH};

use super::CompressedError;
use crate::{blake3_hash, hash_public_inputs, hash_public_inputs_with_fn};

/// The finite field used for compress proofs.
pub type F = sp1_primitives::SP1Field;
pub type GC = sp1_primitives::SP1GlobalContext;
/// The stark configuration used for compress proofs.
pub type C = sp1_hypercube::SP1CoreJaggedConfig;

/// Degree of Poseidon2 etc. in the compress machine.
pub const COMPRESS_DEGREE: usize = 3;

pub type CompressAir<F> = sp1_recursion_machine::RecursionAir<F, COMPRESS_DEGREE, 2>;

pub const RECURSION_LOG_BLOWUP: usize = 1;
pub const RECURSION_LOG_STACKING_HEIGHT: u32 = 20;
pub const RECURSION_MAX_LOG_ROW_COUNT: usize = 20;

// // The rest of the functions in this file have been copied from elsewhere with slight
// modifications.

/// Verify a compressed proof.
pub fn verify_compressed(
    proof: &SP1RecursionProof<GC, C>,
    sp1_public_inputs: &[u8],
    vkey_hash: &[F; 8],
) -> Result<(), CompressedError> {
    let SP1RecursionProof { vk: compress_vk, proof } = proof;

    let verifier = verifier();

    let mut challenger = verifier.challenger();
    compress_vk.observe_into(&mut challenger);

    // Verify the shard proof.
    let () = verifier
        .verify_shard(compress_vk, proof, &mut challenger)
        .map_err(MachineVerifierError::InvalidShardProof)?;

    // Validate the public values.
    let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

    // Validate the SP1 public values against the committed digest.
    let committed_value_digest_bytes = public_values
        .committed_value_digest
        .iter()
        .flat_map(|w| w.iter().map(|x| x.as_canonical_u32() as u8))
        .collect::<Vec<_>>();

    if committed_value_digest_bytes.as_slice() != hash_public_inputs(sp1_public_inputs).as_slice()
        && committed_value_digest_bytes.as_slice()
            != hash_public_inputs_with_fn(sp1_public_inputs, blake3_hash)
    {
        return Err(CompressedError::PublicValuesMismatch);
    }

    // The `digest` is the correct hash of the recursion public values.
    if !is_recursion_public_values_valid(public_values) {
        return Err(MachineVerifierError::InvalidPublicValues(
            "recursion public values are invalid",
        )
        .into());
    }

    // TODO: vkey verification (see comment at top of file)
    // // The `vk_root` is the expected `vk_root`.
    // if public_values.vk_root != self.recursion_prover.recursion_vk_root {
    //     return Err(MachineVerifierError::InvalidPublicValues("vk_root mismatch"));
    // }

    // // If `vk_verification` is on, check the `vk` is within the expected list of `vk`'s.
    // // This `vk_verification` must be only turned off for testing purposes.
    // if self.recursion_prover.vk_verification()
    //     && !self.recursion_prover.recursion_vk_map.contains_key(&compress_vk.hash_koalabear())
    // {
    //     return Err(MachineVerifierError::InvalidVerificationKey);
    // }

    // `is_complete` should be 1. This ensures that the proof is fully reduced.
    if public_values.is_complete != F::one() {
        return Err(MachineVerifierError::InvalidPublicValues("is_complete is not 1").into());
    }

    // Verify that the proof is for the sp1 vkey we are expecting.
    if public_values.sp1_vk_digest != *vkey_hash {
        return Err(MachineVerifierError::InvalidPublicValues("sp1 vk hash mismatch").into());
    }

    Ok(())
}

/// Copied from `RecursionProverComponents::verifier`.
pub fn verifier() -> MachineVerifier<GC, C, CompressAir<F>> {
    let compress_log_blowup = RECURSION_LOG_BLOWUP;
    let compress_log_stacking_height = RECURSION_LOG_STACKING_HEIGHT;
    let compress_max_log_row_count = RECURSION_MAX_LOG_ROW_COUNT;

    let machine = CompressAir::<F>::compress_machine();
    let recursion_shard_verifier = ShardVerifier::from_basefold_parameters(
        compress_log_blowup,
        compress_log_stacking_height,
        compress_max_log_row_count,
        machine.clone(),
    );

    MachineVerifier::new(recursion_shard_verifier)
}

/// Compute the digest of the public values.
pub fn recursion_public_values_digest(public_values: &RecursionPublicValues<F>) -> [F; 8] {
    let hasher = poseidon2_hasher();
    hasher.hash_slice(&public_values.as_array()[0..NUM_PV_ELMS_TO_HASH])
}

/// Assert that the digest of the public values is correct.
pub fn is_recursion_public_values_valid(public_values: &RecursionPublicValues<F>) -> bool {
    let expected_digest = recursion_public_values_digest(public_values);
    public_values.digest.iter().copied().eq(expected_digest)
}
