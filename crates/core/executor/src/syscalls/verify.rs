use crate::{DeferredProofVerification, ExecutorConfig};

use super::{SyscallCode, SyscallContext};

#[allow(clippy::mut_mut)]
pub(crate) fn verify_syscall<E: ExecutorConfig>(
    ctx: &mut SyscallContext<E>,
    _: SyscallCode,
    vkey_ptr: u64,
    pv_digest_ptr: u64,
) -> Option<u64> {
    let rt = &mut ctx.rt;

    // Skip deferred proof verification if the corresponding runtime flag is set.
    if rt.deferred_proof_verification == DeferredProofVerification::Enabled {
        // vkey_ptr is a pointer to [u32; 8] which contains the verification key.
        assert_eq!(vkey_ptr % 8, 0, "vkey_ptr must be word-aligned");
        // pv_digest_ptr is a pointer to [u32; 8] which contains the public values digest.
        assert_eq!(pv_digest_ptr % 8, 0, "pv_digest_ptr must be word-aligned");

        let vkey: [u64; 4] =
            core::array::from_fn(|i| rt.double_word::<E>(vkey_ptr + (i as u64) * 8));

        let pv_digest: [u64; 4] =
            core::array::from_fn(|i| rt.double_word::<E>(pv_digest_ptr + (i as u64) * 8));

        let proof_index = rt.state.proof_stream_ptr;
        if proof_index >= rt.state.proof_stream.len() {
            panic!("Not enough proofs were written to the runtime.");
        }
        let (proof, proof_vk) = &rt.state.proof_stream[proof_index].clone();
        rt.state.proof_stream_ptr += 1;
        if let Some(verifier) = rt.subproof_verifier.as_ref() {
            verifier.verify_deferred_proof(proof, proof_vk, vkey, pv_digest).unwrap_or_else(|_| {
                panic!(
                    "Failed to verify proof {proof_index} with digest {}:",
                    hex::encode(bytemuck::cast_slice(&pv_digest)),
                )
            });
        } else if rt.state.proof_stream_ptr == 1 {
            tracing::info!("Not verifying sub proof during runtime");
        }
    }

    None
}
