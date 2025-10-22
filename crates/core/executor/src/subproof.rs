//! Types and methods for subproof verification inside the [`crate::Executor`].

use std::sync::Arc;

use sp1_hypercube::{MachineVerifierConfigError, MachineVerifyingKey, SP1CoreJaggedConfig};

use crate::SP1RecursionProof;
use sp1_primitives::SP1GlobalContext;

/// Verifier used in runtime when `sp1_zkvm::precompiles::verify::verify_sp1_proof` is called. This
/// is then used to sanity check that the user passed in the correct proof; the actual constraints
/// happen in the recursion layer.
///
/// This needs to be passed in rather than written directly since the actual implementation relies
/// on crates in recursion that depend on sp1-core.
pub trait SubproofVerifier: Sync + Send {
    /// Verify a deferred proof.
    fn verify_deferred_proof(
        &self,
        proof: &SP1RecursionProof<SP1GlobalContext, SP1CoreJaggedConfig>,
        vk: &MachineVerifyingKey<SP1GlobalContext, SP1CoreJaggedConfig>,
        vk_hash: [u64; 4],
        committed_value_digest: [u64; 4],
    ) -> Result<(), MachineVerifierConfigError<SP1GlobalContext, SP1CoreJaggedConfig>>;
}

/// A dummy verifier which does nothing.
pub struct NoOpSubproofVerifier;

impl SubproofVerifier for NoOpSubproofVerifier {
    fn verify_deferred_proof(
        &self,
        _proof: &SP1RecursionProof<SP1GlobalContext, SP1CoreJaggedConfig>,
        _vk: &MachineVerifyingKey<SP1GlobalContext, SP1CoreJaggedConfig>,
        _vk_hash: [u64; 4],
        _committed_value_digest: [u64; 4],
    ) -> Result<(), MachineVerifierConfigError<SP1GlobalContext, SP1CoreJaggedConfig>> {
        Ok(())
    }
}

// Implement subproof verifier for pointer types

impl<V> SubproofVerifier for &'_ V
where
    V: SubproofVerifier + ?Sized,
{
    fn verify_deferred_proof(
        &self,
        proof: &SP1RecursionProof<SP1GlobalContext, SP1CoreJaggedConfig>,
        vk: &MachineVerifyingKey<SP1GlobalContext, SP1CoreJaggedConfig>,
        vk_hash: [u64; 4],
        committed_value_digest: [u64; 4],
    ) -> Result<(), MachineVerifierConfigError<SP1GlobalContext, SP1CoreJaggedConfig>> {
        (*self).verify_deferred_proof(proof, vk, vk_hash, committed_value_digest)
    }
}

impl<V> SubproofVerifier for Arc<V>
where
    V: SubproofVerifier + ?Sized,
{
    fn verify_deferred_proof(
        &self,
        proof: &SP1RecursionProof<SP1GlobalContext, SP1CoreJaggedConfig>,
        vk: &MachineVerifyingKey<SP1GlobalContext, SP1CoreJaggedConfig>,
        vk_hash: [u64; 4],
        committed_value_digest: [u64; 4],
    ) -> Result<(), MachineVerifierConfigError<SP1GlobalContext, SP1CoreJaggedConfig>> {
        self.as_ref().verify_deferred_proof(proof, vk, vk_hash, committed_value_digest)
    }
}

impl<V> SubproofVerifier for Box<V>
where
    V: SubproofVerifier + ?Sized,
{
    fn verify_deferred_proof(
        &self,
        proof: &SP1RecursionProof<SP1GlobalContext, SP1CoreJaggedConfig>,
        vk: &MachineVerifyingKey<SP1GlobalContext, SP1CoreJaggedConfig>,
        vk_hash: [u64; 4],
        committed_value_digest: [u64; 4],
    ) -> Result<(), MachineVerifierConfigError<SP1GlobalContext, SP1CoreJaggedConfig>> {
        self.as_ref().verify_deferred_proof(proof, vk, vk_hash, committed_value_digest)
    }
}
