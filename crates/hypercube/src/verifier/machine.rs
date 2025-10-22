use derive_where::derive_where;
use slop_algebra::PrimeField32;
use slop_basefold::FriConfig;
use slop_challenger::IopCtx;
use slop_jagged::JaggedConfig;

use serde::{Deserialize, Serialize};
use slop_air::Air;
use slop_multilinear::MultilinearPcsVerifier;
use sp1_primitives::{SP1Field, SP1GlobalContext};
use thiserror::Error;

use crate::{
    air::MachineAir, prover::CoreProofShape, Machine, SP1CoreJaggedConfig,
    ShardVerifierConfigError, VerifierConstraintFolder,
};

use super::{MachineConfig, MachineVerifyingKey, ShardProof, ShardVerifier, ShardVerifierError};
/// A complete proof of program execution.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: MachineConfig<GC>, GC::Challenger: Serialize",
    deserialize = "C: MachineConfig<GC>, GC::Challenger: Deserialize<'de>"
))]
pub struct MachineProof<GC: IopCtx, C: MachineConfig<GC>> {
    /// The shard proofs.
    pub shard_proofs: Vec<ShardProof<GC, C>>,
}

impl<GC: IopCtx, C: MachineConfig<GC>> From<Vec<ShardProof<GC, C>>> for MachineProof<GC, C> {
    fn from(shard_proofs: Vec<ShardProof<GC, C>>) -> Self {
        Self { shard_proofs }
    }
}

/// An error that occurs during the verification of a machine proof.
#[derive(Debug, Error)]
pub enum MachineVerifierError<EF, PcsError> {
    /// An error that occurs during the verification of a shard proof.
    #[error("invalid shard proof: {0}")]
    InvalidShardProof(#[from] ShardVerifierError<EF, PcsError>),
    /// The public values are invalid
    #[error("invalid public values: {0}")]
    InvalidPublicValues(&'static str),
    /// There are too many shards.
    #[error("too many shards")]
    TooManyShards,
    /// Invalid verification key.
    #[error("invalid verification key")]
    InvalidVerificationKey,
    /// Empty proof.
    #[error("empty proof")]
    EmptyProof,
}

/// Derive the error type from the machine config.
pub type MachineVerifierConfigError<GC, C> = MachineVerifierError<
    <GC as IopCtx>::EF,
    <<C as JaggedConfig<GC>>::PcsVerifier as MultilinearPcsVerifier<GC>>::VerifierError,
>;

/// A verifier for a machine proof.
#[derive_where(Clone)]
pub struct MachineVerifier<GC: IopCtx, C: MachineConfig<GC>, A: MachineAir<GC::F>> {
    /// Shard proof verifier.
    shard_verifier: ShardVerifier<GC, C, A>,
}

impl<GC: IopCtx, C: MachineConfig<GC>, A: MachineAir<GC::F>> MachineVerifier<GC, C, A> {
    /// Create a new machine verifier.
    pub fn new(shard_verifier: ShardVerifier<GC, C, A>) -> Self {
        Self { shard_verifier }
    }

    /// Get a new challenger.
    pub fn challenger(&self) -> GC::Challenger {
        self.shard_verifier.challenger()
    }

    /// Get the machine.
    pub fn machine(&self) -> &Machine<GC::F, A> {
        &self.shard_verifier.machine
    }

    /// Get the maximum log row count.
    pub fn max_log_row_count(&self) -> usize {
        self.shard_verifier.jagged_pcs_verifier.max_log_row_count
    }

    /// Get the log stacking height.
    #[must_use]
    #[inline]
    pub fn log_stacking_height(&self) -> u32 {
        self.shard_verifier.log_stacking_height()
    }

    /// Get the shape of a shard proof.
    pub fn shape_from_proof(&self, proof: &ShardProof<GC, C>) -> CoreProofShape<GC::F, A> {
        self.shard_verifier.shape_from_proof(proof)
    }

    /// Get the shard verifier.
    #[must_use]
    #[inline]
    pub fn shard_verifier(&self) -> &ShardVerifier<GC, C, A> {
        &self.shard_verifier
    }
}

impl<GC: IopCtx, C: MachineConfig<GC>, A: MachineAir<GC::F>> MachineVerifier<GC, C, A>
where
    GC::F: PrimeField32,
{
    /// Verify the machine proof.
    pub fn verify(
        &self,
        vk: &MachineVerifyingKey<GC, C>,
        proof: &MachineProof<GC, C>,
    ) -> Result<(), MachineVerifierConfigError<GC, C>>
    where
        A: for<'a> Air<VerifierConstraintFolder<'a, GC>>,
    {
        let mut challenger = self.challenger();
        // Observe the verifying key.
        vk.observe_into(&mut challenger);

        // Verify the shard proofs.
        for (i, shard_proof) in proof.shard_proofs.iter().enumerate() {
            let mut challenger = challenger.clone();
            let span = tracing::debug_span!("verify shard", i).entered();
            self.verify_shard(vk, shard_proof, &mut challenger)
                .map_err(MachineVerifierError::InvalidShardProof)?;
            span.exit();
        }

        Ok(())
    }

    /// Verify a shard proof.
    pub fn verify_shard(
        &self,
        vk: &MachineVerifyingKey<GC, C>,
        proof: &ShardProof<GC, C>,
        challenger: &mut GC::Challenger,
    ) -> Result<(), ShardVerifierConfigError<GC, C>>
    where
        A: for<'a> Air<VerifierConstraintFolder<'a, GC>>,
    {
        self.shard_verifier.verify_shard(vk, proof, challenger)
    }
}

impl<A: MachineAir<SP1Field>> MachineVerifier<SP1GlobalContext, SP1CoreJaggedConfig, A> {
    /// Get the FRI config.
    #[must_use]
    #[inline]
    pub fn fri_config(&self) -> &FriConfig<SP1Field> {
        &self.shard_verifier.jagged_pcs_verifier.pcs_verifier.pcs_verifier.fri_config
    }
}
