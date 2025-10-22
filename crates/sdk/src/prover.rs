//! # SP1 Prover Trait
//!
//! A trait that each prover variant must implement.

use std::{
    borrow::Borrow,
    fmt,
    future::{Future, IntoFuture},
    sync::Arc,
};

use crate::StatusCode;
use anyhow::Result;
use itertools::Itertools;
use slop_algebra::PrimeField32;
use sp1_core_machine::io::SP1Stdin;
use sp1_hypercube::{air::PublicValues, MachineVerifierConfigError};
use sp1_primitives::{types::Elf, SP1GlobalContext};
use sp1_prover::{
    components::{CpuSP1ProverComponents, SP1ProverComponents},
    local::LocalProver,
    CoreSC, InnerSC, SP1CoreProofData, SP1Prover, SP1VerifyingKey, SP1_CIRCUIT_VERSION,
};
use thiserror::Error;

/// The module that exposes the [`ExecuteRequest`] type.
mod execute;

/// The module that exposes the [`ProveRequest`] trait.
mod prove;

pub use execute::ExecuteRequest;
pub(crate) use prove::BaseProveRequest;
pub use prove::ProveRequest;

use crate::{SP1Proof, SP1ProofWithPublicValues};

/// The entire user-facing functionality of a prover.
pub trait Prover: Clone + Send + Sync {
    /// The proving key used for this prover type.
    type ProvingKey: ProvingKey;

    /// The possible errors that can occur when proving.
    type Error: fmt::Debug + fmt::Display;

    /// The prove request builder.
    type ProveRequest<'a>: ProveRequest<'a, Self>
    where
        Self: 'a;

    /// The inner [`LocalProver`] struct used by the prover.
    fn inner(&self) -> Arc<LocalProver<CpuSP1ProverComponents>>;

    /// The version of the current SP1 circuit.
    fn version(&self) -> &str {
        SP1_CIRCUIT_VERSION
    }

    /// Setup the prover with the given ELF.
    fn setup(&self, elf: Elf) -> impl SendFutureResult<Self::ProvingKey, Self::Error>;

    /// Prove the given program on the given input in the given proof mode.
    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a>;

    /// Execute the program on the given input.
    fn execute(&self, elf: Elf, stdin: SP1Stdin) -> ExecuteRequest<'_, Self> {
        ExecuteRequest::new(self, elf, stdin)
    }

    /// Verify the given proof.
    ///
    /// Note: If the status code is not set, the verification process will check for success.
    fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
        status_code: Option<StatusCode>,
    ) -> Result<(), SP1VerificationError> {
        verify_proof(self.inner().prover(), self.version(), proof, vkey, status_code)
    }
}

/// A trait that represents a prover's proving key.
pub trait ProvingKey: Clone + Send + Sync {
    /// Get the verifying key corresponding to the proving key.
    fn verifying_key(&self) -> &SP1VerifyingKey;

    /// Get the ELF corresponding to the proving key.
    fn elf(&self) -> &Elf;
}

/// A trait for [`Future`]s that are send and return a [`Result`].
///
/// This is just slightly better for the [`_Prover`] trait signature.
pub trait SendFutureResult<T, E>: Future<Output = Result<T, E>> + Send {}

impl<F, T, E> SendFutureResult<T, E> for F where F: Future<Output = Result<T, E>> + Send {}

/// A trait for [`IntoFuture`]s that are send and return a [`Result`].
///
/// This is just slightly better for the [`_Prover`] trait signature.
pub trait IntoSendFutureResult<T, E>: IntoFuture<Output = Result<T, E>> + Send {}

impl<F, T, E> IntoSendFutureResult<T, E> for F where F: IntoFuture<Output = Result<T, E>> + Send {}

/// An error that occurs when calling [`Prover::verify`].
#[derive(Error, Debug)]
pub enum SP1VerificationError {
    /// An error that occurs when the public values are invalid.
    #[error("Invalid public values")]
    InvalidPublicValues,
    /// An error that occurs when the SP1 version does not match the version of the circuit.
    #[error("Version mismatch: {0}")]
    VersionMismatch(String),
    /// An error that occurs when the core machine verification fails.
    #[error("Core machine verification error: {0}")]
    Core(MachineVerifierConfigError<SP1GlobalContext, CoreSC>),
    /// An error that occurs when the recursion verification fails.
    #[error("Recursion verification error: {0}")]
    Recursion(MachineVerifierConfigError<SP1GlobalContext, InnerSC>),
    /// An error that occurs when the Plonk verification fails.
    #[error("Plonk verification error: {0}")]
    Plonk(anyhow::Error),
    /// An error that occurs when the Groth16 verification fails.
    #[error("Groth16 verification error: {0}")]
    Groth16(anyhow::Error),
    /// An error that occurs when the proof is invalid.
    #[error("Unexpected error: {0:?}")]
    Other(anyhow::Error),
    /// An error that occurs when the exit code is unexpected.
    #[error("Unexpected exit code: {0}")]
    UnexpectedExitCode(u32),
}

/// In SP1, a proof's public values can either be hashed with SHA2 or Blake3. In SP1 V4, there is no
/// metadata attached to the proof about which hasher function was used for public values hashing.
/// Instead, when verifying the proof, the public values are hashed with SHA2 and Blake3, and
/// if either matches the `expected_public_values_hash`, the verification is successful.
///
/// The security for this verification in SP1 V4 derives from the fact that both SHA2 and Blake3 are
/// designed to be collision resistant. It is computationally infeasible to find an input i1 for
/// SHA256 and an input i2 for Blake3 that the same hash value. Doing so would require breaking both
/// algorithms simultaneously.
pub(crate) fn verify_proof<C: SP1ProverComponents>(
    prover: &SP1Prover<C>,
    version: &str,
    bundle: &SP1ProofWithPublicValues,
    vkey: &SP1VerifyingKey,
    status_code: Option<StatusCode>,
) -> Result<(), SP1VerificationError> {
    let status_code = status_code.unwrap_or(StatusCode::SUCCESS);

    // Check that the SP1 version matches the version of the current circuit.
    if bundle.sp1_version != version {
        return Err(SP1VerificationError::VersionMismatch(bundle.sp1_version.clone()));
    }

    match &bundle.proof {
        SP1Proof::Core(proof) => {
            let public_values: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
                proof.last().unwrap().public_values.as_slice().borrow();

            if !status_code.is_accepted_code(public_values.exit_code.as_canonical_u32()) {
                return Err(SP1VerificationError::UnexpectedExitCode(
                    public_values.exit_code.as_canonical_u32(),
                ));
            }

            // Get the committed value digest bytes.
            let committed_value_digest_bytes = public_values
                .committed_value_digest
                .iter()
                .flat_map(|w| w.iter().map(|x| x.as_canonical_u32() as u8))
                .collect_vec();

            // Make sure the committed value digest matches the public values hash.
            // It is computationally infeasible to find two distinct inputs, one processed with
            // SHA256 and the other with Blake3, that yield the same hash value.
            if committed_value_digest_bytes != bundle.public_values.hash()
                && committed_value_digest_bytes != bundle.public_values.blake3_hash()
            {
                tracing::error!("committed value digest doesnt match");
                return Err(SP1VerificationError::InvalidPublicValues);
            }

            // Verify the core proof.
            prover
                .verify(&SP1CoreProofData(proof.clone()), vkey)
                .map_err(SP1VerificationError::Core)
        }
        SP1Proof::Compressed(proof) => {
            let public_values: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
                proof.proof.public_values.as_slice().borrow();

            if !status_code.is_accepted_code(public_values.exit_code.as_canonical_u32()) {
                return Err(SP1VerificationError::UnexpectedExitCode(
                    public_values.exit_code.as_canonical_u32(),
                ));
            }

            // Get the committed value digest bytes.
            let committed_value_digest_bytes = public_values
                .committed_value_digest
                .iter()
                .flat_map(|w| w.iter().map(|x| x.as_canonical_u32() as u8))
                .collect_vec();

            // Make sure the committed value digest matches the public values hash.
            // It is computationally infeasible to find two distinct inputs, one processed with
            // SHA256 and the other with Blake3, that yield the same hash value.
            if committed_value_digest_bytes != bundle.public_values.hash()
                && committed_value_digest_bytes != bundle.public_values.blake3_hash()
            {
                return Err(SP1VerificationError::InvalidPublicValues);
            }

            prover.verify_compressed(proof, vkey).map_err(SP1VerificationError::Recursion)
        }
        SP1Proof::Plonk(_) => unimplemented!(),
        // prover
        //     .verify_plonk_bn254(
        //         proof,
        //         vkey,
        //         &bundle.public_values,
        //         &if sp1_prover::build::sp1_dev_mode() {
        //             sp1_prover::build::plonk_bn254_artifacts_dev_dir()
        //         } else {
        //             try_install_circuit_artifacts("plonk")
        //         },
        //     )
        //     .map_err(SP1VerificationError::Plonk),
        SP1Proof::Groth16(_) => unimplemented!(),
        // prover
        // .verify_groth16_bn254(
        //     proof,
        //     vkey,
        //     &bundle.public_values,
        //     &if sp1_prover::build::sp1_dev_mode() {
        //         sp1_prover::build::groth16_bn254_artifacts_dev_dir()
        //     } else {
        //         try_install_circuit_artifacts("groth16")
        //     },
        // )
        // .map_err(SP1VerificationError::Groth16),
    }
}
