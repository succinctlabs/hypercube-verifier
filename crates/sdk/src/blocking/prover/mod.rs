//! # SP1 Prover Trait
//!
//! A trait that each prover variant must implement.

use std::{fmt, sync::Arc};

use crate::{prover::verify_proof, ProvingKey, SP1VerificationError, StatusCode};
use anyhow::Result;
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::types::Elf;
use sp1_prover::{
    components::CpuSP1ProverComponents, local::LocalProver, SP1VerifyingKey, SP1_CIRCUIT_VERSION,
};

/// The module that exposes the [`ExecuteRequest`] type.
mod execute;

/// The module that exposes the [`ProveRequest`] trait.
mod prove;

pub use execute::ExecuteRequest;
pub(crate) use prove::BaseProveRequest;
pub use prove::ProveRequest;

use crate::SP1ProofWithPublicValues;

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
    fn setup(&self, elf: Elf) -> Result<Self::ProvingKey, Self::Error>;

    /// Prove the given program on the given input in the given proof mode.
    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a>;

    /// Execute the program on the given input.
    fn execute(&self, elf: Elf, stdin: SP1Stdin) -> ExecuteRequest<'_, Self> {
        ExecuteRequest::new(self, elf, stdin)
    }

    /// Verify the given proof.
    ///
    /// If the status code is not set, the verification process will check for success.
    fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
        status_code: Option<StatusCode>,
    ) -> Result<(), SP1VerificationError> {
        verify_proof(self.inner().prover(), self.version(), proof, vkey, status_code)
    }
}
