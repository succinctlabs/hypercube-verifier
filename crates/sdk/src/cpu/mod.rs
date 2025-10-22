//! # SP1 CPU Prover
//!
//! A prover that uses the CPU to execute and prove programs.

pub mod builder;
pub mod prove;

use std::sync::Arc;

use anyhow::Result;
use prove::CpuProveBuilder;
use sp1_core_executor::{ExecutionError, Program, SP1Context};
use sp1_core_machine::io::SP1Stdin;
use sp1_hypercube::prover::MachineProvingKey;
use sp1_primitives::{Elf, SP1GlobalContext};
use sp1_prover::{
    components::CpuSP1ProverComponents,
    // verify::{verify_groth16_bn254_public_inputs, verify_plonk_bn254_public_inputs},
    SP1CoreProofData,
    SP1ProofWithMetadata,
};
use sp1_prover::{
    components::SP1ProverComponents,
    error::SP1ProverError,
    local::{LocalProver, LocalProverOpts},
    SP1ProverBuilder, SP1VerifyingKey,
};

use crate::{
    install::try_install_circuit_artifacts,
    prover::{Prover, ProvingKey, SendFutureResult},
    SP1Proof, SP1ProofMode, SP1ProofWithPublicValues,
};

use thiserror::Error;

/// A prover that uses the CPU to execute and prove programs.
#[derive(Clone)]
pub struct CpuProver {
    pub(crate) prover: Arc<LocalProver<CpuSP1ProverComponents>>,
}

/// A proving key for the [`CpuProver`].
///
/// This struct is used to store the proving key for the [`CpuProver`].
#[derive(Clone)]
pub struct CPUProvingKey {
    pub(crate) raw: Arc<
        MachineProvingKey<
            SP1GlobalContext,
            <CpuSP1ProverComponents as SP1ProverComponents>::CoreComponents,
        >,
    >,
    pub(crate) vk: SP1VerifyingKey,
    pub(crate) program: Arc<Program>,
    pub(crate) elf: Elf,
}

/// An error occurred while proving.
#[derive(Debug, Error)]
pub enum CPUProverError {
    /// An error occurred while proving.
    #[error(transparent)]
    Prover(#[from] SP1ProverError),

    /// An error occurred while executing.
    #[error(transparent)]
    Execution(#[from] ExecutionError),

    /// An unexpected error occurred.
    #[error("An unexpected error occurred: {:?}", .0)]
    Unexpected(#[from] anyhow::Error),
}

impl ProvingKey for CPUProvingKey {
    fn verifying_key(&self) -> &SP1VerifyingKey {
        &self.vk
    }

    fn elf(&self) -> &Elf {
        &self.elf
    }
}

impl Prover for CpuProver {
    type ProvingKey = CPUProvingKey;
    type Error = CPUProverError;
    type ProveRequest<'a> = CpuProveBuilder<'a>;

    fn inner(&self) -> Arc<LocalProver<CpuSP1ProverComponents>> {
        self.prover.clone()
    }

    fn setup(&self, elf: Elf) -> impl SendFutureResult<Self::ProvingKey, Self::Error> {
        async move {
            let (raw, program, vk) = self.prover.prover().core().setup(&elf).await;

            // todo!(n): safety comments
            let inner = unsafe { raw.into_inner() };

            Ok(CPUProvingKey { raw: inner, vk, elf, program })
        }
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        CpuProveBuilder::new(self, pk, stdin)
    }
}

impl CpuProver {
    /// Creates a new [`CpuProver`], using the default [`LocalProverOpts`].
    #[must_use]
    pub async fn new() -> Self {
        Self::new_with_opts(None).await
    }

    /// Creates a new [`CpuProver`] with optional custom [`SP1CoreOpts`].
    #[must_use]
    pub async fn new_with_opts(core_opts: Option<sp1_core_executor::SP1CoreOpts>) -> Self {
        let prover = SP1ProverBuilder::<CpuSP1ProverComponents>::new().build().await;
        let mut opts = LocalProverOpts::default();

        // Override core_opts if provided
        if let Some(core_opts) = core_opts {
            opts.core_opts = core_opts;
        }

        let prover = Arc::new(LocalProver::new(prover, opts));

        Self { prover }
    }

    /// # ⚠️ WARNING: This prover is experimental and should not be used in production.
    /// It is intended for development and debugging purposes.
    ///
    /// Creates a new [`CpuProver`], using the default [`LocalProverOpts`].
    /// Verification of the proof system's verification key is skipped, meaning that the
    /// recursion proofs are not guaranteed to be about a permitted recursion program.
    #[cfg(feature = "experimental")]
    #[must_use]
    pub async fn new_experimental() -> Self {
        let prover = SP1ProverBuilder::<CpuSP1ProverComponents>::new()
            .without_vk_verification()
            .build()
            .await;
        let opts = LocalProverOpts::default();
        let prover = Arc::new(LocalProver::new(prover, opts));

        Self { prover }
    }

    pub(crate) async fn prove_impl(
        &self,
        pk: &CPUProvingKey,
        stdin: SP1Stdin,
        context: SP1Context<'static>,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues, CPUProverError> {
        // Collect the deferred proofs
        let deferred_proofs =
            stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();

        let CPUProvingKey { raw: pk, vk, program, .. } = pk;

        // Generate the core proof.
        let proof: SP1ProofWithMetadata<SP1CoreProofData> =
            self.prover.clone().prove_core(pk.clone(), program.clone(), stdin, context).await?;
        if mode == SP1ProofMode::Core {
            return Ok(SP1ProofWithPublicValues::new(
                SP1Proof::Core(proof.proof.0),
                proof.public_values,
                self.version().to_string(),
            ));
        }

        // Generate the compressed proof.
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.clone().compress(vk, proof, deferred_proofs).await?;
        if mode == SP1ProofMode::Compressed {
            return Ok(SP1ProofWithPublicValues::new(
                SP1Proof::Compressed(Box::new(reduce_proof)),
                public_values,
                self.version().to_string(),
            ));
        }

        // Generate the shrink proof.
        // let compress_proof = self.prover.shrink(reduce_proof, opts)?;

        // Generate the wrap proof.
        // let outer_proof = self.prover.wrap_bn254(compress_proof, opts)?;

        // Generate the gnark proof.
        match mode {
            SP1ProofMode::Groth16 => {
                let _ = try_install_circuit_artifacts("groth16").await;
                todo!()

                // let proof = self.prover.wrap_groth16_bn254(outer_proof,
                // &groth16_bn254_artifacts); Ok(SP1ProofWithPublicValues::new(
                //     SP1Proof::Groth16(proof),
                //     public_values,
                //     self.version().to_string(),
                // ))
            }
            SP1ProofMode::Plonk => {
                let _ = try_install_circuit_artifacts("plonk").await;

                todo!()
                // let plonk_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
                //     sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                //         &outer_proof.vk,
                //         &outer_proof.proof,
                //     )
                // } else {
                //     try_install_circuit_artifacts("plonk")
                // };
                // let proof = self.prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_artifacts);
                // Ok(SP1ProofWithPublicValues::new(
                //     SP1Proof::Plonk(proof),
                //     public_values,
                //     self.version().to_string(),
                // ))
            }
            _ => unreachable!(),
        }
    }
}
