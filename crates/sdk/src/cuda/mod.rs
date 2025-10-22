//! # SP1 CUDA Prover
//!
//! A prover that uses the CUDA to execute and prove programs.

/// The builder for the CUDA prover.
pub mod builder;
/// The CUDA prove request type.
pub mod prove;

use std::sync::Arc;

use crate::{
    cpu::CpuProver,
    prover::{BaseProveRequest, Prover, SendFutureResult},
    ProvingKey, SP1Proof, SP1ProofMode, SP1ProofWithPublicValues,
};

use prove::CudaProveRequest;
use sp1_core_executor::SP1Context;
use sp1_core_machine::io::SP1Stdin;
use sp1_cuda::{CudaClientError, CudaProver as CudaProverImpl, CudaProvingKey};
use sp1_primitives::Elf;
use sp1_prover::{
    components::CpuSP1ProverComponents, local::LocalProver, SP1CoreProofData, SP1ProofWithMetadata,
    SP1VerifyingKey,
};

/// A prover that uses the CPU for execution and the CUDA for proving.
#[derive(Clone)]
pub struct CudaProver {
    pub(crate) cpu_prover: CpuProver,
    pub(crate) prover: CudaProverImpl,
}

impl Prover for CudaProver {
    type ProvingKey = CudaProvingKey;
    type Error = CudaClientError;
    type ProveRequest<'a> = CudaProveRequest<'a>;

    fn inner(&self) -> Arc<LocalProver<CpuSP1ProverComponents>> {
        self.cpu_prover.inner()
    }

    fn setup(&self, elf: Elf) -> impl SendFutureResult<Self::ProvingKey, Self::Error> {
        self.prover.setup(elf)
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        CudaProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
    }
}

impl ProvingKey for CudaProvingKey {
    fn elf(&self) -> &Elf {
        self.elf()
    }

    fn verifying_key(&self) -> &SP1VerifyingKey {
        self.verifying_key()
    }
}

impl CudaProver {
    async fn prove_impl(
        &self,
        pk: &CudaProvingKey,
        stdin: SP1Stdin,
        context: SP1Context<'static>,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues, CudaClientError> {
        // Collect the deferred proofs
        let deferred_proofs =
            stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();

        // Generate the core proof.
        let proof: SP1ProofWithMetadata<SP1CoreProofData> =
            self.prover.core(pk, stdin, context.proof_nonce).await?;
        if mode == SP1ProofMode::Core {
            return Ok(SP1ProofWithPublicValues::new(
                SP1Proof::Core(proof.proof.0),
                proof.public_values,
                self.version().to_string(),
            ));
        }

        // Generate the compressed proof.
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.compress(pk.verifying_key(), proof, deferred_proofs).await?;
        if mode == SP1ProofMode::Compressed {
            return Ok(SP1ProofWithPublicValues::new(
                SP1Proof::Compressed(Box::new(reduce_proof)),
                public_values,
                self.version().to_string(),
            ));
        }

        // Generate the shrink proof.
        let compress_proof = self.prover.shrink(reduce_proof).await?;

        // Generate the wrap proof.
        let _outer_proof = self.prover.wrap(compress_proof).await?;

        // Generate the gnark proof.
        match mode {
            SP1ProofMode::Groth16 => {
                let _ = crate::install::try_install_circuit_artifacts("groth16").await;

                todo!()

                // let proof = self.prover.wrap_groth16_bn254(outer_proof,
                // &groth16_bn254_artifacts); Ok(SP1ProofWithPublicValues::new(
                //     SP1Proof::Groth16(proof),
                //     public_values,
                //     self.version().to_string(),
                // ))
            }
            SP1ProofMode::Plonk => {
                let _ = crate::install::try_install_circuit_artifacts("plonk").await;

                todo!()

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
