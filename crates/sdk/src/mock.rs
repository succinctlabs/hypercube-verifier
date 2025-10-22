//! # Mock Prover
//!
//! A mock prover that can be used for testing.

use std::pin::Pin;

use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{
    components::CpuSP1ProverComponents, local::LocalProver, Groth16Bn254Proof, PlonkBn254Proof,
    SP1VerifyingKey,
};

use crate::{
    cpu::{CPUProverError, CPUProvingKey, CpuProver},
    prover::{BaseProveRequest, ProveRequest},
    Prover, SP1Proof, SP1ProofWithPublicValues, SP1VerificationError, StatusCode,
};
use std::{
    future::{Future, IntoFuture},
    sync::Arc,
};

/// A mock prover that can be used for testing.
#[derive(Clone)]
pub struct MockProver {
    inner: CpuProver,
}

impl MockProver {
    /// Create a new mock prover.
    #[must_use]
    pub async fn new() -> Self {
        Self { inner: CpuProver::new().await }
    }
}

impl Prover for MockProver {
    type ProvingKey = CPUProvingKey;

    type Error = CPUProverError;

    type ProveRequest<'a> = MockProveRequest<'a>;

    fn inner(&self) -> Arc<LocalProver<CpuSP1ProverComponents>> {
        self.inner.inner()
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        MockProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
    }

    fn setup(
        &self,
        elf: sp1_build::Elf,
    ) -> impl crate::prover::SendFutureResult<Self::ProvingKey, Self::Error> {
        async move { Ok(self.inner.setup(elf).await.unwrap()) }
    }

    fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        _vkey: &SP1VerifyingKey,
        _status_code: Option<StatusCode>,
    ) -> Result<(), SP1VerificationError> {
        match &proof.proof {
            SP1Proof::Plonk(PlonkBn254Proof { public_inputs: _, .. }) => {
                todo!()
                // verify_plonk_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                // .map_err(SP1VerificationError::Plonk)
            }
            SP1Proof::Groth16(Groth16Bn254Proof { public_inputs: _, .. }) => {
                todo!()
                // verify_groth16_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                // .map_err(SP1VerificationError::Groth16)
            }
            _ => Ok(()),
        }
    }
}

/// A mock prove request that can be used for testing.
pub struct MockProveRequest<'a> {
    pub(crate) base: BaseProveRequest<'a, MockProver>,
}

impl<'a> ProveRequest<'a, MockProver> for MockProveRequest<'a> {
    fn base(&mut self) -> &mut BaseProveRequest<'a, MockProver> {
        &mut self.base
    }
}

impl<'a> IntoFuture for MockProveRequest<'a> {
    type Output = Result<SP1ProofWithPublicValues, CPUProverError>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let BaseProveRequest { prover, pk, mode: _, stdin, context_builder } = self.base;

            // Override the context builder, in case there's anything added.
            let mut req = prover.inner.execute(pk.elf.clone(), stdin);
            req.context_builder = context_builder;

            // Spawn blocking under the hood.
            let (public_values, _) = req.await?;

            Ok(SP1ProofWithPublicValues::create_mock_proof(
                &pk.vk,
                public_values,
                self.base.mode,
                prover.version(),
            ))
        })
    }
}
