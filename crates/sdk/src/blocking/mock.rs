//! # Mock Prover
//!
//! A mock prover that can be used for testing.

use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{
    components::CpuSP1ProverComponents, local::LocalProver, Groth16Bn254Proof, PlonkBn254Proof,
    SP1VerifyingKey,
};

use crate::{
    blocking::{
        cpu::{CPUProverError, CpuProver},
        prover::{BaseProveRequest, ProveRequest, Prover},
    },
    cpu::CPUProvingKey,
    SP1Proof, SP1ProofWithPublicValues, SP1VerificationError, StatusCode,
};
use std::sync::Arc;

/// A mock prover that can be used for testing.
#[derive(Default, Clone)]
pub struct MockProver {
    inner: CpuProver,
}

impl MockProver {
    /// Create a new mock prover.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

    fn setup(&self, elf: sp1_build::Elf) -> Result<Self::ProvingKey, Self::Error> {
        Ok(self.inner.setup(elf).unwrap())
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

    fn run(self) -> Result<SP1ProofWithPublicValues, CPUProverError> {
        let BaseProveRequest { prover, pk, mode, stdin, context_builder } = self.base;
        let mut req = prover.inner.execute(pk.elf.clone(), stdin);
        req.context_builder = context_builder;
        let (public_values, _) = req.run()?;
        Ok(SP1ProofWithPublicValues::create_mock_proof(
            &pk.vk,
            public_values,
            mode,
            prover.version(),
        ))
    }
}
