use crate::utils::words_to_bytes_be;
use anyhow::Result;
use clap::ValueEnum;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use slop_algebra::{AbstractField, PrimeField, PrimeField32};
use slop_bn254::Bn254Fr;
use slop_challenger::IopCtx;
use sp1_core_machine::io::SP1Stdin;
use sp1_hypercube::{
    air::ShardRange, ChipDimensions, MachineConfig, MachineVerifyingKey, ShardProof, DIGEST_SIZE,
};
use sp1_primitives::{io::SP1PublicValues, poseidon2_hash, SP1Field, SP1GlobalContext};
use sp1_recursion_circuit::{
    machine::{
        SP1CompressWithVKeyWitnessValues, SP1DeferredWitnessValues, SP1NormalizeWitnessValues,
        SP1ShapedWitnessValues,
    },
    utils::koalabears_to_bn254,
    InnerSC,
};
pub use sp1_recursion_gnark_ffi::proof::{Groth16Bn254Proof, PlonkBn254Proof};
use std::{borrow::Borrow, fs::File, path::Path};
use thiserror::Error;

use crate::CoreSC;

/// The information necessary to verify a proof for a given RISC-V program.
#[derive(Clone, Serialize, Deserialize)]
pub struct SP1VerifyingKey {
    pub vk: MachineVerifyingKey<SP1GlobalContext, CoreSC>,
}

/// A trait for keys that can be hashed into a digest.
pub trait HashableKey {
    /// Hash the key into a digest of SP1Field elements.
    fn hash_koalabear(&self) -> [SP1Field; DIGEST_SIZE];

    /// Hash the key into a digest of u32 elements.
    fn hash_u32(&self) -> [u32; DIGEST_SIZE];

    /// Hash the key into a Bn254Fr element.
    fn hash_bn254(&self) -> Bn254Fr {
        koalabears_to_bn254(&self.hash_koalabear())
    }

    /// Hash the key into a 32 byte hex string, prefixed with "0x".
    ///
    /// This is ideal for generating a vkey hash for onchain verification.
    fn bytes32(&self) -> String {
        let vkey_digest_bn254 = self.hash_bn254();
        format!("0x{:0>64}", vkey_digest_bn254.as_canonical_biguint().to_str_radix(16))
    }

    /// Hash the key into a 32 byte array.
    ///
    /// This has the same value as `bytes32`, but as a raw byte array.
    fn bytes32_raw(&self) -> [u8; 32] {
        let vkey_digest_bn254 = self.hash_bn254();
        let vkey_bytes = vkey_digest_bn254.as_canonical_biguint().to_bytes_be();
        let mut result = [0u8; 32];
        result[1..].copy_from_slice(&vkey_bytes);
        result
    }

    /// Hash the key into a digest of bytes elements.
    fn hash_bytes(&self) -> [u8; DIGEST_SIZE * 4] {
        words_to_bytes_be(&self.hash_u32())
    }

    /// Hash the key into a digest of u64 elements.
    fn hash_u64(&self) -> [u64; DIGEST_SIZE / 2] {
        self.hash_u32()
            .chunks_exact(2)
            .map(|chunk| chunk[0] as u64 | ((chunk[1] as u64) << 32))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl HashableKey for SP1VerifyingKey {
    fn hash_koalabear(&self) -> [SP1Field; DIGEST_SIZE] {
        self.vk.hash_koalabear()
    }

    fn hash_u32(&self) -> [u32; DIGEST_SIZE] {
        self.vk.hash_u32()
    }
}

impl<GC: IopCtx<F = SP1Field>, C: MachineConfig<GC>> HashableKey for MachineVerifyingKey<GC, C>
where
    GC::Digest: Borrow<[SP1Field; DIGEST_SIZE]>,
{
    fn hash_koalabear(&self) -> [SP1Field; DIGEST_SIZE] {
        let num_inputs = DIGEST_SIZE + 3 + 14 + 1;
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.preprocessed_commit.borrow());
        inputs.extend(self.pc_start);
        inputs.extend(self.initial_global_cumulative_sum.0.x.0);
        inputs.extend(self.initial_global_cumulative_sum.0.y.0);
        inputs.push(self.enable_untrusted_programs);
        for (name, ChipDimensions { height, num_polynomials: _ }) in
            self.preprocessed_chip_information.iter()
        {
            inputs.push(*height);
            inputs.push(SP1Field::from_canonical_usize(name.len()));
            for byte in name.as_bytes() {
                inputs.push(SP1Field::from_canonical_u8(*byte));
            }
        }

        poseidon2_hash(inputs)
    }

    fn hash_u32(&self) -> [u32; 8] {
        self.hash_koalabear()
            .into_iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(serialize = "P: Serialize"))]
#[serde(bound(deserialize = "P: DeserializeOwned"))]
pub struct SP1ProofWithMetadata<P: Clone> {
    pub proof: P,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
    pub cycles: u64,
}

impl<P: Serialize + DeserializeOwned + Clone> SP1ProofWithMetadata<P> {
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(Into::into)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(Into::into)
    }
}

impl<P: std::fmt::Debug + Clone> std::fmt::Debug for SP1ProofWithMetadata<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SP1ProofWithMetadata").field("proof", &self.proof).finish()
    }
}

/// A proof of an SP1 program without any wrapping.
pub type SP1CoreProof = SP1ProofWithMetadata<SP1CoreProofData>;

/// An SP1 proof that has been recursively reduced into a single proof. This proof can be
/// verified within SP1 programs.
pub type SP1ReducedProof = SP1ProofWithMetadata<SP1ReducedProofData>;

/// An SP1 proof that has been wrapped into a single PLONK proof and can be verified onchain.
pub type SP1PlonkBn254Proof = SP1ProofWithMetadata<SP1PlonkBn254ProofData>;

/// An SP1 proof that has been wrapped into a single Groth16 proof and can be verified onchain.
pub type SP1Groth16Bn254Proof = SP1ProofWithMetadata<SP1Groth16Bn254ProofData>;

/// An SP1 proof that has been wrapped into a single proof and can be verified onchain.
pub type SP1Proof = SP1ProofWithMetadata<SP1Bn254ProofData>;

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1CoreProofData(pub Vec<ShardProof<SP1GlobalContext, CoreSC>>);

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1ReducedProofData(pub ShardProof<SP1GlobalContext, InnerSC>);

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1PlonkBn254ProofData(pub PlonkBn254Proof);

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1Groth16Bn254ProofData(pub Groth16Bn254Proof);

#[derive(Serialize, Deserialize, Clone)]
pub enum SP1Bn254ProofData {
    Plonk(PlonkBn254Proof),
    Groth16(Groth16Bn254Proof),
}

impl SP1Bn254ProofData {
    pub fn get_proof_system(&self) -> ProofSystem {
        match self {
            SP1Bn254ProofData::Plonk(_) => ProofSystem::Plonk,
            SP1Bn254ProofData::Groth16(_) => ProofSystem::Groth16,
        }
    }

    pub fn get_raw_proof(&self) -> &str {
        match self {
            SP1Bn254ProofData::Plonk(proof) => &proof.raw_proof,
            SP1Bn254ProofData::Groth16(proof) => &proof.raw_proof,
        }
    }
}

/// The mode of the prover.
#[derive(Debug, Default, Clone, ValueEnum, PartialEq, Eq)]
pub enum ProverMode {
    #[default]
    Cpu,
    Cuda,
    Network,
    Mock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystem {
    Plonk,
    Groth16,
}

impl ProofSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofSystem::Plonk => "Plonk",
            ProofSystem::Groth16 => "Groth16",
        }
    }
}

#[derive(Error, Debug)]
pub enum SP1RecursionProverError {
    #[error("Runtime error: {0}")]
    RuntimeError(String),
}

pub type SP1CompressWitness = SP1ShapedWitnessValues<SP1GlobalContext, InnerSC>;

#[allow(clippy::large_enum_variant)]
pub enum SP1CircuitWitness {
    Core(SP1NormalizeWitnessValues<SP1GlobalContext, CoreSC>),
    Deferred(SP1DeferredWitnessValues<SP1GlobalContext, InnerSC>),
    Compress(SP1CompressWitness),
    Shrink(SP1CompressWithVKeyWitnessValues<InnerSC>),
    Wrap(SP1CompressWithVKeyWitnessValues<InnerSC>),
}

impl SP1CircuitWitness {
    pub fn range(&self) -> ShardRange {
        match self {
            SP1CircuitWitness::Core(input) => input.range(),
            SP1CircuitWitness::Deferred(input) => input.range(),
            SP1CircuitWitness::Compress(input) => input.range(),
            SP1CircuitWitness::Shrink(_) => {
                unimplemented!("Shrink witness does not need to have a range")
            }
            SP1CircuitWitness::Wrap(_) => {
                unimplemented!("Wrap witness does not need to have a range")
            }
        }
    }
}
