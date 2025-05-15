use std::collections::BTreeMap;

use p3_challenger::CanObserve;
use p3_field::AbstractField;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use slop_jagged::JaggedConfig;

use crate::septic_digest::SepticDigest;

/// A configuration for a machine.
pub trait MachineConfig:
    JaggedConfig + 'static + Send + Sync + Serialize + DeserializeOwned
{
}

impl<C> MachineConfig for C where
    C: JaggedConfig + 'static + Send + Sync + Serialize + DeserializeOwned
{
}

pub use slop_jagged::{BabyBearPoseidon2, Bn254JaggedConfig};

/// A specification of preprocessed polynomial batch dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChipDimensions {
    /// The height of the preprocessed polynomial.
    pub height: usize,
    /// The number of polynomials in the preprocessed batch.
    pub num_polynomials: usize,
}

/// A verifying key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineVerifyingKey<C: MachineConfig> {
    /// The start pc of the program.
    pub pc_start: C::F,
    /// The starting global digest of the program, after incorporating the initial memory.
    pub initial_global_cumulative_sum: SepticDigest<C::F>,
    /// The preprocessed commitments.
    pub preprocessed_commit: Option<C::Commitment>,
    /// The dimensions of the preprocessed polynomials.
    pub preprocessed_chip_information: BTreeMap<String, ChipDimensions>,
}

impl<C: MachineConfig> MachineVerifyingKey<C> {
    /// Observes the values of the proving key into the challenger.
    pub fn observe_into(&self, challenger: &mut C::Challenger) {
        if let Some(preprocessed_commit) = self.preprocessed_commit.as_ref() {
            challenger.observe(preprocessed_commit.clone());
        }
        challenger.observe(self.pc_start);
        challenger.observe_slice(&self.initial_global_cumulative_sum.0.x.0);
        challenger.observe_slice(&self.initial_global_cumulative_sum.0.y.0);
        // Observe the padding.
        challenger.observe(C::F::zero());
    }
}
