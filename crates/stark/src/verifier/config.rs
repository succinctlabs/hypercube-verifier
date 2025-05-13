use std::{borrow::Borrow, collections::BTreeMap};

use hypercube_jagged::JaggedConfig;
use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_field::AbstractField;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sp1_primitives::poseidon2_hash;

use crate::{septic_digest::SepticDigest, DIGEST_SIZE};

/// A configuration for a machine.
pub trait MachineConfig:
    JaggedConfig + 'static + Send + Sync + Serialize + DeserializeOwned
{
}

impl<C> MachineConfig for C where
    C: JaggedConfig + 'static + Send + Sync + Serialize + DeserializeOwned
{
}

pub use hypercube_jagged::BabyBearPoseidon2;

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

impl<C: MachineConfig<F = BabyBear>> MachineVerifyingKey<C>
where
    C::Commitment: Borrow<[BabyBear; DIGEST_SIZE]>,
{
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

    /// Hash the verifying key, an array of `BabyBear` elements.
    pub fn hash_babybear(&self) -> [BabyBear; DIGEST_SIZE] {
        let num_inputs = DIGEST_SIZE + 1 + 14 + (4 * self.preprocessed_chip_information.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(
            self.preprocessed_commit
                .as_ref()
                .map(Borrow::borrow)
                .map(IntoIterator::into_iter)
                .unwrap_or_default()
                .copied(),
        );
        inputs.push(self.pc_start);
        inputs.extend(self.initial_global_cumulative_sum.0.x.0);
        inputs.extend(self.initial_global_cumulative_sum.0.y.0);
        for ChipDimensions { height, num_polynomials: _ } in
            self.preprocessed_chip_information.values()
        {
            inputs.push(BabyBear::from_canonical_usize(*height));
        }

        poseidon2_hash(inputs)
    }
}
