use std::fmt::Debug;
use std::marker::PhantomData;

use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, DuplexChallenger, FieldChallenger, GrindingChallenger};
use p3_field::{extension::BinomialExtensionField, ExtensionField, TwoAdicField};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use hypercube_commit::TensorCs;
use hypercube_merkle_tree::{my_bb_16_perm, MerkleTreeTcs, Perm, Poseidon2BabyBearConfig};

use crate::{BasefoldVerifier, FriConfig};

/// The configuration required for a Reed-Solomon-based Basefold.
pub trait BasefoldConfig:
    'static + Clone + Debug + Send + Sync + Serialize + DeserializeOwned
{
    /// The base field.
    ///
    /// This is the field on which the MLEs committed to are defined over.
    type F: TwoAdicField;
    /// The field of random elements.
    ///
    /// This is an extension field of the base field which is of cryptographically secure size. The
    /// random evaluation points of the protocol are drawn from `EF`.
    type EF: ExtensionField<Self::F>;

    type Commitment: 'static + Clone + Send + Sync + Serialize + DeserializeOwned;

    /// The tensor commitment scheme.
    ///
    /// The tensor commitment scheme is used to send long messages in the protocol by converting
    /// them to a tensor committment providing oracle acccess.
    type Tcs: TensorCs<Data = Self::F, Commitment = Self::Commitment>;
    /// The challenger type that creates the random challenges via Fiat-Shamir.
    ///
    /// The challenger is observing all the messages sent throughout the protocol and uses this
    /// to create the verifier messages of the IOP.
    type Challenger: FieldChallenger<Self::F>
        + GrindingChallenger
        + CanObserve<Self::Commitment>
        + 'static
        + Send
        + Sync
        + Clone;

    fn default_challenger(_verifier: &BasefoldVerifier<Self>) -> Self::Challenger;
}

pub trait DefaultBasefoldConfig: BasefoldConfig + Sized {
    fn default_verifier(log_blowup: usize) -> BasefoldVerifier<Self>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BasefoldConfigImpl<F, EF, Tcs, Challenger>(PhantomData<(F, EF, Tcs, Challenger)>);

impl<F, EF, Tcs, Challenger> std::fmt::Debug for BasefoldConfigImpl<F, EF, Tcs, Challenger> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BasefoldConfigImpl")
    }
}

impl<F, EF, Tcs, Challenger> Default for BasefoldConfigImpl<F, EF, Tcs, Challenger> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

pub type Poseidon2BabyBear16BasefoldConfig = BasefoldConfigImpl<
    BabyBear,
    BinomialExtensionField<BabyBear, 4>,
    MerkleTreeTcs<Poseidon2BabyBearConfig>,
    DuplexChallenger<BabyBear, Perm, 16, 8>,
>;

impl BasefoldConfig for Poseidon2BabyBear16BasefoldConfig {
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
    type Commitment = <MerkleTreeTcs<Poseidon2BabyBearConfig> as TensorCs>::Commitment;
    type Tcs = MerkleTreeTcs<Poseidon2BabyBearConfig>;
    type Challenger = DuplexChallenger<BabyBear, Perm, 16, 8>;

    fn default_challenger(
        _verifier: &BasefoldVerifier<Self>,
    ) -> DuplexChallenger<BabyBear, Perm, 16, 8> {
        let default_perm = my_bb_16_perm();
        DuplexChallenger::<BabyBear, Perm, 16, 8>::new(default_perm)
    }
}

impl DefaultBasefoldConfig for Poseidon2BabyBear16BasefoldConfig {
    fn default_verifier(log_blowup: usize) -> BasefoldVerifier<Self> {
        let fri_config = FriConfig::<BabyBear>::auto(log_blowup, 100);
        let tcs = MerkleTreeTcs::<Poseidon2BabyBearConfig>::default();
        BasefoldVerifier::<Self> { fri_config, tcs }
    }
}
