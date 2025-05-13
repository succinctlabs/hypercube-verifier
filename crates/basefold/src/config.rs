use std::fmt::Debug;
use std::marker::PhantomData;

use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_challenger::{
    CanObserve, DuplexChallenger, FieldChallenger, GrindingChallenger, MultiField32Challenger,
};
use p3_field::{extension::BinomialExtensionField, ExtensionField, TwoAdicField};
use p3_symmetric::Hash;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use slop_commit::TensorCs;
use slop_merkle_tree::{
    my_bb_16_perm, outer_perm, MerkleTreeTcs, OuterPerm, Perm, Poseidon2BabyBearConfig,
    Poseidon2Bn254Config, OUTER_CHALLENGER_RATE, OUTER_CHALLENGER_STATE_WIDTH, OUTER_DIGEST_SIZE,
};

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

// impl<F, EF, Tcs, Challenger> BasefoldConfig for BasefoldConfigImpl<F, EF, Tcs, Challenger>
// where
//     F: TwoAdicField,
//     EF: ExtensionField<F>,
//     Tcs: TensorCs<Data = F>,
//     Challenger: FieldChallenger<F>
//         + GrindingChallenger
//         + CanObserve<<Tcs as TensorCs>::Commitment>
//         + 'static
//         + Send
//         + Sync,
// {
//     type F = F;
//     type EF = EF;
//     type Tcs = Tcs;
//     type Commitment = <Tcs as TensorCs>::Commitment;
//     type Challenger = Challenger;
// }

pub type Poseidon2BabyBear16BasefoldConfig = BasefoldConfigImpl<
    BabyBear,
    BinomialExtensionField<BabyBear, 4>,
    MerkleTreeTcs<Poseidon2BabyBearConfig>,
    DuplexChallenger<BabyBear, Perm, 16, 8>,
>;

pub type Poseidon2Bn254FrBasefoldConfig = BasefoldConfigImpl<
    BabyBear,
    BinomialExtensionField<BabyBear, 4>,
    MerkleTreeTcs<Poseidon2Bn254Config>,
    MultiField32Challenger<
        BabyBear,
        Bn254Fr,
        OuterPerm,
        OUTER_CHALLENGER_STATE_WIDTH,
        OUTER_CHALLENGER_RATE,
    >,
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

impl BasefoldConfig for Poseidon2Bn254FrBasefoldConfig {
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
    type Commitment = Hash<BabyBear, Bn254Fr, OUTER_DIGEST_SIZE>;
    type Tcs = MerkleTreeTcs<Poseidon2Bn254Config>;
    type Challenger = MultiField32Challenger<
        BabyBear,
        Bn254Fr,
        OuterPerm,
        OUTER_CHALLENGER_STATE_WIDTH,
        OUTER_CHALLENGER_RATE,
    >;

    fn default_challenger(
        _verifier: &BasefoldVerifier<Self>,
    ) -> MultiField32Challenger<
        BabyBear,
        Bn254Fr,
        OuterPerm,
        OUTER_CHALLENGER_STATE_WIDTH,
        OUTER_CHALLENGER_RATE,
    > {
        let default_perm = outer_perm();
        MultiField32Challenger::<
            BabyBear,
            Bn254Fr,
            OuterPerm,
            OUTER_CHALLENGER_STATE_WIDTH,
            OUTER_CHALLENGER_RATE,
        >::new(default_perm)
        .unwrap()
    }
}

impl DefaultBasefoldConfig for Poseidon2Bn254FrBasefoldConfig {
    fn default_verifier(log_blowup: usize) -> BasefoldVerifier<Self> {
        let fri_config = FriConfig::<BabyBear>::auto(log_blowup, 100);
        let tcs = MerkleTreeTcs::<Poseidon2Bn254Config>::default();
        BasefoldVerifier::<Self> { fri_config, tcs }
    }
}
