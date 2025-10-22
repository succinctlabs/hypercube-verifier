use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use slop_algebra::extension::BinomialExtensionField;
use slop_baby_bear::{
    baby_bear_poseidon2::{BabyBearDegree4Duplex, Perm},
    BabyBear,
};
use slop_bn254::{
    Bn254Fr, OuterPerm, Poseidon2Bn254GlobalConfig, OUTER_CHALLENGER_RATE,
    OUTER_CHALLENGER_STATE_WIDTH,
};
use slop_challenger::{DuplexChallenger, MultiField32Challenger};
use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex, KoalaPerm};
use slop_merkle_tree::MerkleTreeTcs;

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
    MerkleTreeTcs<BabyBearDegree4Duplex>,
    DuplexChallenger<BabyBear, Perm, 16, 8>,
>;

pub type Poseidon2KoalaBear16BasefoldConfig = BasefoldConfigImpl<
    KoalaBear,
    BinomialExtensionField<KoalaBear, 4>,
    MerkleTreeTcs<KoalaBearDegree4Duplex>,
    DuplexChallenger<KoalaBear, KoalaPerm, 16, 8>,
>;

pub type Poseidon2Bn254FrBasefoldConfig<F, EF> = BasefoldConfigImpl<
    F,
    BinomialExtensionField<F, 4>,
    MerkleTreeTcs<Poseidon2Bn254GlobalConfig<F, EF>>,
    MultiField32Challenger<
        F,
        Bn254Fr,
        OuterPerm,
        OUTER_CHALLENGER_STATE_WIDTH,
        OUTER_CHALLENGER_RATE,
    >,
>;
