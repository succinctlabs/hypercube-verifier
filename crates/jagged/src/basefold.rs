use p3_baby_bear::BabyBear;
use serde::{Deserialize, Serialize};
use slop_basefold::{
    BasefoldConfig, BasefoldProof, BasefoldVerifier, DefaultBasefoldConfig,
    Poseidon2BabyBear16BasefoldConfig, Poseidon2Bn254FrBasefoldConfig,
};
use slop_stacked::StackedPcsVerifier;
use std::fmt::Debug;

use crate::{
    JaggedConfig, JaggedEvalConfig, JaggedEvalSumcheckConfig, JaggedPcsVerifier,
    TrivialJaggedEvalConfig,
};

pub type BabyBearPoseidon2 =
    JaggedBasefoldConfig<Poseidon2BabyBear16BasefoldConfig, JaggedEvalSumcheckConfig<BabyBear>>;

pub type Bn254JaggedConfig =
    JaggedBasefoldConfig<Poseidon2Bn254FrBasefoldConfig, JaggedEvalSumcheckConfig<BabyBear>>;

pub type BabyBearPoseidon2TrivialEval =
    JaggedBasefoldConfig<Poseidon2BabyBear16BasefoldConfig, TrivialJaggedEvalConfig>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JaggedBasefoldConfig<BC, E>(BC, E);

impl<BC, E> JaggedConfig for JaggedBasefoldConfig<BC, E>
where
    BC: BasefoldConfig,
    E: JaggedEvalConfig<BC::F, BC::EF, BC::Challenger> + Clone,
    BC::Commitment: Debug,
{
    type F = BC::F;
    type EF = BC::EF;
    type Commitment = BC::Commitment;
    type BatchPcsProof = BasefoldProof<BC>;
    type Challenger = BC::Challenger;
    type BatchPcsVerifier = BasefoldVerifier<BC>;
    type JaggedEvaluator = E;
}

impl<BC, E> JaggedPcsVerifier<JaggedBasefoldConfig<BC, E>>
where
    BC: DefaultBasefoldConfig,
    BC::Commitment: Debug,
    E: JaggedEvalConfig<BC::F, BC::EF, BC::Challenger> + Default,
{
    pub fn new(log_blowup: usize, log_stacking_height: u32, max_log_row_count: usize) -> Self {
        let basefold_verifer = BasefoldVerifier::<BC>::new(log_blowup);
        let stacked_pcs_verifier = StackedPcsVerifier::new(basefold_verifer, log_stacking_height);
        Self { stacked_pcs_verifier, max_log_row_count, jagged_evaluator: E::default() }
    }
}
