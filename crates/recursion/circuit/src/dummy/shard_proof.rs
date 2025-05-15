use std::collections::{BTreeMap, BTreeSet};

use hypercube_stark::{
    air::MachineAir, septic_digest::SepticDigest, AirOpenedValues, BabyBearPoseidon2, Chip,
    ChipDimensions, ChipOpenedValues, MachineVerifyingKey, ShardOpenedValues, ShardProof,
    PROOF_MAX_NUM_PVS,
};
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use slop_basefold::{DefaultBasefoldConfig, Poseidon2BabyBear16BasefoldConfig};
use slop_jagged::JaggedConfig;
use slop_multilinear::Point;

use crate::dummy::{
    jagged::dummy_pcs_proof, logup_gkr::dummy_gkr_proof, sumcheck::dummy_sumcheck_proof,
};

type EF = <BabyBearPoseidon2 as JaggedConfig>::EF;

pub fn dummy_vk(
    preprocessed_chip_information: BTreeMap<String, ChipDimensions>,
) -> MachineVerifyingKey<BabyBearPoseidon2> {
    MachineVerifyingKey {
        pc_start: BabyBear::zero(),
        initial_global_cumulative_sum: SepticDigest::zero(),
        preprocessed_commit: Some([BabyBear::zero(); 8]),
        preprocessed_chip_information,
    }
}

pub fn dummy_shard_proof<A: MachineAir<BabyBear>>(
    shard_chips: BTreeSet<Chip<BabyBear, A>>,
    max_log_row_count: usize,
    log_blowup: usize,
    log_stacking_height: usize,
    log_stacking_height_multiples: &[usize],
) -> ShardProof<BabyBearPoseidon2> {
    let default_verifier = Poseidon2BabyBear16BasefoldConfig::default_verifier(log_blowup);
    let fri_queries = default_verifier.fri_config.num_queries;

    let total_machine_cols =
        shard_chips.iter().map(|chip| chip.air.width() + chip.preprocessed_width()).sum::<usize>();

    let evaluation_proof = dummy_pcs_proof(
        fri_queries,
        log_stacking_height_multiples,
        log_stacking_height,
        log_blowup,
        total_machine_cols,
        max_log_row_count,
    );

    let logup_gkr_proof = dummy_gkr_proof::<_, <BabyBearPoseidon2 as JaggedConfig>::EF, _>(
        &shard_chips,
        max_log_row_count,
    );

    let zerocheck_proof =
        dummy_sumcheck_proof::<<BabyBearPoseidon2 as JaggedConfig>::EF>(max_log_row_count, 4);

    ShardProof {
        public_values: vec![BabyBear::zero(); PROOF_MAX_NUM_PVS],
        main_commitment: [BabyBear::zero(); 8],
        logup_gkr_proof,
        zerocheck_proof,
        opened_values: ShardOpenedValues {
            chips: shard_chips
                .iter()
                .map(|chip| ChipOpenedValues {
                    preprocessed: AirOpenedValues {
                        local: vec![EF::zero(); chip.preprocessed_width()],
                        next: vec![],
                    },
                    main: AirOpenedValues {
                        local: vec![EF::zero(); chip.air.width()],
                        next: vec![],
                    },
                    local_cumulative_sum: EF::zero(),
                    degree: Point::from_usize(0, max_log_row_count + 1),
                })
                .collect(),
        },
        evaluation_proof,
        shard_chips: shard_chips.iter().map(|chip| chip.air.name().to_string()).collect(),
    }
}
