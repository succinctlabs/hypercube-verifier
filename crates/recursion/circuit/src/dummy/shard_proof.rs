use std::{
    collections::{BTreeMap, BTreeSet},
    iter::once,
};

use slop_algebra::AbstractField;
use slop_basefold::BasefoldVerifier;
use slop_multilinear::Point;
use sp1_hypercube::{
    air::MachineAir, septic_digest::SepticDigest, AirOpenedValues, Chip, ChipDimensions,
    ChipOpenedValues, MachineVerifyingKey, SP1CoreJaggedConfig, ShardOpenedValues, ShardProof,
    NUM_SP1_COMMITMENTS, PROOF_MAX_NUM_PVS,
};
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext};

use crate::dummy::{
    jagged::dummy_pcs_proof, logup_gkr::dummy_gkr_proof, sumcheck::dummy_sumcheck_proof,
};

type F = SP1Field;
type EF = SP1ExtensionField;

pub fn dummy_vk(
    preprocessed_chip_information: BTreeMap<String, ChipDimensions<F>>,
) -> MachineVerifyingKey<SP1GlobalContext, SP1CoreJaggedConfig> {
    MachineVerifyingKey {
        pc_start: [SP1Field::zero(); 3],
        initial_global_cumulative_sum: SepticDigest::zero(),
        preprocessed_commit: [SP1Field::zero(); 8],
        preprocessed_chip_information,
        marker: std::marker::PhantomData,
        enable_untrusted_programs: SP1Field::zero(),
    }
}

pub fn dummy_shard_proof<A: MachineAir<SP1Field>>(
    shard_chips: BTreeSet<Chip<SP1Field, A>>,
    max_log_row_count: usize,
    log_blowup: usize,
    log_stacking_height: usize,
    log_stacking_height_multiples: &[usize],
    added_cols: &[usize],
) -> ShardProof<SP1GlobalContext, SP1CoreJaggedConfig> {
    let default_verifier =
        BasefoldVerifier::<SP1GlobalContext>::new(log_blowup, NUM_SP1_COMMITMENTS);

    let fri_queries = default_verifier.fri_config.num_queries;

    let total_machine_cols =
        shard_chips.iter().map(|chip| chip.air.width() + chip.preprocessed_width()).sum::<usize>();

    let evaluation_proof = dummy_pcs_proof(
        fri_queries,
        log_stacking_height_multiples,
        log_stacking_height,
        log_blowup,
        total_machine_cols,
        once(shard_chips.iter().map(MachineAir::preprocessed_width).filter(|x| *x > 0).collect())
            .chain(once(shard_chips.iter().map(|chip| chip.air.width()).collect::<Vec<_>>()))
            .zip(added_cols.iter().copied())
            .collect(),
    );

    let logup_gkr_proof =
        dummy_gkr_proof::<_, SP1ExtensionField, _>(&shard_chips, max_log_row_count);
    dummy_gkr_proof::<_, SP1ExtensionField, _>(&shard_chips, max_log_row_count);

    let zerocheck_proof = dummy_sumcheck_proof::<SP1ExtensionField>(max_log_row_count, 4);

    ShardProof {
        public_values: vec![SP1Field::zero(); PROOF_MAX_NUM_PVS],
        main_commitment: [SP1Field::zero(); 8],
        logup_gkr_proof,
        zerocheck_proof,
        opened_values: ShardOpenedValues {
            chips: shard_chips
                .iter()
                .map(|chip| {
                    (
                        chip.name().clone(),
                        ChipOpenedValues {
                            preprocessed: AirOpenedValues {
                                local: vec![EF::zero(); chip.preprocessed_width()],
                            },
                            main: AirOpenedValues { local: vec![EF::zero(); chip.air.width()] },
                            local_cumulative_sum: EF::zero(),
                            degree: Point::from_usize(0, max_log_row_count + 1),
                        },
                    )
                })
                .collect(),
        },
        evaluation_proof,
        shard_chips: shard_chips.iter().map(|chip| chip.air.name().clone()).collect(),
    }
}
