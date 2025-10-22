// use slop_algebra::{extension::BinomialExtensionField, Field};
// use slop_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
// use slop_challenger::DuplexChallenger;
// use slop_commit::ExtensionMmcs;
// use slop_dft::p3::Radix2DitParallel;
// use slop_fri::FriConfig;
// use slop_jagged::JaggedPcs;
// use slop_merkle_tree::FieldMerkleTreeMmcs;
// use slop_multilinear::{StackedPcsProver, StackedPcsVerifier};
// use slop_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
// use slop_symmetric::{PaddingFreeSponge, TruncatedPermutation};

// use crate::{poseidon2::my_perm, BaseFoldPcs, BaseFoldProver};

// pub type Val = BabyBear;
// pub type Challenge = BinomialExtensionField<Val, 4>;
// pub type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
// pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
// pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
// pub type ValMmcs =
//     FieldMerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
// pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
// pub type Dft = Radix2DitParallel;
// pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

// pub type BaseFoldVerifierConfig = BaseFoldPcs<Val, Challenge, ValMmcs, Challenger>;
// pub type BaseFoldProverConfig = BaseFoldProver<Val, Challenge, ValMmcs, Challenger>;

// pub fn default_basefold_config() -> (BaseFoldProverConfig, BaseFoldVerifierConfig) {
//     let perm = my_perm();
//     let hash = MyHash::new(perm.clone());
//     let compress = MyCompress::new(perm.clone());
//     let inner_mmcs = ValMmcs::new(hash, compress);
//     let mmcs = ChallengeMmcs::new(inner_mmcs.clone());

//     let config =
//         FriConfig { log_blowup: 1, num_queries: 100, proof_of_work_bits: 16, mmcs: mmcs.clone() };

//     let pcs = BaseFoldPcs::<Val, Challenge, ValMmcs, Challenger>::new(config, inner_mmcs);
//     (BaseFoldProver::new(pcs.clone()), pcs)
// }

// pub fn default_stacked_basefold_config(
//     log_stacking_height: usize,
// ) -> (StackedPcsProver<BaseFoldProverConfig>, StackedPcsVerifier<BaseFoldVerifierConfig>) {
//     let (prover, verifier) = default_basefold_config();

//     (
//         StackedPcsProver::new(prover, log_stacking_height),
//         StackedPcsVerifier::new(verifier, log_stacking_height),
//     )
// }

// pub fn default_jagged_basefold_config(
//     log_stacking_height: usize,
//     max_log_row_count: usize,
// ) -> (
//     JaggedPcs<StackedPcsProver<BaseFoldProverConfig>>,
//     JaggedPcs<StackedPcsVerifier<BaseFoldVerifierConfig>>,
// ) {
//     let (prover, verifier) = default_stacked_basefold_config(log_stacking_height);

//     (JaggedPcs::new(prover, max_log_row_count), JaggedPcs::new(verifier, max_log_row_count))
// }
