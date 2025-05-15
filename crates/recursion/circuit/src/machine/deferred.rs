use std::{
    array,
    borrow::{Borrow, BorrowMut},
};

use serde::{Deserialize, Serialize};

use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
// use slop_commit::Mmcs;
// use slop_matrix::dense::RowMajorMatrix;
use hypercube_recursion_compiler::ir::{Builder, Felt};
use hypercube_stark::{
    air::MachineAir, septic_curve::SepticCurve, septic_digest::SepticDigest, MachineVerifyingKey,
    ShardProof, Word,
};

use hypercube_recursion_executor::{
    RecursionPublicValues, DIGEST_SIZE, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS,
    RECURSIVE_PROOF_NUM_PV_ELTS,
};

use crate::{
    basefold::{RecursiveBasefoldConfigImpl, RecursiveBasefoldProof, RecursiveBasefoldVerifier},
    challenger::{CanObserveVariable, DuplexChallengerVariable},
    hash::{FieldHasher, FieldHasherVariable},
    jagged::RecursiveJaggedConfig,
    shard::{MachineVerifyingKeyVariable, RecursiveShardVerifier, ShardProofVariable},
    zerocheck::RecursiveVerifierConstraintFolder,
    BabyBearFriConfig,
    BabyBearFriConfigVariable,
    CircuitConfig, // {ShardProofVariable, StarkVerifier, VerifyingKeyVariable},
};

use super::{assert_complete, recursion_public_values_digest, SP1CompressShape};

pub struct SP1DeferredVerifier<C, SC, A, JC> {
    _phantom: std::marker::PhantomData<(C, SC, A, JC)>,
}

#[derive(Debug, Clone, Hash)]
pub struct SP1DeferredShape {
    inner: SP1CompressShape,
    height: usize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "SC::Challenger: Serialize, ShardProof<SC>: Serialize, [SC::F; DIGEST_SIZE]: Serialize, SC::Digest: Serialize"
))]
#[serde(bound(
    deserialize = "SC::Challenger: Deserialize<'de>, ShardProof<SC>: Deserialize<'de>,  [SC::F; DIGEST_SIZE]: Deserialize<'de>, SC::Digest: Deserialize<'de>"
))]
pub struct SP1DeferredWitnessValues<SC: BabyBearFriConfig + FieldHasher<BabyBear> + Send + Sync> {
    pub vks_and_proofs: Vec<(MachineVerifyingKey<SC>, ShardProof<SC>)>,
    // pub vk_merkle_data: SP1MerkleProofWitnessValues<SC>,
    pub start_reconstruct_deferred_digest: [SC::F; POSEIDON_NUM_WORDS],
    pub sp1_vk_digest: [SC::F; DIGEST_SIZE],
    pub committed_value_digest: [[SC::F; 4]; PV_DIGEST_NUM_WORDS],
    pub deferred_proofs_digest: [SC::F; POSEIDON_NUM_WORDS],
    pub end_pc: SC::F,
    pub end_shard: SC::F,
    pub end_execution_shard: SC::F,
    pub init_addr_word: Word<SC::F>,
    pub finalize_addr_word: Word<SC::F>,
    pub is_complete: bool,
}

#[allow(clippy::type_complexity)]
pub struct SP1DeferredWitnessVariable<
    C: CircuitConfig<F = BabyBear, EF = crate::EF>,
    SC: FieldHasherVariable<C> + BabyBearFriConfigVariable<C>,
    JC: RecursiveJaggedConfig<
        BatchPcsVerifier = RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
    >,
> {
    pub vks_and_proofs: Vec<(MachineVerifyingKeyVariable<C, SC>, ShardProofVariable<C, SC, JC>)>,
    // pub vk_merkle_data: SP1MerkleProofWitnessVariable<C, SC>,
    pub start_reconstruct_deferred_digest: [Felt<C::F>; POSEIDON_NUM_WORDS],
    pub sp1_vk_digest: [Felt<C::F>; DIGEST_SIZE],
    pub committed_value_digest: [[Felt<C::F>; 4]; PV_DIGEST_NUM_WORDS],
    pub deferred_proofs_digest: [Felt<C::F>; POSEIDON_NUM_WORDS],
    pub end_pc: Felt<C::F>,
    pub end_shard: Felt<C::F>,
    pub end_execution_shard: Felt<C::F>,
    pub init_addr_word: Word<Felt<C::F>>,
    pub finalize_addr_word: Word<Felt<C::F>>,
    pub is_complete: Felt<C::F>,
}

impl<C, SC, A, JC> SP1DeferredVerifier<C, SC, A, JC>
where
    SC: BabyBearFriConfigVariable<
            C,
            FriChallengerVariable = DuplexChallengerVariable<C>,
            DigestVariable = [Felt<BabyBear>; DIGEST_SIZE],
        > + Send
        + Sync,
    C: CircuitConfig<F = SC::F, EF = SC::EF, Bit = Felt<BabyBear>>,
    // <SC::ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>: Clone,
    A: MachineAir<SC::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    JC: RecursiveJaggedConfig<
        F = C::F,
        EF = C::EF,
        Circuit = C,
        Commitment = SC::DigestVariable,
        Challenger = SC::FriChallengerVariable,
        BatchPcsProof = RecursiveBasefoldProof<RecursiveBasefoldConfigImpl<C, SC>>,
        BatchPcsVerifier = RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
    >,
{
    /// Verify a batch of deferred proofs.
    ///
    /// Each deferred proof is a recursive proof representing some computation. Namely, every such
    /// proof represents a recursively verified program.
    /// verifier:
    /// - Asserts that each of these proofs is valid as a `compress` proof.
    /// - Asserts that each of these proofs is complete by checking the `is_complete` flag in the
    ///   proof's public values.
    /// - Aggregates the proof information into the accumulated deferred digest.
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &RecursiveShardVerifier<A, SC, C, JC>,
        input: SP1DeferredWitnessVariable<C, SC, JC>,
        // value_assertions: bool,
    ) {
        let SP1DeferredWitnessVariable {
            vks_and_proofs,
            // vk_merkle_data,
            start_reconstruct_deferred_digest,
            sp1_vk_digest,
            committed_value_digest,
            deferred_proofs_digest,
            end_pc,
            end_shard,
            end_execution_shard,
            init_addr_word,
            finalize_addr_word,
            is_complete,
        } = input;

        // First, verify the merkle tree proofs.
        // let vk_root = vk_merkle_data.root;
        // let values = vks_and_proofs.iter().map(|(vk, _)| vk.hash(builder)).collect::<Vec<_>>();
        // SP1MerkleProofVerifier::verify(builder, values, vk_merkle_data, value_assertions);

        let mut deferred_public_values_stream: Vec<Felt<C::F>> =
            (0..RECURSIVE_PROOF_NUM_PV_ELTS).map(|_| builder.uninit()).collect();
        let deferred_public_values: &mut RecursionPublicValues<_> =
            deferred_public_values_stream.as_mut_slice().borrow_mut();

        // Initialize the start of deferred digests.
        deferred_public_values.start_reconstruct_deferred_digest =
            start_reconstruct_deferred_digest;

        // Initialize the consistency check variable.
        let mut reconstruct_deferred_digest: [Felt<C::F>; POSEIDON_NUM_WORDS] =
            start_reconstruct_deferred_digest;

        for (vk, shard_proof) in vks_and_proofs {
            // Prepare a challenger.
            let mut challenger = SC::challenger_variable(builder);
            // Observe the vk and start pc.
            if let Some(commit) = vk.preprocessed_commit {
                challenger.observe(builder, commit);
            }
            challenger.observe(builder, vk.pc_start);
            challenger.observe_slice(builder, vk.initial_global_cumulative_sum.0.x.0);
            challenger.observe_slice(builder, vk.initial_global_cumulative_sum.0.y.0);
            // Observe the padding.
            let zero: Felt<_> = builder.eval(C::F::zero());
            challenger.observe(builder, zero);

            machine.verify_shard(builder, &vk, &shard_proof, &mut challenger);

            // Get the current public values.
            let current_public_values: &RecursionPublicValues<Felt<C::F>> =
                shard_proof.public_values.as_slice().borrow();
            // Assert that the `vk_root` is the same as the witnessed one.
            // for (elem, expected) in current_public_values.vk_root.iter().zip(vk_root.iter()) {
            //     builder.assert_felt_eq(*elem, *expected);
            // }
            // Assert that the public values are valid.
            // assert_recursion_public_values_valid::<C, SC>(builder, current_public_values);

            // Assert that the proof is complete.
            // builder.assert_felt_eq(current_public_values.is_complete, C::F::one());

            // Update deferred proof digest
            // poseidon2( current_digest[..8] || pv.sp1_vk_digest[..8] ||
            // pv.committed_value_digest[..16] )
            let mut inputs: [Felt<C::F>; 48] = array::from_fn(|_| builder.uninit());
            inputs[0..DIGEST_SIZE].copy_from_slice(&reconstruct_deferred_digest);

            inputs[DIGEST_SIZE..DIGEST_SIZE + DIGEST_SIZE]
                .copy_from_slice(&current_public_values.sp1_vk_digest);

            for j in 0..PV_DIGEST_NUM_WORDS {
                for k in 0..4 {
                    let element = current_public_values.committed_value_digest[j][k];
                    inputs[j * 4 + k + 16] = element;
                }
            }
            reconstruct_deferred_digest = SC::hash(builder, &inputs);
        }

        // Set the public values.

        // Set initial_pc, end_pc, initial_shard, and end_shard to be the hitned values.
        deferred_public_values.start_pc = end_pc;
        deferred_public_values.next_pc = end_pc;
        deferred_public_values.start_shard = end_shard;
        deferred_public_values.next_shard = end_shard;
        deferred_public_values.start_execution_shard = end_execution_shard;
        deferred_public_values.next_execution_shard = end_execution_shard;
        // Set the init and finalize address words to be the hinted values.
        deferred_public_values.previous_init_addr_word = init_addr_word;
        deferred_public_values.last_init_addr_word = init_addr_word;
        deferred_public_values.previous_finalize_addr_word = finalize_addr_word;
        deferred_public_values.last_finalize_addr_word = finalize_addr_word;

        // Set the sp1_vk_digest to be the hitned value.
        deferred_public_values.sp1_vk_digest = sp1_vk_digest;

        // Set the committed value digest to be the hitned value.
        deferred_public_values.committed_value_digest = committed_value_digest;
        // Set the deferred proof digest to be the hitned value.
        deferred_public_values.deferred_proofs_digest = deferred_proofs_digest;

        // Set the exit code to be zero for now.
        deferred_public_values.exit_code = builder.eval(C::F::zero());
        // Assign the deferred proof digests.
        deferred_public_values.end_reconstruct_deferred_digest = reconstruct_deferred_digest;
        // Set the is_complete flag.
        deferred_public_values.is_complete = is_complete;
        // Set the cumulative sum to zero.
        deferred_public_values.global_cumulative_sum =
            SepticDigest(SepticCurve::convert(SepticDigest::<C::F>::zero().0, |value| {
                builder.eval(value)
            }));
        // Set the vk root from the witness.
        // deferred_public_values.vk_root = vk_root;
        deferred_public_values.vk_root = [builder.eval(C::F::zero()); DIGEST_SIZE];
        // Set the digest according to the previous values.
        deferred_public_values.digest =
            recursion_public_values_digest::<C, SC>(builder, deferred_public_values);

        assert_complete(builder, deferred_public_values, is_complete);
        builder.assert_felt_eq(is_complete, C::F::zero());

        SC::commit_recursion_public_values(builder, *deferred_public_values);
    }
}

// impl SP1DeferredWitnessValues<BabyBearPoseidon2> {
//     pub fn dummy<A: MachineAir<BabyBear>>(
//         machine: &MachineVerifier<BabyBearPoseidon2, A>,
//         shape: &SP1DeferredShape,
//     ) -> Self {
//         let inner_witness =
//             SP1CompressWitnessValues::<BabyBearPoseidon2>::dummy(machine, &shape.inner);
//         let vks_and_proofs = inner_witness.vks_and_proofs;

//         let vk_merkle_data = SP1MerkleProofWitnessValues::dummy(vks_and_proofs.len(),
// shape.height);

//         Self {
//             vks_and_proofs,
//             vk_merkle_data,
//             is_complete: true,
//             sp1_vk_digest: [BabyBear::zero(); DIGEST_SIZE],
//             start_reconstruct_deferred_digest: [BabyBear::zero(); POSEIDON_NUM_WORDS],
//             committed_value_digest: [Word::default(); PV_DIGEST_NUM_WORDS],
//             deferred_proofs_digest: [BabyBear::zero(); POSEIDON_NUM_WORDS],
//             end_pc: BabyBear::zero(),
//             end_shard: BabyBear::zero(),
//             end_execution_shard: BabyBear::zero(),
//             init_addr_word: Word([BabyBear::zero(); 2]),
//             finalize_addr_word: Word([BabyBear::zero(); 2]),
//         }
//     }
// }

impl SP1DeferredShape {
    pub const fn new(inner: SP1CompressShape, height: usize) -> Self {
        Self { inner, height }
    }
}
