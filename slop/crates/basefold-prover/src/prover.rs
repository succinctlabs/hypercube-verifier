use slop_algebra::{
    extension::{BinomiallyExtendable, HasTwoAdicBionmialExtension},
    PrimeField31,
};
use slop_baby_bear::baby_bear_poseidon2::BabyBearDegree4Duplex;
use slop_bn254::{Bn254Fr, Poseidon2Bn254GlobalConfig, BNGC, OUTER_DIGEST_SIZE};
use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex};
use std::{fmt::Debug, marker::PhantomData, sync::Arc};

use derive_where::derive_where;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use slop_algebra::{ExtensionField, Field, TwoAdicField};
use slop_alloc::{Backend, CpuBackend};
use slop_baby_bear::BabyBear;
use slop_basefold::{BasefoldProof, BasefoldVerifier, RsCodeWord};
use slop_challenger::{CanSampleBits, FieldChallenger, IopCtx};
use slop_commit::{Message, Rounds};
use slop_dft::p3::Radix2DitParallel;
use slop_futures::OwnedBorrow;
use slop_merkle_tree::{
    ComputeTcsOpenings, FieldMerkleTreeProver, MerkleTreeOpeningAndProof,
    Poseidon2BabyBear16Prover, Poseidon2KoalaBear16Prover, TensorCsProver,
};
use slop_multilinear::{
    Evaluations, Mle, MleBaseBackend, MleEvaluationBackend, MleFixedAtZeroBackend,
    MultilinearPcsBatchProver, MultilinearPcsBatchVerifier, Point,
};
use slop_tensor::Tensor;
use thiserror::Error;

use crate::{
    BasefoldBatcher, CpuDftEncoder, FriCpuProver, FriIoppProver, GrindingPowProver, PowProver,
    ReedSolomonEncoder,
};

/// The components required for a Basefold prover.
pub trait BasefoldProverComponents<GC: IopCtx<F: TwoAdicField>>:
    Clone + Send + Sync + 'static + Debug
{
    type A: Backend
        + MleBaseBackend<GC::EF>
        + MleFixedAtZeroBackend<GC::EF, GC::EF>
        + MleEvaluationBackend<GC::F, GC::EF>;

    /// The encoder for encoding the Mle guts into codewords.
    type Encoder: ReedSolomonEncoder<GC::F, Self::A> + Clone + Debug + Send + Sync + 'static;
    /// The prover for the FRI proximity test.
    type FriProver: FriIoppProver<
            GC,
            Self::Encoder,
            Self::A,
            Encoder = Self::Encoder,
            TcsProver = Self::TcsProver,
        > + Send
        + Debug
        + Sync
        + 'static;
    /// The TCS prover for committing to the encoded messages.
    type TcsProver: TensorCsProver<GC, Self::A>
        + ComputeTcsOpenings<GC, Self::A>
        + Debug
        + 'static
        + Send
        + Sync;
    /// The prover for the proof-of-work grinding phase.
    type PowProver: PowProver<GC::Challenger> + Debug + Send + Sync + 'static;
}

pub trait DefaultBasefoldProver<GC: IopCtx<F: TwoAdicField>>:
    BasefoldProverComponents<GC> + Sized
{
    fn default_prover(verifier: &BasefoldVerifier<GC>) -> BasefoldProver<GC, Self>;
}

#[derive_where(Debug, Clone; <C::TcsProver as TensorCsProver<GC,C::A>>::ProverData: Debug + Clone)]
#[derive_where(
    Serialize, Deserialize;
    <C::TcsProver as TensorCsProver<GC, C::A>>::ProverData,
    RsCodeWord<GC::F, C::A>
)]
pub struct BasefoldProverData<GC: IopCtx<F: TwoAdicField>, C: BasefoldProverComponents<GC>> {
    pub tcs_prover_data: <C::TcsProver as TensorCsProver<GC, C::A>>::ProverData,
    pub encoded_messages: Message<RsCodeWord<GC::F, C::A>>,
}

#[derive(Debug, Error)]
pub enum BasefoldProverError<TcsError, EncoderError, FriError> {
    #[error("Commit error: {0}")]
    TcsCommitError(TcsError),
    #[error("Encoder error: {0}")]
    EncoderError(EncoderError),
    #[error("Commit phase error: {0}")]
    #[allow(clippy::type_complexity)]
    CommitPhaseError(FriError),
}

pub type BaseFoldConfigProverError<GC, C> = BasefoldProverError<
    <<C as BasefoldProverComponents<GC>>::TcsProver as TensorCsProver<
        GC,
        <C as BasefoldProverComponents<GC>>::A,
    >>::ProverError,
    <<C as BasefoldProverComponents<GC>>::Encoder as ReedSolomonEncoder<
        <GC as IopCtx>::F,
        <C as BasefoldProverComponents<GC>>::A,
    >>::Error,
    <<C as BasefoldProverComponents<GC>>::FriProver as FriIoppProver<
        GC,
        <C as BasefoldProverComponents<GC>>::Encoder,
        <C as BasefoldProverComponents<GC>>::A,
    >>::FriProverError,
>;

/// A prover for the BaseFold protocol.
///
/// The [BasefoldProver] struct implements the interactive parts of the Basefold PCS while
/// abstracting some of the key parts.
#[derive(Debug, Clone, Copy, Default)]
pub struct BasefoldProver<GC: IopCtx<F: TwoAdicField>, C: BasefoldProverComponents<GC>> {
    pub encoder: C::Encoder,
    pub fri_prover: C::FriProver,
    pub tcs_prover: C::TcsProver,
    pub pow_prover: C::PowProver,
}

impl<GC: IopCtx<F: TwoAdicField>, C: BasefoldProverComponents<GC>> MultilinearPcsBatchProver<GC>
    for BasefoldProver<GC, C>
{
    type Verifier = BasefoldVerifier<GC>;
    type ProverData = BasefoldProverData<GC, C>;
    type A = C::A;
    type ProverError = BaseFoldConfigProverError<GC, C>;

    async fn commit_multilinears(
        &self,
        mles: Message<Mle<GC::F, Self::A>>,
    ) -> Result<(GC::Digest, Self::ProverData), Self::ProverError> {
        self.commit_mles(mles).await
    }

    async fn prove_trusted_evaluations(
        &self,
        eval_point: Point<GC::EF>,
        mle_rounds: Rounds<Message<Mle<GC::F, Self::A>>>,
        evaluation_claims: Rounds<Evaluations<GC::EF, Self::A>>,
        prover_data: Rounds<Self::ProverData>,
        challenger: &mut GC::Challenger,
    ) -> Result<<Self::Verifier as MultilinearPcsBatchVerifier<GC>>::Proof, Self::ProverError> {
        self.prove_trusted_mle_evaluations(
            eval_point,
            mle_rounds,
            evaluation_claims,
            prover_data,
            challenger,
        )
        .await
    }
}

impl<GC: IopCtx<F: TwoAdicField>, C: BasefoldProverComponents<GC>> BasefoldProver<GC, C> {
    #[inline]
    pub const fn from_parts(
        encoder: C::Encoder,
        fri_prover: C::FriProver,
        tcs_prover: C::TcsProver,
        pow_prover: C::PowProver,
    ) -> Self {
        Self { encoder, fri_prover, tcs_prover, pow_prover }
    }

    #[inline]
    pub fn new(verifier: &BasefoldVerifier<GC>) -> Self
    where
        C: DefaultBasefoldProver<GC>,
    {
        C::default_prover(verifier)
    }

    #[inline]
    #[allow(clippy::type_complexity)]
    pub async fn commit_mles<M>(
        &self,
        mles: Message<M>,
    ) -> Result<(GC::Digest, BasefoldProverData<GC, C>), BaseFoldConfigProverError<GC, C>>
    where
        M: OwnedBorrow<Mle<GC::F, C::A>>,
    {
        // Encode the guts of the mle via Reed-Solomon encoding.

        let encoded_messages = self.encoder.encode_batch(mles.clone()).await.unwrap();

        // Commit to the encoded messages.
        let (commitment, tcs_prover_data) = self
            .tcs_prover
            .commit_tensors(encoded_messages.clone())
            .await
            .map_err(BaseFoldConfigProverError::<GC, C>::TcsCommitError)?;

        Ok((commitment, BasefoldProverData { encoded_messages, tcs_prover_data }))
    }

    #[inline]
    pub async fn prove_trusted_mle_evaluations(
        &self,
        mut eval_point: Point<GC::EF>,
        mle_rounds: Rounds<Message<Mle<GC::F, C::A>>>,
        evaluation_claims: Rounds<Evaluations<GC::EF, C::A>>,
        prover_data: Rounds<BasefoldProverData<GC, C>>,
        challenger: &mut GC::Challenger,
    ) -> Result<BasefoldProof<GC>, BaseFoldConfigProverError<GC, C>> {
        // Get all the mles from all rounds in order.
        let mles = mle_rounds
            .iter()
            .flat_map(|round| round.clone().into_iter())
            .collect::<Message<Mle<_, _>>>();

        let encoded_messages = prover_data
            .iter()
            .flat_map(|data| data.encoded_messages.iter().cloned())
            .collect::<Message<RsCodeWord<_, _>>>();

        let evaluation_claims = evaluation_claims.into_iter().flatten().collect::<Vec<_>>();

        // Sample a batching challenge and batch the mles and codewords.
        let batching_challenge: GC::EF = challenger.sample_ext_element();
        // Batch the mles and codewords.
        let (mle_batch, codeword_batch, batched_eval_claim) = self
            .fri_prover
            .batch(batching_challenge, mles, encoded_messages, evaluation_claims, &self.encoder)
            .await;
        // From this point on, run the BaseFold protocol on the random linear combination codeword,
        // the random linear combination multilinear, and the random linear combination of the
        // evaluation claims.
        let mut current_mle = mle_batch;
        let mut current_codeword = codeword_batch;
        // Initialize the vecs that go into a BaseFoldProof.
        let log_len = current_mle.num_variables();
        let mut univariate_messages: Vec<[GC::EF; 2]> = vec![];
        let mut fri_commitments = vec![];
        let mut commit_phase_data = vec![];
        let mut current_batched_eval_claim = batched_eval_claim;
        let mut commit_phase_values = vec![];

        assert_eq!(
            current_mle.num_variables(),
            eval_point.dimension() as u32,
            "eval point dimension mismatch"
        );
        for _ in 0..eval_point.dimension() {
            // Compute claims for `g(X_0, X_1, ..., X_{d-1}, 0)` and `g(X_0, X_1, ..., X_{d-1}, 1)`.
            let last_coord = eval_point.remove_last_coordinate();
            let zero_values = current_mle.fixed_at_zero(&eval_point).await;
            let zero_val = zero_values[0];
            let one_val = (current_batched_eval_claim - zero_val) / last_coord + zero_val;
            let uni_poly = [zero_val, one_val];
            univariate_messages.push(uni_poly);

            uni_poly.iter().for_each(|elem| challenger.observe_ext_element(*elem));

            // Perform a single round of the FRI commit phase, returning the commitment, folded
            // codeword, and folding parameter.
            let (beta, folded_mle, folded_codeword, commitment, leaves, prover_data) = self
                .fri_prover
                .commit_phase_round(
                    current_mle,
                    current_codeword,
                    &self.encoder,
                    &self.tcs_prover,
                    challenger,
                )
                .await
                .map_err(BasefoldProverError::CommitPhaseError)?;

            fri_commitments.push(commitment);
            commit_phase_data.push(prover_data);
            commit_phase_values.push(leaves);

            current_mle = folded_mle;
            current_codeword = folded_codeword;
            current_batched_eval_claim = zero_val + beta * one_val;
        }

        let final_poly = self.fri_prover.final_poly(current_codeword).await;
        challenger.observe_ext_element(final_poly);

        let fri_config = self.encoder.config();
        let pow_bits = fri_config.proof_of_work_bits;
        let pow_witness = self.pow_prover.grind(challenger, pow_bits).await;
        // FRI Query Phase.
        let query_indices: Vec<usize> = (0..fri_config.num_queries)
            .map(|_| challenger.sample_bits(log_len as usize + fri_config.log_blowup()))
            .collect();

        // Open the original polynomials at the query indices.
        let mut component_polynomials_query_openings_and_proofs = vec![];
        for prover_data in prover_data {
            let BasefoldProverData { encoded_messages, tcs_prover_data } = prover_data;
            let values =
                self.tcs_prover.compute_openings_at_indices(encoded_messages, &query_indices).await;
            let proof = self
                .tcs_prover
                .prove_openings_at_indices(tcs_prover_data, &query_indices)
                .await
                .map_err(BaseFoldConfigProverError::<GC, C>::TcsCommitError)
                .unwrap();
            let opening = MerkleTreeOpeningAndProof::<GC> { values, proof };
            component_polynomials_query_openings_and_proofs.push(opening);
        }

        // Provide openings for the FRI query phase.
        let mut query_phase_openings_and_proofs = vec![];
        let mut indices = query_indices;
        for (leaves, data) in commit_phase_values.into_iter().zip_eq(commit_phase_data) {
            for index in indices.iter_mut() {
                *index >>= 1;
            }
            let leaves: Message<Tensor<GC::F, C::A>> = leaves.into();
            let values = self.tcs_prover.compute_openings_at_indices(leaves, &indices).await;

            let proof = self
                .tcs_prover
                .prove_openings_at_indices(data, &indices)
                .await
                .map_err(BaseFoldConfigProverError::<GC, C>::TcsCommitError)?;
            let opening = MerkleTreeOpeningAndProof { values, proof };
            query_phase_openings_and_proofs.push(opening);
        }

        Ok(BasefoldProof {
            univariate_messages,
            fri_commitments,
            component_polynomials_query_openings_and_proofs,
            query_phase_openings_and_proofs,
            final_poly,
            pow_witness,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, PartialOrd, Eq, Ord, Serialize, Deserialize)]
pub struct Poseidon2BabyBear16BasefoldCpuProverComponents;

impl BasefoldProverComponents<BabyBearDegree4Duplex>
    for Poseidon2BabyBear16BasefoldCpuProverComponents
{
    type A = CpuBackend;
    type Encoder = CpuDftEncoder<BabyBear, Radix2DitParallel>;
    type FriProver = FriCpuProver<Self::Encoder, Self::TcsProver>;
    type TcsProver = FieldMerkleTreeProver<
        <BabyBear as Field>::Packing,
        <BabyBear as Field>::Packing,
        BabyBearDegree4Duplex,
        8,
    >;
    type PowProver = GrindingPowProver;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, PartialOrd, Eq, Ord, Serialize, Deserialize)]
pub struct Poseidon2KoalaBear16BasefoldCpuProverComponents;

impl BasefoldProverComponents<KoalaBearDegree4Duplex>
    for Poseidon2KoalaBear16BasefoldCpuProverComponents
{
    type A = CpuBackend;
    type Encoder = CpuDftEncoder<KoalaBear, Radix2DitParallel>;
    type FriProver = FriCpuProver<Self::Encoder, Self::TcsProver>;
    type TcsProver = FieldMerkleTreeProver<
        <KoalaBear as Field>::Packing,
        <KoalaBear as Field>::Packing,
        KoalaBearDegree4Duplex,
        8,
    >;
    type PowProver = GrindingPowProver;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, PartialOrd, Eq, Ord, Serialize, Deserialize)]
pub struct Poseidon2Bn254BasefoldCpuProverComponents<F>(PhantomData<F>);

impl<
        F: PrimeField31 + BinomiallyExtendable<4> + TwoAdicField,
        EF: ExtensionField<F> + TwoAdicField,
    > BasefoldProverComponents<Poseidon2Bn254GlobalConfig<F, EF>>
    for Poseidon2Bn254BasefoldCpuProverComponents<F>
{
    type A = CpuBackend;
    type Encoder = CpuDftEncoder<F, Radix2DitParallel>;
    type FriProver = FriCpuProver<Self::Encoder, Self::TcsProver>;
    type TcsProver =
        FieldMerkleTreeProver<F, Bn254Fr, Poseidon2Bn254GlobalConfig<F, EF>, OUTER_DIGEST_SIZE>;
    type PowProver = GrindingPowProver;
}

impl DefaultBasefoldProver<BabyBearDegree4Duplex>
    for Poseidon2BabyBear16BasefoldCpuProverComponents
{
    fn default_prover(
        verifier: &BasefoldVerifier<BabyBearDegree4Duplex>,
    ) -> BasefoldProver<BabyBearDegree4Duplex, Self> {
        let encoder =
            CpuDftEncoder { config: verifier.fri_config, dft: Arc::new(Radix2DitParallel) };
        let fri_prover = FriCpuProver::<
            CpuDftEncoder<BabyBear, Radix2DitParallel>,
            FieldMerkleTreeProver<
                <BabyBear as Field>::Packing,
                <BabyBear as Field>::Packing,
                BabyBearDegree4Duplex,
                8,
            >,
        >(PhantomData);

        let tcs_prover = Poseidon2BabyBear16Prover::default();
        let pow_prover = GrindingPowProver;
        BasefoldProver { encoder, fri_prover, tcs_prover, pow_prover }
    }
}

impl DefaultBasefoldProver<KoalaBearDegree4Duplex>
    for Poseidon2KoalaBear16BasefoldCpuProverComponents
{
    fn default_prover(
        verifier: &BasefoldVerifier<KoalaBearDegree4Duplex>,
    ) -> BasefoldProver<KoalaBearDegree4Duplex, Self> {
        let encoder =
            CpuDftEncoder { config: verifier.fri_config, dft: Arc::new(Radix2DitParallel) };
        let fri_prover = FriCpuProver::<
            CpuDftEncoder<KoalaBear, Radix2DitParallel>,
            FieldMerkleTreeProver<
                <KoalaBear as Field>::Packing,
                <KoalaBear as Field>::Packing,
                KoalaBearDegree4Duplex,
                8,
            >,
        >(PhantomData);

        let tcs_prover = Poseidon2KoalaBear16Prover::default();
        let pow_prover = GrindingPowProver;
        BasefoldProver { encoder, fri_prover, tcs_prover, pow_prover }
    }
}

impl<
        F: PrimeField31 + BinomiallyExtendable<4> + TwoAdicField + HasTwoAdicBionmialExtension<4>,
        EF: ExtensionField<F> + TwoAdicField,
    > DefaultBasefoldProver<Poseidon2Bn254GlobalConfig<F, EF>>
    for Poseidon2Bn254BasefoldCpuProverComponents<F>
{
    fn default_prover(
        verifier: &BasefoldVerifier<BNGC<F, EF>>,
    ) -> BasefoldProver<BNGC<F, EF>, Self> {
        let encoder =
            CpuDftEncoder { config: verifier.fri_config, dft: Arc::new(Radix2DitParallel) };
        let fri_prover = FriCpuProver::<
            CpuDftEncoder<F, Radix2DitParallel>,
            FieldMerkleTreeProver<F, Bn254Fr, BNGC<F, EF>, OUTER_DIGEST_SIZE>,
        >(PhantomData);

        let tcs_prover =
            FieldMerkleTreeProver::<F, Bn254Fr, BNGC<F, EF>, OUTER_DIGEST_SIZE>::default();
        let pow_prover = GrindingPowProver;
        BasefoldProver { encoder, fri_prover, tcs_prover, pow_prover }
    }
}

#[cfg(test)]
mod tests {
    use futures::prelude::*;
    use rand::thread_rng;
    use slop_basefold::BasefoldVerifier;
    use slop_challenger::CanObserve;
    use slop_multilinear::{MleEval, MultilinearPcsBatchVerifier};

    use super::*;

    #[tokio::test]
    async fn test_baby_bear_basefold_prover() {
        test_basefold_prover_backend::<
            BabyBearDegree4Duplex,
            Poseidon2BabyBear16BasefoldCpuProverComponents,
        >()
        .await;
    }

    #[tokio::test]
    async fn test_koala_bear_basefold_prover() {
        test_basefold_prover_backend::<
            KoalaBearDegree4Duplex,
            Poseidon2KoalaBear16BasefoldCpuProverComponents,
        >()
        .await;
    }

    async fn test_basefold_prover_backend<
        GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
        Prover: DefaultBasefoldProver<GC, A = CpuBackend>,
    >()
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        let num_variables = 16;
        let round_widths = [vec![16, 10, 14], vec![20, 78, 34], vec![10, 10]];
        let log_blowup = 1;

        let mut rng = thread_rng();
        let round_mles = round_widths
            .iter()
            .map(|widths| {
                widths
                    .iter()
                    .map(|&w| Mle::<GC::F>::rand(&mut rng, w, num_variables))
                    .collect::<Message<_>>()
            })
            .collect::<Rounds<_>>();

        let verifier = BasefoldVerifier::<GC>::new(log_blowup, round_widths.len());
        let prover = BasefoldProver::<GC, Prover>::new(&verifier);

        let mut challenger = GC::default_challenger();
        let mut commitments = vec![];
        let mut prover_data = Rounds::new();
        let mut eval_claims = Rounds::new();
        let point = Point::<GC::EF>::rand(&mut rng, num_variables);
        for mles in round_mles.iter() {
            let (commitment, data) = prover.commit_mles(mles.clone()).await.unwrap();
            challenger.observe(commitment);
            commitments.push(commitment);
            prover_data.push(data);
            let evaluations = stream::iter(mles.iter())
                .then(|mle| mle.eval_at(&point))
                .collect::<Evaluations<_>>()
                .await;
            eval_claims.push(evaluations);
        }

        let proof = prover
            .prove_trusted_mle_evaluations(
                point.clone(),
                round_mles,
                eval_claims.clone(),
                prover_data,
                &mut challenger,
            )
            .await
            .unwrap();

        let mut challenger = GC::default_challenger();
        for commitment in commitments.iter() {
            challenger.observe(*commitment);
        }

        let eval_claims = eval_claims
            .into_iter()
            .map(|round| round.into_iter().flat_map(|x| x.into_iter()).collect::<MleEval<_>>())
            .collect::<Vec<_>>();
        verifier
            .verify_trusted_evaluations(&commitments, point, &eval_claims, &proof, &mut challenger)
            .unwrap();
    }
}
