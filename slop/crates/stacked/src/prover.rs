use derive_where::derive_where;
use futures::prelude::*;
use slop_algebra::Field;
use slop_alloc::{HasBackend, ToHost};
use slop_challenger::IopCtx;
use slop_commit::{Message, Rounds};
use slop_multilinear::{
    Evaluations, Mle, MleBaseBackend, MleEval, MultilinearPcsBatchProver, MultilinearPcsProver,
    Point,
};
use std::fmt::Debug;
use thiserror::Error;

use crate::{InterleaveMultilinears, StackedPcsProof, StackedPcsVerifier};

#[derive(Debug, Clone)]
pub struct StackedPcsProver<P, S, GC> {
    pcs_prover: P,
    stacker: S,
    pub log_stacking_height: u32,
    _marker: std::marker::PhantomData<GC>,
}

pub trait ToMle<F: Field, A: MleBaseBackend<F>> {
    fn interleaved_mles(&self) -> Message<Mle<F, A>>;
}

#[derive_where(Debug, Clone; P::ProverData: Debug + Clone)]
#[derive_where(Serialize, Deserialize; P::ProverData, Mle<GC::F, P::A>)]
pub struct StackedPcsProverData<GC: IopCtx, P: MultilinearPcsBatchProver<GC>> {
    pcs_batch_data: P::ProverData,
    pub interleaved_mles: Message<Mle<GC::F, P::A>>,
}

impl<GC: IopCtx, P: MultilinearPcsBatchProver<GC>> ToMle<GC::F, P::A>
    for StackedPcsProverData<GC, P>
{
    fn interleaved_mles(&self) -> Message<Mle<GC::F, P::A>> {
        self.interleaved_mles.clone()
    }
}

#[derive(Error, Debug)]
pub enum StackedPcsProverError<E> {
    #[error("PCS prover error: {0}")]
    PcsProverError(E),
}

impl<GC, P, S> StackedPcsProver<P, S, GC>
where
    GC: IopCtx,
    P: MultilinearPcsBatchProver<GC>,
    S: InterleaveMultilinears<GC::F, P::A>,
{
    pub const fn new(pcs_prover: P, stacker: S, log_stacking_height: u32) -> Self {
        Self { pcs_prover, stacker, log_stacking_height, _marker: std::marker::PhantomData }
    }

    pub async fn round_batch_evaluations(
        &self,
        stacked_point: &Point<GC::EF, P::A>,
        prover_data: &StackedPcsProverData<GC, P>,
    ) -> Evaluations<GC::EF, P::A> {
        stream::iter(prover_data.interleaved_mles.iter())
            .then(|mle| mle.eval_at(stacked_point))
            .collect::<Evaluations<_, _>>()
            .await
    }

    pub async fn commit_multilinears(
        &self,
        multilinears: Message<Mle<GC::F, P::A>>,
    ) -> Result<
        (GC::Digest, StackedPcsProverData<GC, P>, usize),
        StackedPcsProverError<P::ProverError>,
    > {
        // To commit to the batch of padded Mles, the underlying PCS prover commits to the dense
        // representation of all of these Mles (i.e. a single "giga" Mle consisting of all the
        // entries of all the individual Mles),
        // padding the total area to the next multiple of the stacking height.
        let next_multiple = multilinears
            .iter()
            .map(|mle| mle.num_non_zero_entries() * mle.num_polynomials())
            .sum::<usize>()
            .next_multiple_of(1 << self.log_stacking_height)
            // Need to pad to at least one column.
            .max(1 << self.log_stacking_height);

        let num_added_vals = next_multiple
            - multilinears
                .iter()
                .map(|mle| mle.num_non_zero_entries() * mle.num_polynomials())
                .sum::<usize>();

        let interleaved_mles =
            self.stacker.interleave_multilinears(multilinears, self.log_stacking_height).await;
        let (commit, pcs_batch_data) = self
            .pcs_prover
            .commit_multilinears(interleaved_mles.clone())
            .await
            .map_err(StackedPcsProverError::PcsProverError)?;
        let prover_data = StackedPcsProverData { pcs_batch_data, interleaved_mles };

        Ok((commit, prover_data, num_added_vals))
    }
}

impl<GC: IopCtx, P: MultilinearPcsBatchProver<GC>> HasBackend for StackedPcsProverData<GC, P> {
    type Backend = P::A;

    fn backend(&self) -> &Self::Backend {
        self.interleaved_mles[0].backend()
    }
}
impl<GC: IopCtx, P: MultilinearPcsBatchProver<GC>, S: InterleaveMultilinears<GC::F, P::A>>
    MultilinearPcsProver<GC> for StackedPcsProver<P, S, GC>
{
    type Verifier = StackedPcsVerifier<GC, P::Verifier>;

    type ProverData = StackedPcsProverData<GC, P>;

    type A = P::A;

    type ProverError = StackedPcsProverError<P::ProverError>;

    async fn commit_multilinear(
        &self,
        mles: Message<Mle<<GC as IopCtx>::F, Self::A>>,
    ) -> Result<(<GC as IopCtx>::Digest, Self::ProverData, usize), Self::ProverError> {
        self.commit_multilinears(mles).await
    }

    async fn prove_trusted_evaluation(
        &self,
        eval_point: Point<<GC as IopCtx>::EF>,
        _evaluation_claim: <GC as IopCtx>::EF,
        prover_data: Rounds<Self::ProverData>,
        challenger: &mut <GC as IopCtx>::Challenger,
    ) -> Result<
        <Self::Verifier as slop_multilinear::MultilinearPcsVerifier<GC>>::Proof,
        Self::ProverError,
    > {
        let backend = prover_data.backend();
        let (_, stack_point) =
            eval_point.split_at(eval_point.dimension() - self.log_stacking_height as usize);
        let stack_point = stack_point.copy_into(backend);
        let batch_evaluations = stream::iter(prover_data.iter())
            .then(|data| self.round_batch_evaluations(&stack_point, data))
            .collect::<Rounds<_>>()
            .await;

        let mut host_batch_evaluations = Rounds::new();
        for round_evals in batch_evaluations.iter() {
            let mut host_round_evals = vec![];
            for eval in round_evals.iter() {
                let host_eval = eval.to_host().await.unwrap();
                host_round_evals.extend(host_eval);
            }
            let host_round_evals = Evaluations::new(vec![host_round_evals.into()]);
            host_batch_evaluations.push(host_round_evals);
        }
        let (pcs_prover_data, mle_rounds): (Rounds<_>, Rounds<_>) = prover_data
            .into_iter()
            .map(|data| (data.pcs_batch_data, data.interleaved_mles))
            .unzip();

        let (_, stack_point) =
            eval_point.split_at(eval_point.dimension() - self.log_stacking_height as usize);

        let pcs_proof = self
            .pcs_prover
            .prove_untrusted_evaluations(
                stack_point,
                mle_rounds,
                batch_evaluations,
                pcs_prover_data,
                challenger,
            )
            .await
            .map_err(StackedPcsProverError::PcsProverError)?;

        let host_batch_evaluations = host_batch_evaluations
            .into_iter()
            .map(|round| round.into_iter().flatten().collect::<MleEval<_>>())
            .collect::<Rounds<_>>();

        Ok(StackedPcsProof { pcs_proof, batch_evaluations: host_batch_evaluations })
    }
}
#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
    use slop_basefold::BasefoldVerifier;
    use slop_basefold_prover::{BasefoldProver, Poseidon2BabyBear16BasefoldCpuProverComponents};
    use slop_challenger::CanObserve;
    use slop_tensor::Tensor;

    use crate::{FixedRateInterleave, StackedPcsVerifier};

    use super::*;

    #[tokio::test]
    async fn test_stacked_prover_with_fixed_rate_interleave() {
        let log_stacking_height = 10;
        let batch_size = 10;

        type GC = BabyBearDegree4Duplex;
        type Prover = BasefoldProver<GC, Poseidon2BabyBear16BasefoldCpuProverComponents>;
        type EF = BinomialExtensionField<BabyBear, 4>;

        let round_widths_and_log_heights = [vec![(1 << 10, 10), (1 << 4, 11), (496, 11)]];

        let total_data_length = round_widths_and_log_heights
            .iter()
            .map(|dims| dims.iter().map(|&(w, log_h)| w << log_h).sum::<usize>())
            .sum::<usize>();
        let total_number_of_variables = total_data_length.next_power_of_two().ilog2();
        assert_eq!(1 << total_number_of_variables, total_data_length);
        let round_areas = round_widths_and_log_heights
            .iter()
            .map(|dims| {
                dims.iter()
                    .map(|&(w, log_h)| w << log_h)
                    .sum::<usize>()
                    .next_multiple_of(1 << log_stacking_height)
            })
            .collect::<Vec<_>>();

        let log_blowup = 1;

        let mut rng = thread_rng();
        let round_mles = round_widths_and_log_heights
            .iter()
            .map(|dims| {
                dims.iter()
                    .map(|&(w, log_h)| Mle::<BabyBear>::rand(&mut rng, w, log_h))
                    .collect::<Message<_>>()
            })
            .collect::<Rounds<_>>();

        let pcs_verifier =
            BasefoldVerifier::<GC>::new(log_blowup, round_widths_and_log_heights.len());
        let pcs_prover = Prover::new(&pcs_verifier);
        let stacker = FixedRateInterleave::new(batch_size);

        let verifier = StackedPcsVerifier::new(pcs_verifier, log_stacking_height);
        let prover = StackedPcsProver::new(pcs_prover, stacker, log_stacking_height);

        let mut challenger = GC::default_challenger();
        let mut commitments = vec![];
        let mut prover_data = Rounds::new();
        let mut batch_evaluations = Rounds::new();
        let point = Point::<EF>::rand(&mut rng, total_number_of_variables);

        let concat_mle: Vec<BabyBear> = round_mles
            .iter()
            .flat_map(|mles| mles.iter())
            .flat_map(|mle| mle.guts().transpose().as_slice().to_vec())
            .collect();

        let concat_mle =
            Mle::new(Tensor::from(concat_mle).reshape([1 << total_number_of_variables, 1]));

        let concat_eval_claim = concat_mle.eval_at(&point).await[0];

        let (batch_point, stack_point) =
            point.split_at(point.dimension() - log_stacking_height as usize);
        for mles in round_mles.iter() {
            let (commitment, data, _) = prover.commit_multilinears(mles.clone()).await.unwrap();
            challenger.observe(commitment);
            commitments.push(commitment);
            let evaluations = prover.round_batch_evaluations(&stack_point, &data).await;
            prover_data.push(data);
            batch_evaluations.push(evaluations);
        }

        // Interpolate the batch evaluations as a multilinear polynomial.
        let batch_evaluations_mle =
            batch_evaluations.iter().flatten().flatten().cloned().collect::<Mle<_>>();
        // Verify that the climed evaluations matched the interpolated evaluations.
        let eval_claim = batch_evaluations_mle.eval_at(&batch_point).await[0];

        assert_eq!(concat_eval_claim, eval_claim);

        let proof = prover
            .prove_trusted_evaluation(point.clone(), eval_claim, prover_data, &mut challenger)
            .await
            .unwrap();

        let mut challenger = GC::default_challenger();
        for commitment in commitments.iter() {
            challenger.observe(*commitment);
        }
        verifier
            .verify_trusted_evaluation(
                &commitments,
                &round_areas,
                &point,
                &proof,
                eval_claim,
                &mut challenger,
            )
            .unwrap();
    }
}
