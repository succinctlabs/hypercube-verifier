use std::{error::Error, future::Future, marker::PhantomData, sync::Arc};

use itertools::Itertools;

use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField, ExtensionField, Field, TwoAdicField};
use slop_alloc::{Backend, Buffer, CpuBackend};
use slop_basefold::RsCodeWord;
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_commit::Message;
pub use slop_fri::fold_even_odd as host_fold_even_odd;
use slop_futures::OwnedBorrow;
use slop_merkle_tree::TensorCsProver;
use slop_multilinear::{Mle, MleEval, Point};
use slop_tensor::Tensor;

use crate::ReedSolomonEncoder;

pub trait BasefoldBatcher<
    GC: IopCtx<F: TwoAdicField>,
    E: ReedSolomonEncoder<GC::F, A> + Clone,
    A: Backend = CpuBackend,
>: 'static + Send + Sync
{
    #[allow(clippy::type_complexity)]
    fn batch<M, Code>(
        &self,
        batching_challenge: GC::EF,
        mles: Message<M>,
        codewords: Message<Code>,
        evaluation_claims: Vec<MleEval<GC::EF, A>>,
        encoder: &E,
    ) -> impl Future<Output = (Mle<GC::EF, A>, RsCodeWord<GC::F, A>, GC::EF)> + Send
    where
        M: OwnedBorrow<Mle<GC::F, A>>,
        Code: OwnedBorrow<RsCodeWord<GC::F, A>>;
}

pub trait FixedAtZero<EF: Field, A: Backend> {
    fn fixed_at_zero(&self, mle: &Mle<EF, A>, point: &Point<EF, A>) -> EF;
}

pub trait FriIoppProver<
    GC: IopCtx<F: TwoAdicField>,
    E: ReedSolomonEncoder<GC::F, A> + Clone,
    A: Backend = CpuBackend,
>: BasefoldBatcher<GC, E, A>
{
    type FriProverError: Error;
    type TcsProver: TensorCsProver<GC, A>;
    type Encoder: ReedSolomonEncoder<GC::F, A>;
    #[allow(clippy::type_complexity)]
    fn commit_phase_round(
        &self,
        current_mle: Mle<GC::EF, A>,
        current_codeword: RsCodeWord<GC::F, A>,
        encoder: &Self::Encoder,
        tcs_prover: &Self::TcsProver,
        challenger: &mut GC::Challenger,
    ) -> impl Future<
        Output = Result<
            (
                GC::EF,
                Mle<GC::EF, A>,
                RsCodeWord<GC::F, A>,
                GC::Digest,
                Arc<Tensor<GC::F, A>>,
                <Self::TcsProver as TensorCsProver<GC, A>>::ProverData,
            ),
            Self::FriProverError,
        >,
    > + Send;

    fn final_poly(
        &self,
        final_codeword: RsCodeWord<GC::F, A>,
    ) -> impl Future<Output = GC::EF> + Send;
}

pub struct MleBatch<F: TwoAdicField, EF: ExtensionField<F>, A: Backend = CpuBackend> {
    pub batched_poly: Mle<F, A>,
    _marker: PhantomData<EF>,
}

#[derive(
    Debug, Clone, Default, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct FriCpuProver<E, P>(pub PhantomData<(E, P)>);

impl<
        GC: IopCtx<F: TwoAdicField>,
        E: ReedSolomonEncoder<GC::F, CpuBackend> + Clone,
        P: TensorCsProver<GC, CpuBackend>,
    > BasefoldBatcher<GC, E, CpuBackend> for FriCpuProver<E, P>
{
    async fn batch<M, Code>(
        &self,
        batching_challenge: GC::EF,
        mles: Message<M>,
        _codewords: Message<Code>,
        evaluation_claims: Vec<MleEval<GC::EF, CpuBackend>>,
        encoder: &E,
    ) -> (Mle<GC::EF, CpuBackend>, RsCodeWord<GC::F, CpuBackend>, GC::EF)
    where
        M: OwnedBorrow<Mle<GC::F>>,
        Code: OwnedBorrow<RsCodeWord<GC::F>>,
    {
        let encoder = encoder.clone();
        let num_variables = mles.first().unwrap().as_ref().borrow().num_variables() as usize;

        let (tx, rx) = tokio::sync::oneshot::channel();

        slop_futures::rayon::spawn(move || {
            // Compute all the batch challenge powers.
            let total_num_polynomials =
                mles.iter().map(|mle| mle.borrow().num_polynomials()).sum::<usize>();
            let mut batch_challenge_powers =
                batching_challenge.powers().take(total_num_polynomials).collect::<Vec<_>>();

            // Compute the random linear combination of the MLEs of the columns of the matrices
            let num_variables = mles.first().unwrap().as_ref().borrow().num_variables() as usize;
            let mut batch_mle = Mle::from(vec![GC::EF::zero(); 1 << num_variables]);
            for mle in mles.iter() {
                let mle: &Mle<_, _> = mle.as_ref().borrow();
                let batch_size = mle.num_polynomials();
                let mut powers = batch_challenge_powers;
                batch_challenge_powers = powers.split_off(batch_size);
                // Batch the mles as an inner product.
                batch_mle
                    .guts_mut()
                    .as_mut_slice()
                    .iter_mut()
                    .zip_eq(mle.hypercube_iter())
                    .for_each(|(batch, row)| {
                        let batch_row =
                            powers.iter().zip_eq(row).map(|(a, b)| *a * *b).sum::<GC::EF>();
                        *batch += batch_row;
                    });
            }

            let batched_eval_claim = evaluation_claims
                .iter()
                .flat_map(|batch_claims| unsafe {
                    batch_claims.evaluations().storage.copy_into_host_vec()
                })
                .zip(batching_challenge.powers())
                .map(|(eval, batch_power)| eval * batch_power)
                .sum::<GC::EF>();
            tx.send((batch_mle, batched_eval_claim)).unwrap();
        });

        let (batch_mle, batched_eval_claim) = rx.await.unwrap();

        let batch_mle_f = Buffer::from(batch_mle.clone().into_guts().storage.as_slice().to_vec())
            .flatten_to_base::<GC::F>();
        let batch_mle_f = Tensor::from(batch_mle_f).reshape([1 << num_variables, GC::EF::D]);
        let batch_codeword =
            encoder.encode_batch(Message::from(Mle::new(batch_mle_f))).await.unwrap();
        let batch_codeword = (*batch_codeword[0]).clone();

        (batch_mle, batch_codeword, batched_eval_claim)
    }
}

impl<
        GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
        E: ReedSolomonEncoder<GC::F, CpuBackend> + Clone,
        P: TensorCsProver<GC, CpuBackend> + Send + Sync + 'static,
    > FriIoppProver<GC, E, CpuBackend> for FriCpuProver<E, P>
{
    type FriProverError = P::ProverError;
    type TcsProver = P;
    type Encoder = E;
    async fn commit_phase_round(
        &self,
        current_mle: Mle<GC::EF, CpuBackend>,
        current_codeword: RsCodeWord<GC::F, CpuBackend>,
        _encoder: &Self::Encoder,
        tcs_prover: &Self::TcsProver,
        challenger: &mut GC::Challenger,
    ) -> Result<
        (GC::EF, Mle<GC::EF>, RsCodeWord<GC::F>, GC::Digest, Arc<Tensor<GC::F>>, P::ProverData),
        P::ProverError,
    > {
        // Perform a single round of the FRI commit phase, returning the commitment, folded
        // codeword, and folding parameter.
        let original_sizes = current_codeword.data.sizes().to_vec();
        // On CPU, the current codeword is in row-major form, which means that in order to put
        // even and odd entries together all we need to do is rehsape it to multiply the number of
        // columns by 2 and divide the number of rows by 2.
        let leaves = Arc::new(
            current_codeword.data.clone().reshape([original_sizes[0] / 2, 2 * original_sizes[1]]),
        );
        let (commit, prover_data) =
            tcs_prover.commit_tensors(Message::<Tensor<_, _>>::from(leaves.clone())).await?;
        // Observe the commitment.
        challenger.observe(commit);

        let beta: GC::EF = challenger.sample_ext_element();

        // To get the original codeword back, we need to reshape it to its original size.
        let current_codeword_vec =
            current_codeword.data.into_buffer().into_extension::<GC::EF>().into_vec();
        let folded_codeword_vec = host_fold_even_odd(current_codeword_vec, beta);
        let folded_codeword_storage = Buffer::from(folded_codeword_vec).flatten_to_base::<GC::F>();
        let mut new_size = original_sizes;
        new_size[0] /= 2;
        let folded_code_word_data = Tensor::from(folded_codeword_storage).reshape(new_size);
        let folded_codeword = RsCodeWord::new(folded_code_word_data);

        // Fold the mle.
        let folded_mle = current_mle.fold(beta).await;

        Ok((beta, folded_mle, folded_codeword, commit, leaves, prover_data))
    }

    async fn final_poly(&self, final_codeword: RsCodeWord<GC::F, CpuBackend>) -> GC::EF {
        GC::EF::from_base_slice(&final_codeword.data.storage.as_slice()[0..GC::EF::D])
    }
}
