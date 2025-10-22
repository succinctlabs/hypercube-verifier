use std::{future::Future, marker::PhantomData};

use slop_algebra::{AbstractField, Field};
use slop_alloc::{Backend, CpuBackend};
use slop_commit::Message;
use slop_multilinear::Mle;
use slop_tensor::Tensor;
use tokio::sync::oneshot;

use crate::InterleaveMultilinears;

pub struct FixedRateInterleave<F, A = CpuBackend> {
    pub batch_size: usize,
    _marker: PhantomData<(F, A)>,
}

impl<F, A> FixedRateInterleave<F, A> {
    #[inline]
    pub const fn new(batch_size: usize) -> Self {
        Self { batch_size, _marker: PhantomData }
    }
}

pub trait FixedRateInterleaveBackend<F: AbstractField>: Backend {
    fn interleave_multilinears_with_fixed_rate(
        stacker: &FixedRateInterleave<F, Self>,
        multilinears: Message<Mle<F, Self>>,
        log_stacking_height: u32,
    ) -> impl Future<Output = Message<Mle<F, Self>>> + Send;
}

impl<F, A> InterleaveMultilinears<F, A> for FixedRateInterleave<F, A>
where
    F: Field,
    A: FixedRateInterleaveBackend<F>,
{
    fn interleave_multilinears(
        &self,
        multilinears: Message<Mle<F, A>>,
        log_stacking_height: u32,
    ) -> impl Future<Output = Message<Mle<F, A>>> + Send {
        A::interleave_multilinears_with_fixed_rate(self, multilinears, log_stacking_height)
    }
}

impl<F> FixedRateInterleaveBackend<F> for CpuBackend
where
    F: Field,
{
    async fn interleave_multilinears_with_fixed_rate(
        stacker: &FixedRateInterleave<F, Self>,
        multilinears: Message<Mle<F>>,
        log_stacking_height: u32,
    ) -> Message<Mle<F>> {
        let (tx, rx) = oneshot::channel();
        let multilinears = multilinears;
        let batch_size = stacker.batch_size;
        slop_futures::rayon::spawn(move || {
            let mut batch_multilinears = vec![];

            let mut overflow_buffer = Vec::with_capacity(1 << log_stacking_height);
            for mle in multilinears {
                let mut data = mle.guts().transpose().into_buffer().into_vec();
                let mut needed_length = (batch_size << log_stacking_height) - overflow_buffer.len();
                while data.len() > needed_length {
                    let mut elements = Vec::with_capacity(batch_size << log_stacking_height);
                    elements.append(&mut overflow_buffer);
                    let remaining = data.split_off(needed_length);
                    elements.append(&mut data);
                    data = remaining;

                    elements.append(&mut overflow_buffer);
                    assert_eq!(elements.len(), batch_size << log_stacking_height);
                    let guts = Tensor::from(elements)
                        .reshape([batch_size, 1 << log_stacking_height])
                        .transpose();
                    let mle = Mle::new(guts);
                    batch_multilinears.push(mle);
                    needed_length = batch_size << log_stacking_height;
                }
                // Insert the remaining elements into the overflow buffer
                overflow_buffer.append(&mut data);
            }
            // Make an mle from the overflow buffer, buf first padding it with zeros to get to the
            // next multiple of 2^{log_stacking_height}.
            let new_overflow_len = overflow_buffer.len().next_multiple_of(1 << log_stacking_height);
            overflow_buffer.resize(new_overflow_len, F::zero());
            let overflow_batch_size = overflow_buffer.len() / (1 << log_stacking_height);
            let overflow_guts = Tensor::from(overflow_buffer)
                .reshape([overflow_batch_size, 1 << log_stacking_height])
                .transpose();
            let overflow_mle = Mle::new(overflow_guts);
            batch_multilinears.push(overflow_mle);

            let batch_multilinears = batch_multilinears.into_iter().collect::<Message<_>>();
            tx.send(batch_multilinears).unwrap();
        });
        rx.await.unwrap()
    }
}
