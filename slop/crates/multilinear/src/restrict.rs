use rayon::prelude::*;
use std::{cmp::max, future::Future, sync::Arc};
use tokio::sync::oneshot;

use slop_algebra::{AbstractExtensionField, AbstractField, ExtensionField, Field};
use slop_alloc::CpuBackend;
use slop_tensor::Tensor;

use crate::{MleBaseBackend, MleEval, MleEvaluationBackend, Point};

pub trait MleFixLastVariableBackend<F: AbstractField, EF: AbstractExtensionField<F>>:
    MleBaseBackend<F>
{
    fn mle_fix_last_variable_constant_padding(
        mle: &Tensor<F, Self>,
        alpha: EF,
        padding_value: F,
    ) -> impl Future<Output = Tensor<EF, Self>> + Send + Sync;

    fn mle_fix_last_variable(
        mle: &Tensor<F, Self>,
        alpha: EF,
        padding_values: Arc<MleEval<F, Self>>,
    ) -> impl Future<Output = Tensor<EF, Self>> + Send + Sync;
}

pub trait MleFixLastVariableInPlaceBackend<F: AbstractField>: MleBaseBackend<F> {
    fn mle_fix_last_variable_in_place(
        mle: &mut Tensor<F, Self>,
        alpha: F,
    ) -> impl Future<Output = ()> + Send + Sync;
}

impl<F, EF> MleFixLastVariableBackend<F, EF> for CpuBackend
where
    F: Field,
    EF: ExtensionField<F>,
{
    async fn mle_fix_last_variable(
        mle: &Tensor<F, Self>,
        alpha: EF,
        padding_values: Arc<MleEval<F, Self>>,
    ) -> Tensor<EF, Self> {
        let mle = unsafe { mle.owned_unchecked() };
        let padding_values = unsafe { padding_values.owned_unchecked() };

        let (tx, rx) = oneshot::channel();
        slop_futures::rayon::spawn(move || {
            let mle = mle;
            let num_polynomials = CpuBackend::num_polynomials(&mle);
            let num_non_zero_elements_out = mle.sizes()[0].div_ceil(2);
            let result_size = num_non_zero_elements_out * num_polynomials;

            let mut result: Vec<EF> = Vec::with_capacity(result_size);

            #[allow(clippy::uninit_vec)]
            unsafe {
                result.set_len(result_size);
            }

            let result_chunk_size =
                max(num_non_zero_elements_out / num_cpus::get() * num_polynomials, num_polynomials);
            let mle_chunk_size = 2 * result_chunk_size;

            mle.as_slice()
                .chunks(mle_chunk_size)
                .zip(result.chunks_mut(result_chunk_size))
                .par_bridge()
                .for_each(|(mle_chunk, result_chunk)| {
                    let num_result_rows = result_chunk.len() / num_polynomials;

                    (0..num_result_rows).for_each(|i| {
                        (0..num_polynomials).for_each(|j| {
                            let x = mle_chunk[(2 * i) * num_polynomials + j];
                            let y = mle_chunk
                                .get((2 * i + 1) * num_polynomials + j)
                                .copied()
                                .unwrap_or_else(|| padding_values[j]);
                            // return alpha * y + (EF::one() - alpha) * x, but in a more efficient
                            // way that minimizes extension field
                            // multiplications.
                            result_chunk[i * num_polynomials + j] = alpha * (y - x) + x;
                        });
                    });
                });

            let result = Tensor::from(result).reshape([num_non_zero_elements_out, num_polynomials]);
            tx.send(result).unwrap();
        });
        rx.await.unwrap()
    }

    fn mle_fix_last_variable_constant_padding(
        mle: &Tensor<F, Self>,
        alpha: EF,
        padding_value: F,
    ) -> impl Future<Output = Tensor<EF, Self>> + Send + Sync {
        let padding_values: MleEval<_> =
            vec![padding_value; CpuBackend::num_polynomials(mle)].into();
        CpuBackend::mle_fix_last_variable(mle, alpha, Arc::new(padding_values))
    }
}

pub trait MleFixedAtZeroBackend<F: AbstractField, EF: AbstractExtensionField<F>>:
    MleEvaluationBackend<F, EF>
{
    fn fixed_at_zero(
        mle: &Tensor<F, Self>,
        point: &Point<EF>,
    ) -> impl Future<Output = Tensor<EF, CpuBackend>> + Send;
}

impl<F: Field, EF: ExtensionField<F>> MleFixedAtZeroBackend<F, EF> for CpuBackend {
    async fn fixed_at_zero(mle: &Tensor<F, Self>, point: &Point<EF, Self>) -> Tensor<EF, Self> {
        // TODO: A smarter way to do this is pre-cache the partial_lagrange_evals that are implicit
        // in `eval_at_point` so we don't recompute it at every step of BaseFold.
        let mle = unsafe { mle.owned_unchecked() };
        let (tx, rx) = oneshot::channel();
        slop_futures::rayon::spawn(move || {
            let even_values = mle.as_slice().par_iter().step_by(2).copied().collect::<Vec<_>>();
            tx.send(even_values).unwrap();
        });
        let even_values = rx.await.unwrap();
        CpuBackend::eval_mle_at_point(&Tensor::from(even_values), point).await
    }
}
