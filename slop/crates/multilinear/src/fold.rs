use std::future::Future;

use rayon::prelude::*;
use slop_algebra::{AbstractField, Field};
use slop_alloc::CpuBackend;
use slop_tensor::Tensor;
use tokio::sync::oneshot;

use crate::MleBaseBackend;

pub trait MleFoldBackend<F: AbstractField>: MleBaseBackend<F> {
    fn fold_mle(
        guts: &Tensor<F, Self>,
        beta: F,
    ) -> impl Future<Output = Tensor<F, Self>> + Send + Sync;
}

impl<F: Field> MleFoldBackend<F> for CpuBackend {
    async fn fold_mle(guts: &Tensor<F, Self>, beta: F) -> Tensor<F, Self> {
        let guts = unsafe { guts.owned_unchecked() };
        assert_eq!(guts.sizes()[1], 1, "this is only supported for a single polynomial");
        assert_eq!(guts.total_len() % 2, 0, "this is only supported for tensor of even length");
        let (tx, rx) = oneshot::channel();
        slop_futures::rayon::spawn(move || {
            // Compute the random linear combination of the even and odd coefficients of `vals`.
            // This is used to reduce the two evaluation claims for new_point into a
            // single evaluation claim.
            let fold_guts = guts
                .as_buffer()
                .par_iter()
                .step_by(2)
                .copied()
                .zip(guts.as_buffer().par_iter().skip(1).step_by(2).copied())
                .map(|(a, b)| a + beta * b)
                .collect::<Vec<_>>();
            let dim = fold_guts.len();
            let result = Tensor::from(fold_guts).reshape([dim, 1]);
            tx.send(result).unwrap();
        });
        rx.await.unwrap()
    }
}
