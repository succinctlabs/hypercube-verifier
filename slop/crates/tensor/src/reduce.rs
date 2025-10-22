use std::future::Future;

use rayon::prelude::*;

use slop_algebra::Field;
use slop_alloc::{buffer, Backend, Buffer, CpuBackend};
use tokio::sync::oneshot;

use crate::{Dimensions, Tensor};

/// Sum backend trait
pub trait ReduceSumBackend<T>: Backend {
    fn sum_tensor_dim(
        src: &Tensor<T, Self>,
        dim: usize,
    ) -> impl Future<Output = Tensor<T, Self>> + Send + Sync;
}

impl<T, A: ReduceSumBackend<T>> Tensor<T, A> {
    /// Computes the sum of the tensor along a dimension
    pub async fn sum(&self, dim: usize) -> Tensor<T, A> {
        A::sum_tensor_dim(self, dim).await
    }
}

impl<T: Field> ReduceSumBackend<T> for CpuBackend {
    async fn sum_tensor_dim(src: &Tensor<T, Self>, dim: usize) -> Tensor<T, Self> {
        let mut sizes = src.sizes().to_vec();
        sizes.remove(dim);
        let dimensions = Dimensions::try_from(sizes).unwrap();
        let mut dst = Tensor { storage: buffer![], dimensions };
        assert_eq!(dim, 0, "Only sum along the first dimension is supported");
        let total_len = dst.total_len();
        let src_buffer = unsafe { src.as_buffer().owned_unchecked() };
        let (tx, rx) = oneshot::channel();
        let dim_stride = src.strides()[dim];
        slop_futures::rayon::spawn(move || {
            let sums = src_buffer
                .par_chunks_exact(dim_stride)
                .fold(
                    || vec![T::zero(); total_len],
                    |mut acc, item| {
                        acc.iter_mut().zip(item).for_each(|(a, b)| *a += *b);
                        acc
                    },
                )
                .reduce(
                    || vec![T::zero(); total_len],
                    |mut a, b| {
                        a.iter_mut().zip(b.iter()).for_each(|(a, b)| *a += *b);
                        a
                    },
                );

            let sums = Buffer::from(sums);
            dst.storage = sums;
            tx.send(dst).unwrap();
        });
        rx.await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use slop_algebra::AbstractField;
    use slop_baby_bear::BabyBear;

    use super::*;

    #[tokio::test]
    async fn test_sum() {
        let mut rng = rand::thread_rng();

        let sizes = [3, 4];

        let a = Tensor::<BabyBear>::rand(&mut rng, sizes);
        let b = a.sum(0).await;
        for j in 0..sizes[1] {
            let mut sum = BabyBear::zero();
            for i in 0..sizes[0] {
                sum += *a[[i, j]];
            }
            assert_eq!(sum, *b[[j]]);
        }

        let sizes = [3, 4, 5];

        let a = Tensor::<BabyBear>::rand(&mut rng, sizes);
        let b = a.sum(0).await;
        for j in 0..sizes[1] {
            for k in 0..sizes[2] {
                let mut sum = BabyBear::zero();
                for i in 0..sizes[0] {
                    sum += *a[[i, j, k]];
                }
                assert_eq!(sum, *b[[j, k]]);
            }
        }
    }
}
