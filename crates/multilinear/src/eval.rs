use hypercube_alloc::{buffer, Buffer, CpuBackend};
use hypercube_tensor::{Dimensions, Tensor};
use p3_field::{AbstractExtensionField, AbstractField};
use rayon::prelude::*;

use crate::{partial_lagrange_blocking, Point};

pub(crate) fn eval_mle_at_point_blocking<
    F: AbstractField + Sync,
    EF: AbstractExtensionField<F> + Send + Sync,
>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
) -> Tensor<EF, CpuBackend> {
    let partial_lagrange = partial_lagrange_blocking(point);
    let mut sizes = mle.sizes().to_vec();
    sizes.remove(0);
    let dimensions = Dimensions::try_from(sizes).unwrap();
    let mut dst = Tensor { storage: buffer![], dimensions };
    let total_len = dst.total_len();
    let dot_products = mle
        .as_buffer()
        .par_chunks_exact(mle.strides()[0])
        .zip(partial_lagrange.as_buffer().par_iter())
        .map(|(chunk, scalar)| chunk.iter().map(|a| scalar.clone() * a.clone()).collect())
        .reduce(
            || vec![EF::zero(); total_len],
            |mut a, b| {
                a.iter_mut().zip(b.iter()).for_each(|(a, b)| *a += b.clone());
                a
            },
        );

    let dot_products = Buffer::from(dot_products);
    dst.storage = dot_products;
    dst
}
