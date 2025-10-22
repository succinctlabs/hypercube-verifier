use std::future::Future;

use rayon::prelude::*;
use slop_algebra::{AbstractExtensionField, AbstractField};
use slop_alloc::{buffer, Backend, Buffer, CanCopyFromRef, CanCopyIntoRef, CpuBackend};
use slop_tensor::{Dimensions, Tensor};

use crate::{
    partial_eq_blocking_with_basis, Basis, MleBaseBackend, MleEval, PartialLagrangeBackend, Point,
};

pub trait MleEvaluationBackend<F: AbstractField, EF: AbstractExtensionField<F>>:
    MleBaseBackend<F> + HostEvaluationBackend<F, EF> + ZeroEvalBackend<F> + ZeroEvalBackend<EF>
{
    fn eval_mle_at_point(
        mle: &Tensor<F, Self>,
        point: &Point<EF, Self>,
    ) -> impl Future<Output = Tensor<EF, Self>> + Send + Sync;

    fn eval_mle_at_eq(
        mle: &Tensor<F, Self>,
        eq: &Tensor<EF, Self>,
    ) -> impl Future<Output = Tensor<EF, Self>> + Send + Sync;
}

pub trait HostEvaluationBackend<F: AbstractField, EF: AbstractExtensionField<F>>:
    CanCopyFromRef<MleEval<EF>, CpuBackend, Output = MleEval<EF, Self>>
    + CanCopyIntoRef<MleEval<EF, Self>, CpuBackend, Output = MleEval<EF>>
{
}

impl<F: AbstractField, EF: AbstractExtensionField<F>, A: Backend> HostEvaluationBackend<F, EF> for A where
    A: CanCopyFromRef<MleEval<EF>, CpuBackend, Output = MleEval<EF, A>>
        + CanCopyIntoRef<MleEval<EF, Self>, CpuBackend, Output = MleEval<EF>>
{
}

pub trait ZeroEvalBackend<F: AbstractField>: Backend {
    fn zero_evaluations(&self, num_polynomials: usize) -> Tensor<F, Self>;
}

impl<F: AbstractField> ZeroEvalBackend<F> for CpuBackend {
    // This function assumes that `F::zero()` is represented by zeroed out memory.
    fn zero_evaluations(&self, num_polynomials: usize) -> Tensor<F, Self> {
        Tensor::zeros_in([num_polynomials], *self)
    }
}

impl<F, EF> MleEvaluationBackend<F, EF> for CpuBackend
where
    F: AbstractField + Sync + 'static,
    EF: AbstractExtensionField<F> + Send + Sync + 'static,
{
    async fn eval_mle_at_point(mle: &Tensor<F, Self>, point: &Point<EF, Self>) -> Tensor<EF, Self> {
        // Comopute the eq(b, point) polynomial.
        let partial_lagrange = Self::partial_lagrange(point).await;
        // Evaluate the mle via a dot product with the partial lagrange polynomial.
        mle.dot(&partial_lagrange, 0).await
    }

    async fn eval_mle_at_eq(mle: &Tensor<F, Self>, eq: &Tensor<EF, Self>) -> Tensor<EF, Self> {
        // Evaluate the mle via a dot product with the eq polynomial.
        mle.dot(eq, 0).await
    }
}

pub(crate) fn eval_mle_at_point_blocking_with_basis<
    F: AbstractField + Sync,
    EF: AbstractExtensionField<F> + Send + Sync,
>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
    basis: Basis,
) -> Tensor<EF, CpuBackend> {
    let partial_lagrange = partial_eq_blocking_with_basis(point, basis);
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

pub(crate) fn eval_mle_at_point_blocking<
    F: AbstractField + Sync,
    EF: AbstractExtensionField<F> + Send + Sync,
>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
) -> Tensor<EF, CpuBackend> {
    eval_mle_at_point_blocking_with_basis(mle, point, Basis::Evaluation)
}

/// Interpreting the internal vector of `mle` as the monomial-basis coefficients of a multilinear
/// polynomial, evaluate that multilinear at `point`.
pub(crate) fn eval_monomial_basis_mle_at_point_blocking<
    F: AbstractField + Sync,
    EF: AbstractExtensionField<F> + Send + Sync,
>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
) -> Tensor<EF, CpuBackend> {
    eval_mle_at_point_blocking_with_basis(mle, point, Basis::Monomial)
}
