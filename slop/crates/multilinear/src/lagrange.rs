use std::future::Future;

use slop_algebra::AbstractField;
use slop_alloc::CpuBackend;
use slop_tensor::Tensor;
use tokio::sync::oneshot;

use crate::{Basis, MleBaseBackend, Point};

pub trait PartialLagrangeBackend<F: AbstractField>: MleBaseBackend<F> {
    fn partial_lagrange(
        point: &Point<F, Self>,
    ) -> impl Future<Output = Tensor<F, Self>> + Send + Sync;
}

impl<F: AbstractField + 'static> PartialLagrangeBackend<F> for CpuBackend {
    async fn partial_lagrange(point: &Point<F, Self>) -> Tensor<F, Self> {
        let (tx, rx) = oneshot::channel();
        let point = point.clone();
        slop_futures::rayon::spawn(move || {
            let result = partial_lagrange_blocking(&point);
            tx.send(result).unwrap();
        });
        rx.await.unwrap()
    }
}

pub async fn monomial_basis_partial_eq<F: AbstractField + 'static>(
    point: &Point<F, CpuBackend>,
) -> Tensor<F, CpuBackend> {
    let (tx, rx) = oneshot::channel();
    let point = point.clone();
    slop_futures::rayon::spawn(move || {
        let result = monomial_basis_evals_blocking(&point);
        tx.send(result).unwrap();
    });
    rx.await.unwrap()
}

pub fn partial_eq_blocking_with_basis<F: AbstractField>(
    point: &Point<F, CpuBackend>,
    basis: Basis,
) -> Tensor<F, CpuBackend> {
    let one = F::one();
    let mut evals = Vec::with_capacity(1 << point.dimension());
    evals.push(one);

    // Build evals in num_variables rounds. In each round, we consider one more entry of `point`,
    // hence the zip.
    point.iter().for_each(|coordinate| {
        evals = evals
            .iter()
            // For each value in the previous round, multiply by (1-coordinate) and coordinate,
            // and collect all these values into a new vec.
            // For the monomial basis, do a slightly different computation.
            .flat_map(|val| {
                let prod = val.clone() * coordinate.clone();
                match basis {
                    Basis::Evaluation => [val.clone() - prod.clone(), prod.clone()],
                    Basis::Monomial => [val.clone(), prod],
                }
            })
            .collect();
    });
    Tensor::from(evals).reshape([1 << point.dimension(), 1])
}

/// Given `point = [x_1,...,x_n]`, this function computes the 2^m-length vector `v` such that
/// `v[i] = prod_j ((1-i_j)(1-x_j) + x_j^{i_j})` where `i = (i_1,...,i_n)` is the big-endian binary
/// representation of the index `i`.
pub fn partial_lagrange_blocking<F: AbstractField>(
    point: &Point<F, CpuBackend>,
) -> Tensor<F, CpuBackend> {
    partial_eq_blocking_with_basis(point, Basis::Evaluation)
}

/// Given `point = [x_1,...,x_n]`, this function computes the 2^m-length vector `v` such that
/// `v[i] = x_1^{i_1} * ... * x_n^{i_n}` where `i = (i_1,...,i_n)` is the big-endian binary
/// representation of the index `i`.
pub fn monomial_basis_evals_blocking<F: AbstractField>(
    point: &Point<F, CpuBackend>,
) -> Tensor<F, CpuBackend> {
    partial_eq_blocking_with_basis(point, Basis::Monomial)
}
