use hypercube_alloc::CpuBackend;
use hypercube_tensor::Tensor;
use p3_field::AbstractField;

use crate::Point;

pub fn partial_lagrange_blocking<F: AbstractField>(
    point: &Point<F, CpuBackend>,
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
            .flat_map(|val| {
                let prod = val.clone() * coordinate.clone();
                [val.clone() - prod.clone(), prod]
            })
            .collect();
    });
    Tensor::from(evals).reshape([1 << point.dimension(), 1])
}
