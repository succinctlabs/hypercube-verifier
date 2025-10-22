use slop_algebra::AbstractField;
use slop_alloc::{Backend, CpuBackend};
use slop_tensor::Tensor;

pub trait MleBaseBackend<F: AbstractField>: Backend {
    /// Returns the number of polynomials in the batch.
    fn num_polynomials(guts: &Tensor<F, Self>) -> usize;

    /// Returns the number of variables in the polynomials.
    fn num_variables(guts: &Tensor<F, Self>) -> u32;

    // Number of non-zero entries in the MLE.
    fn num_non_zero_entries(guts: &Tensor<F, Self>) -> usize;

    fn uninit_mle(&self, num_polynomials: usize, num_non_zero_entries: usize) -> Tensor<F, Self>;
}

impl<F: AbstractField> MleBaseBackend<F> for CpuBackend {
    fn num_polynomials(guts: &Tensor<F, Self>) -> usize {
        guts.sizes()[1]
    }

    fn num_variables(guts: &Tensor<F, Self>) -> u32 {
        guts.sizes()[0].next_power_of_two().ilog2()
    }

    fn num_non_zero_entries(guts: &Tensor<F, Self>) -> usize {
        guts.sizes()[0]
    }

    fn uninit_mle(&self, num_polynomials: usize, num_non_zero_entries: usize) -> Tensor<F, Self> {
        Tensor::with_sizes_in([num_non_zero_entries, num_polynomials], *self)
    }
}
