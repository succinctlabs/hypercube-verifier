#![allow(clippy::disallowed_types)]
use std::error::Error;

use serde::{Deserialize, Serialize};
use slop_algebra::Field;
use slop_alloc::{Backend, CpuBackend};
use slop_tensor::Tensor;

pub mod p3;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DftOrdering {
    Normal,
    BitReversed,
}

pub trait Dft<T: Field, A: Backend = CpuBackend>: 'static + Send + Sync {
    type Error: Error;

    /// Perofrms a discrete Fourier transform along a given dimension.
    ///
    /// A `dft` implemelemtor may choose to:
    /// - Return an error if the dimension is not supported.
    /// - Return an error if the ordering is not supported.
    /// - Return an error if the shift is not supported.
    fn coset_dft_into(
        &self,
        src: &Tensor<T, A>,
        dst: &mut Tensor<T, A>,
        shift: T,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<(), Self::Error>;

    fn coset_dft(
        &self,
        src: &Tensor<T, A>,
        shift: T,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<Tensor<T, A>, Self::Error> {
        let mut sizes = src.sizes().to_vec();
        sizes[dim] <<= log_blowup;
        let mut dst = Tensor::with_sizes_in(sizes, src.backend().clone());
        self.coset_dft_into(src, &mut dst, shift, log_blowup, ordering, dim)?;
        Ok(dst)
    }

    fn dft_into(
        &self,
        src: &Tensor<T, A>,
        dst: &mut Tensor<T, A>,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<(), Self::Error> {
        self.coset_dft_into(src, dst, T::one(), log_blowup, ordering, dim)
    }

    fn dft(
        &self,
        src: &Tensor<T, A>,
        log_blowup: usize,
        ordering: DftOrdering,
        dim: usize,
    ) -> Result<Tensor<T, A>, Self::Error> {
        self.coset_dft(src, T::one(), log_blowup, ordering, dim)
    }
}
