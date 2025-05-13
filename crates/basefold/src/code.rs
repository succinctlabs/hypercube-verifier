use derive_where::derive_where;
use p3_field::{AbstractField, TwoAdicField};
use serde::{Deserialize, Serialize};
use slop_alloc::{Backend, CpuBackend, HasBackend};
use slop_tensor::Tensor;
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FriConfig<F> {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
    _marker: PhantomData<F>,
}

impl<F: TwoAdicField> FriConfig<F> {
    #[inline]
    pub const fn new(log_blowup: usize, num_queries: usize, proof_of_work_bits: usize) -> Self {
        Self { log_blowup, num_queries, proof_of_work_bits, _marker: PhantomData }
    }

    pub fn auto(log_blowup: usize, bits_of_security: usize) -> Self {
        assert_eq!(bits_of_security, 100);
        assert_eq!(log_blowup, 1);
        let num_queries = 100;
        let proof_of_work_bits = 16;
        Self::new(log_blowup, num_queries, proof_of_work_bits)
    }

    #[inline]
    pub const fn log_blowup(&self) -> usize {
        self.log_blowup
    }

    #[inline]
    pub const fn num_queries(&self) -> usize {
        self.num_queries
    }

    #[inline]
    pub const fn proof_of_work_bits(&self) -> usize {
        self.proof_of_work_bits
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive_where(PartialEq, Eq; Tensor<F, A>)]
#[serde(bound(
    serialize = "Tensor<F, A>: Serialize",
    deserialize = "Tensor<F, A>: Deserialize<'de>"
))]
pub struct RsCodeWord<F, A: Backend = CpuBackend> {
    pub data: Tensor<F, A>,
}

impl<F: AbstractField, A: Backend> RsCodeWord<F, A> {
    pub const fn new(data: Tensor<F, A>) -> Self {
        Self { data }
    }
}

impl<F: AbstractField, A: Backend> Borrow<Tensor<F, A>> for RsCodeWord<F, A> {
    fn borrow(&self) -> &Tensor<F, A> {
        &self.data
    }
}

impl<F: AbstractField, A: Backend> BorrowMut<Tensor<F, A>> for RsCodeWord<F, A> {
    fn borrow_mut(&mut self) -> &mut Tensor<F, A> {
        &mut self.data
    }
}

impl<F, A: Backend> HasBackend for RsCodeWord<F, A> {
    type Backend = A;

    #[inline]
    fn backend(&self) -> &Self::Backend {
        self.data.backend()
    }
}
