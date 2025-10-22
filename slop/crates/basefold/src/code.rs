use derive_where::derive_where;
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, TwoAdicField};
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

    pub fn auto(log_blowup: usize, bits_of_security_needed_post_grinding: usize) -> Self {
        assert_eq!(bits_of_security_needed_post_grinding, 84);
        let num_queries = 84_usize.div_ceil(log_blowup);
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

#[derive(Debug, Clone)]
#[derive_where(PartialEq, Eq, Serialize, Deserialize; Tensor<F, A>)]
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
