use crate::{Backend, Buffer, CpuBackend, HasBackend};
use slop_algebra::PrimeField64;
use slop_symmetric::CryptographicPermutation;

impl<
        F: PrimeField64,
        P: CryptographicPermutation<[F; WIDTH]>,
        const WIDTH: usize,
        const RATE: usize,
    > HasBackend for slop_challenger::DuplexChallenger<F, P, WIDTH, RATE>
{
    type Backend = CpuBackend;

    fn backend(&self) -> &Self::Backend {
        &CpuBackend
    }
}
