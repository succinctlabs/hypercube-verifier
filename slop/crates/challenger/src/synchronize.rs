use p3_challenger::{CanObserve, CanSample, DuplexChallenger};
use slop_algebra::Field;
use slop_symmetric::CryptographicPermutation;

pub trait Synchronizable: Sized {
    fn synchronize_challengers(challengers: Vec<Self>) -> Self;
}

impl<F: Field, P: CryptographicPermutation<[F; WIDTH]>, const WIDTH: usize, const RATE: usize>
    Synchronizable for DuplexChallenger<F, P, WIDTH, RATE>
{
    fn synchronize_challengers(mut challengers: Vec<Self>) -> Self {
        debug_assert!(!challengers.is_empty(), "No challengers to synchronize");

        let mut result = challengers[0].clone();

        for c in challengers[1..].iter_mut() {
            for _ in 0..RATE {
                let elt: F = c.sample();
                result.observe(elt);
            }
        }
        result
    }
}
