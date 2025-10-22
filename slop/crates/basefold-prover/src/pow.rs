use std::future::Future;

use serde::{Deserialize, Serialize};
use slop_challenger::GrindingChallenger;

pub trait PowProver<C: GrindingChallenger>: 'static + Send + Sync {
    fn grind(&self, challenger: &mut C, bits: usize) -> impl Future<Output = C::Witness> + Send;
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct GrindingPowProver;

impl<C: GrindingChallenger + Send + Sync> PowProver<C> for GrindingPowProver {
    async fn grind(&self, challenger: &mut C, bits: usize) -> C::Witness {
        challenger.grind(bits)
    }
}
