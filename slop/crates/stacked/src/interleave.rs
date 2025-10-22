use std::future::Future;

use slop_algebra::Field;
use slop_alloc::Backend;
use slop_commit::Message;
use slop_multilinear::Mle;

pub trait InterleaveMultilinears<F: Field, A: Backend>: 'static + Send + Sync {
    fn interleave_multilinears(
        &self,
        multilinears: Message<Mle<F, A>>,
        log_stacking_height: u32,
    ) -> impl Future<Output = Message<Mle<F, A>>> + Send;
}
