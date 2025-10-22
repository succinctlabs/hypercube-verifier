use std::{error::Error, future::Future, sync::Arc};

use slop_algebra::TwoAdicField;
use slop_alloc::{Backend, CpuBackend};
use slop_basefold::{FriConfig, RsCodeWord};
use slop_commit::Message;
use slop_dft::{Dft, DftOrdering};
use slop_futures::OwnedBorrow;
use slop_multilinear::Mle;

pub trait ReedSolomonEncoder<F: TwoAdicField, A: Backend = CpuBackend>:
    'static + Send + Sync
{
    /// The error type returned by the encoder.
    type Error: Error;

    fn config(&self) -> &FriConfig<F>;

    /// Encodes the input into a new codeword.
    fn encode_batch<M>(
        &self,
        data: Message<M>,
    ) -> impl Future<Output = Result<Message<RsCodeWord<F, A>>, Self::Error>> + Send
    where
        M: OwnedBorrow<Mle<F, A>>;
}

#[derive(Debug, Clone)]
pub struct CpuDftEncoder<F: TwoAdicField, D> {
    pub config: FriConfig<F>,
    pub dft: Arc<D>,
}

impl<F: TwoAdicField, D: Dft<F>> ReedSolomonEncoder<F> for CpuDftEncoder<F, D> {
    type Error = D::Error;

    #[inline]
    fn config(&self) -> &FriConfig<F> {
        &self.config
    }

    async fn encode_batch<M>(&self, data: Message<M>) -> Result<Message<RsCodeWord<F>>, Self::Error>
    where
        M: OwnedBorrow<Mle<F>>,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let dft = self.dft.clone();
        let log_blowup = self.config.log_blowup();
        let data = data.to_vec();
        slop_futures::rayon::spawn(move || {
            let mut results = Vec::with_capacity(data.len());
            for data in data {
                let data = data.borrow().guts();
                assert_eq!(data.sizes().len(), 2, "Expected a 2D tensor");
                // Perform a DFT along the first axis of the tensor (assumed to be the long
                // dimension).
                let dft = dft.dft(data, log_blowup, DftOrdering::BitReversed, 0).unwrap();
                results.push(Arc::new(RsCodeWord { data: dft }));
            }
            tx.send(Message::from(results)).unwrap();
        });
        Ok(rx.await.unwrap())
    }
}
