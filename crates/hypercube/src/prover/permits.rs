use std::sync::Arc;

use thiserror::Error;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};
use tracing::Span;

/// A permit for the prover.
#[derive(Debug)]
pub struct ProverPermit {
    /// The underlying permit.
    #[allow(dead_code)]
    permit: OwnedSemaphorePermit,
    /// The span for the permit lifetime.
    span: Span,
    /// The time the permit was acquired.
    time: tokio::time::Instant,
}

/// A semaphore for the prover.
#[derive(Debug, Clone)]
pub struct ProverSemaphore {
    /// The underlying semaphore.
    sem: Arc<Semaphore>,
}

impl ProverSemaphore {
    /// Create a new prover semaphore with the given number of permits.
    #[must_use]
    #[inline]
    pub fn new(max_permits: usize) -> Self {
        Self { sem: Arc::new(Semaphore::new(max_permits)) }
    }

    /// Acquire a permit.
    #[inline]
    pub async fn acquire(self) -> Result<ProverPermit, ProverAcquireError> {
        let span = tracing::Span::current();
        let permit = self.sem.acquire_owned().await?;
        let time = tokio::time::Instant::now();
        Ok(ProverPermit { permit, span, time })
    }

    /// Acquire multiple permits.
    #[inline]
    pub async fn acquire_many(self, n: u32) -> Result<ProverPermit, ProverAcquireError> {
        let span = tracing::Span::current();
        let permit = self.sem.acquire_many_owned(n).await?;
        let time = tokio::time::Instant::now();
        Ok(ProverPermit { permit, span, time })
    }
}

/// An error that occurs when acquiring a permit.
#[derive(Debug, Error)]
#[error("failed to acquire permit")]
pub struct ProverAcquireError(#[from] AcquireError);

impl Drop for ProverPermit {
    fn drop(&mut self) {
        let duration = self.time.elapsed();
        tracing::debug!(parent: &self.span, "permit acquired for {:?} ", duration);
    }
}
