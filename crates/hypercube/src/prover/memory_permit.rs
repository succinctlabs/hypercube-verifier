use std::sync::Arc;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};

/// A semaphore that can be used to permit memory usage.
pub struct MemoryPermitting {
    inner: Arc<Semaphore>,
    mem_in_bytes: usize,
}

impl MemoryPermitting {
    /// The maximum number of bytes that can be permitted.
    ///
    /// Note: This bound comes from underlying [`Semaphore`].
    pub const MAX: usize = usize::MAX >> 3;

    /// Create a new memory permitting.
    ///
    /// Panics if the number of permits is greater than [`Self::MAX`].
    #[must_use]
    pub fn new(mem_in_bytes: usize) -> Self {
        Self { inner: Arc::new(Semaphore::new(mem_in_bytes)), mem_in_bytes }
    }

    /// Get the total memory that can be permitted.
    #[must_use]
    pub fn total_memory(&self) -> usize {
        self.inner.available_permits()
    }

    /// Get a memory permit for the given number of bytes.
    ///
    /// # Panics
    ///
    /// Panics if the number of bytes is greater than [`Self::MAX`].
    pub async fn acquire(&self, mem_in_bytes: usize) -> Result<MemoryPermit, MemoryPermitError> {
        if mem_in_bytes > self.mem_in_bytes {
            return Err(MemoryPermitError::ExceedsMaxPermittedMemory);
        } else if mem_in_bytes == 0 {
            return Err(MemoryPermitError::TriedToAcquireZero);
        }

        let permits = accquire_raw(&self.inner, mem_in_bytes).await?;
        Ok(MemoryPermit { inner: permits, mem_in_bytes: self.mem_in_bytes })
    }
}

impl Clone for MemoryPermitting {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), mem_in_bytes: self.mem_in_bytes }
    }
}

/// Errors that can occur when acquiring a memory permit.
#[derive(Debug, thiserror::Error)]
pub enum MemoryPermitError {
    /// The requested memory is zero.
    #[error("Request a permit for 0 memory.")]
    TriedToAcquireZero,
    /// The requested memory exceeds the maximum permitted memory.
    #[error("Requested memory exceeds the maximum permitted memory")]
    ExceedsMaxPermittedMemory,
    /// The requested memory is negative.
    #[error("Split request with insufficient memory permit")]
    NotEnoughMemoryToSplit,
    /// The requested memory is negative.
    #[error("The semaphore has been explicitly closed, this is a bug")]
    Closed(#[from] AcquireError),
}

/// A memory permit.
pub struct MemoryPermit {
    inner: Vec<OwnedSemaphorePermit>,
    /// The total possible memory that can be permitted.
    mem_in_bytes: usize,
}

impl MemoryPermit {
    /// Create a new memory permit from a list of permits.
    #[must_use]
    pub fn num_bytes(&self) -> usize {
        #[allow(clippy::pedantic)]
        self.inner.iter().map(|p| p.num_permits()).sum()
    }

    /// Split the memory permit into two.
    ///
    /// # Panics
    ///
    /// Panics if the number of bytes is greater than [`Self::num_bytes`].
    pub fn split(&mut self, mem_in_bytes: usize) -> Result<MemoryPermit, MemoryPermitError> {
        if mem_in_bytes > self.num_bytes() {
            return Err(MemoryPermitError::NotEnoughMemoryToSplit);
        } else if mem_in_bytes == 0 {
            return Err(MemoryPermitError::TriedToAcquireZero);
        }

        let mut permits = Vec::new();
        let mut to_acquire = mem_in_bytes;
        while let Some(permit) = self.inner.last_mut() {
            let num_permits = permit.num_permits();

            if num_permits <= to_acquire {
                to_acquire -= num_permits;
                permits.push(self.inner.pop().unwrap());
            } else {
                // todo this accepts a usize, should we just use usize everywhere?
                permits.push(permit.split(to_acquire).unwrap());
            }
        }

        Ok(MemoryPermit { inner: permits, mem_in_bytes: self.mem_in_bytes })
    }

    /// Increase the memory permit by the given number of bytes.
    pub async fn increase(&mut self, mem_in_bytes: usize) -> Result<(), MemoryPermitError> {
        if mem_in_bytes == 0 {
            return Ok(());
        }

        self.inner.extend(
            accquire_raw(
                self.inner
                    .first()
                    .expect("We should have at least one permit, this is a bug.")
                    .semaphore(),
                mem_in_bytes,
            )
            .await?,
        );

        Ok(())
    }

    /// Partially release the memory permit.
    ///
    /// This will release the memory permit by the given number of bytes.
    ///
    /// # Panics
    ///
    /// Panics if the number of bytes is greater than [`Self::num_bytes`].
    pub fn release(&mut self, mem_in_bytes: usize) -> Result<(), MemoryPermitError> {
        if mem_in_bytes == 0 {
            return Ok(());
        }

        // On drop, the permits will be released.
        let _ = self.split(mem_in_bytes)?;

        Ok(())
    }
}

/// Acquire a list of permits from a semaphore.
///
/// This helper function is needed because the [`Semaphore::acquire_many_owned`] method only accepts
/// a [`u32`].
async fn accquire_raw(
    inner: &Arc<Semaphore>,
    mem_in_bytes: usize,
) -> Result<Vec<OwnedSemaphorePermit>, MemoryPermitError> {
    let mut permits = Vec::new();
    let mut to_acquire = mem_in_bytes;
    while to_acquire > 0 {
        let n = to_acquire.min(u32::MAX as usize);
        let permit = inner.clone().acquire_many_owned(n as u32).await?;

        permits.push(permit);
        to_acquire -= n;
    }

    Ok(permits)
}
