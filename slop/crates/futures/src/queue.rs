use std::{mem::ManuallyDrop, ops::Deref, sync::Arc};

use thiserror::Error;

use crossbeam::queue::ArrayQueue;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, TryAcquireError};

/// An asynchronous queue that allows workers to be popped by multiple callers.
///
/// This queue is thread-safe and allows multiple callers to pop workers concurrently.
/// The queue is implemented using a `crossbeam::queue::ArrayQueue` and a `tokio::sync::Semaphore`.
#[derive(Debug)]
pub struct WorkerQueue<T> {
    queue: ArrayQueue<T>,
    permits: Arc<Semaphore>,
}

#[derive(Debug, Error)]
#[error("failed to acquire worker: {0}")]
pub struct TryAcquireWorkerError(#[from] pub TryAcquireError);

#[derive(Debug, Error)]
#[error("failed to acquire worker: {0}")]
pub struct AcquireWorkerError(#[from] pub AcquireError);

pub struct Worker<T> {
    worker: ManuallyDrop<T>,
    owner: Arc<WorkerQueue<T>>,
    _permit: OwnedSemaphorePermit,
}

impl<T> WorkerQueue<T> {
    #[inline]
    pub fn new(workers: Vec<T>) -> Self {
        let queue = ArrayQueue::new(workers.len());
        let permits = Arc::new(Semaphore::new(workers.len()));
        for worker in workers {
            queue.push(worker).ok().unwrap();
        }
        Self { queue, permits }
    }

    /// Pop a worker from the queue.
    ///
    /// This function will wait until a worker becomes available.
    pub async fn pop(self: Arc<Self>) -> Result<Worker<T>, AcquireWorkerError> {
        let permit = self.permits.clone().acquire_owned().await?;
        let worker = ManuallyDrop::new(self.queue.pop().unwrap());
        Ok(Worker { worker, owner: self.clone(), _permit: permit })
    }

    /// Try to pop a worker from the queue.
    ///
    /// This function returns immediately if the queue is empty.
    pub fn try_pop(self: Arc<Self>) -> Result<Worker<T>, TryAcquireWorkerError> {
        let permit = self.permits.clone().try_acquire_owned()?;
        let worker = ManuallyDrop::new(self.queue.pop().unwrap());
        Ok(Worker { worker, owner: self.clone(), _permit: permit })
    }
}

impl<T> Worker<T> {
    #[inline]
    pub fn owner(&self) -> &Arc<WorkerQueue<T>> {
        &self.owner
    }
}

impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        unsafe {
            let worker = ManuallyDrop::take(&mut self.worker);
            self.owner.queue.push(worker).ok();
        }
    }
}

impl<T> Deref for Worker<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.worker
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_queue() {
        let num_workers = 100;
        let num_callers = 1000;
        let workers = (0..num_workers).collect::<Vec<_>>();
        let queue = Arc::new(WorkerQueue::new(workers));

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        for _ in 0..num_callers {
            let queue = queue.clone();
            let tx = tx.clone();
            tokio::task::spawn(async move {
                let worker = queue.pop().await;
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                drop(worker);
                tx.send(true).unwrap();
            });
        }
        drop(tx);

        let mut count = 0;
        while let Some(flag) = rx.recv().await {
            assert!(flag);
            count += 1;
        }
        assert_eq!(count, num_callers);
    }
}
