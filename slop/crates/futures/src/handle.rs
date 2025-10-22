use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{prelude::*, stream::AbortHandle};
use pin_project::pin_project;
use tokio::sync::oneshot;

/// A handle for abortable tasks.
#[derive(Debug)]
#[pin_project]
pub struct TaskHandle<T, E> {
    #[pin]
    output_rx: oneshot::Receiver<Result<T, E>>,
    abort_handle: AbortHandle,
}

impl<T, E> Future for TaskHandle<T, E>
where
    E: From<oneshot::error::RecvError>,
{
    type Output = Result<T, E>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        this.output_rx.poll(cx).map(|res| res?)
    }
}

impl<T, E> TaskHandle<T, E> {
    #[inline]
    pub const fn new(
        output_rx: oneshot::Receiver<Result<T, E>>,
        abort_handle: AbortHandle,
    ) -> Self {
        Self { output_rx, abort_handle }
    }

    #[inline]
    pub fn abort(&self) {
        self.abort_handle.abort();
    }
}
