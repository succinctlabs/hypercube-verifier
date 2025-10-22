use std::{
    collections::{hash_map::Entry, HashMap},
    future::Future,
    pin::Pin,
    sync::{Arc, Condvar, Mutex},
    task::{Context, Poll, Waker},
};

/// A turn-based synchronization primitive.
pub struct TurnBasedSync {
    pub current_turn: Mutex<usize>,
    pub cv: Condvar,
}

impl TurnBasedSync {
    /// Creates a new [TurnBasedSync].
    pub fn new() -> Self {
        TurnBasedSync { current_turn: Mutex::new(0), cv: Condvar::new() }
    }

    /// Waits for the current turn to be equal to the given turn.
    pub fn wait_for_turn(&self, my_turn: usize) {
        let mut turn = self.current_turn.lock().unwrap();
        while *turn != my_turn {
            turn = self.cv.wait(turn).unwrap();
        }
    }

    /// Gets the current turn
    ///
    /// # WARNING
    /// Note that relying on this value can cause race conditions.
    pub fn current_turn(&self) -> usize {
        *self.current_turn.lock().unwrap()
    }

    /// Advances the current turn.
    pub fn advance_turn(&self) {
        let mut turn: std::sync::MutexGuard<'_, usize> = self.current_turn.lock().unwrap();
        *turn += 1;
        self.cv.notify_all();
    }
}

pub struct AsyncTurn {
    inner: Arc<Mutex<AsyncTurnInner>>,
}

impl AsyncTurn {
    pub fn new() -> Self {
        // Note: We could define some preconditions here and use unsafe + atomic counter here, but
        // this works fine for now...
        Self {
            inner: Arc::new(Mutex::new(AsyncTurnInner { current_turn: 0, wakers: HashMap::new() })),
        }
    }

    pub fn wait_for_turn(&self, my_turn: usize) -> AsyncTurnFuture {
        AsyncTurnFuture { inner: self.inner.clone(), my_turn }
    }
}

/// The inner state of the [AsyncTurn] primitive.
pub struct AsyncTurnInner {
    current_turn: usize,
    wakers: HashMap<usize, Waker>,
}

impl Clone for AsyncTurn {
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}

#[must_use = "Futures do nothing unless `await`ed"]
pub struct AsyncTurnFuture {
    inner: Arc<Mutex<AsyncTurnInner>>,
    my_turn: usize,
}

impl Future for AsyncTurnFuture {
    type Output = AsyncTurnGuard;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut inner = this.inner.lock().expect("AsyncTurnFuture poisoned");

        // Fast path: if the current turn is equal to the given turn, we can return immediately.
        if inner.current_turn == this.my_turn {
            return Poll::Ready(AsyncTurnGuard { inner: this.inner.clone() });
        }

        // Normal path: We need to wait for `this.my_turn` to be reached.
        match inner.wakers.entry(this.my_turn) {
            Entry::Vacant(v) => {
                v.insert(cx.waker().clone());
            }
            Entry::Occupied(mut o) => {
                let _ = o.insert(cx.waker().clone());
            }
        }

        // Ensure our turn has not passed.
        if inner.current_turn > this.my_turn {
            #[cold]
            #[inline(never)]
            fn panic_turn_passed(turn: usize) -> ! {
                panic!("AsyncTurnFuture: turn {turn} has already passed");
            }

            panic_turn_passed(this.my_turn);
        } else {
            Poll::Pending
        }
    }
}

pub struct AsyncTurnGuard {
    inner: Arc<Mutex<AsyncTurnInner>>,
}

impl Drop for AsyncTurnGuard {
    fn drop(&mut self) {
        let mut lock = self.inner.lock().expect("AsyncTurnGuard poisoned");

        // Advance the turn.
        lock.current_turn += 1;

        // Notify the waker.
        if let Some(waker) = lock.wakers.get(&lock.current_turn) {
            waker.wake_by_ref();
        }
    }
}
