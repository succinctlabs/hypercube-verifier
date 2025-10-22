use std::future::Future;

use slop_algebra::AbstractField;
use slop_alloc::{Backend, CpuBackend};
use tokio::sync::oneshot;

use crate::Tensor;

pub trait AddBackend<T, U>: Backend {
    type AddOutput;

    fn add(
        lhs: &Tensor<T, Self>,
        rhs: &Tensor<U, Self>,
    ) -> impl Future<Output = Tensor<Self::AddOutput, Self>> + Send + Sync;
}

pub trait AddAssignBackend<T>: Backend {
    fn add_assign(lhs: &mut Tensor<T, Self>, rhs: T) -> impl Future<Output = ()> + Send + Sync;
}

impl<T: AbstractField + Send + Sync + 'static> AddAssignBackend<T> for CpuBackend {
    async fn add_assign(lhs: &mut Tensor<T, Self>, rhs: T) {
        let lhs = unsafe { lhs.owned_unchecked() };

        let (tx, rx) = oneshot::channel();
        slop_futures::rayon::spawn(move || {
            let mut lhs = lhs;

            let lhs = lhs.as_mut_slice();

            (0..lhs.len()).for_each(|i| {
                lhs[i] += rhs.clone();
            });

            tx.send(()).unwrap();
        });

        rx.await.unwrap();
    }
}
