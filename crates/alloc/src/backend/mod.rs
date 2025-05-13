mod cpu;
mod io;

use std::{borrow::Cow, fmt::Debug, future::Future, rc::Rc, sync::Arc};

pub use cpu::*;
pub use io::*;

use crate::{
    mem::{CopyError, DeviceMemory},
    Allocator,
};

/// # Safety
///
/// TODO
pub unsafe trait Backend:
    Sized + Allocator + DeviceMemory + Clone + Debug + Send + Sync + 'static
{
    fn copy_from<B, T>(&self, data: T) -> impl Future<Output = Result<T::Output, CopyError>> + Send
    where
        B: Backend,
        T: HasBackend + CopyIntoBackend<Self, B>,
    {
        data.copy_into_backend(self)
    }
}

pub trait GlobalBackend: Backend + 'static {
    fn global() -> &'static Self;
}

pub trait HasBackend {
    type Backend: Backend;

    fn backend(&self) -> &Self::Backend;
}

impl<'a, T> HasBackend for &'a T
where
    T: HasBackend,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        (**self).backend()
    }
}

impl<'a, T> HasBackend for &'a mut T
where
    T: HasBackend,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        (**self).backend()
    }
}

impl<'a, T> HasBackend for Cow<'a, T>
where
    T: HasBackend + Clone,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        self.as_ref().backend()
    }
}

impl<T> HasBackend for Box<T>
where
    T: HasBackend,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        self.as_ref().backend()
    }
}

impl<T> HasBackend for Arc<T>
where
    T: HasBackend,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        self.as_ref().backend()
    }
}

impl<T> HasBackend for Rc<T>
where
    T: HasBackend,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        self.as_ref().backend()
    }
}
