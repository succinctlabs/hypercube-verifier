use slop_alloc::HasBackend;

pub trait BackendWrite: HasBackend {
    fn copy_into_backend(self, backend: &Self::Backend);
}
