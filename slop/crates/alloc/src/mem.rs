use std::{rc::Rc, sync::Arc};

use thiserror::Error;

/// The [AllocError] error indicates an allocation failure that may be due to resource exhaustion
/// or to something wrong when combining the given input arguments with this allocator.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Error)]
#[error("allocation error")]
pub struct AllocError;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Error)]
#[error("copy error")]
pub struct CopyError;

/// The [CopyDirection] enum represents the direction of a memory copy operation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CopyDirection {
    HostToDevice,
    DeviceToHost,
    DeviceToDevice,
}

/// A trait that defines memory operations for a device.
pub trait DeviceMemory {
    /// # Safety
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        direction: CopyDirection,
    ) -> Result<(), CopyError>;

    /// TODO
    ///
    /// # Safety
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError>;
}

impl<T: DeviceMemory> DeviceMemory for &T {
    #[inline]
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        direction: CopyDirection,
    ) -> Result<(), CopyError> {
        (**self).copy_nonoverlapping(src, dst, size, direction)
    }

    #[inline]
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError> {
        (**self).write_bytes(dst, value, size)
    }
}

impl<T: DeviceMemory> DeviceMemory for Rc<T> {
    #[inline]
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        direction: CopyDirection,
    ) -> Result<(), CopyError> {
        (**self).copy_nonoverlapping(src, dst, size, direction)
    }

    #[inline]
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError> {
        (**self).write_bytes(dst, value, size)
    }
}

impl<T: DeviceMemory> DeviceMemory for Arc<T> {
    #[inline]
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        direction: CopyDirection,
    ) -> Result<(), CopyError> {
        (**self).copy_nonoverlapping(src, dst, size, direction)
    }

    #[inline]
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError> {
        (**self).write_bytes(dst, value, size)
    }
}
