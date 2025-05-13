use p3_field::{ExtensionField, Field};
use serde::{Deserialize, Serialize, Serializer};

use crate::backend::{Backend, CpuBackend, GLOBAL_CPU_BACKEND};
use crate::mem::{CopyDirection, CopyError};
use crate::slice::Slice;
use crate::{HasBackend, Init};
use crate::{RawBuffer, TryReserveError};
use std::mem::ManuallyDrop;
use std::{
    alloc::Layout,
    mem::MaybeUninit,
    ops::{
        Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo,
        RangeToInclusive,
    },
};

/// A fixed-size buffer.
#[derive(Debug)]
#[repr(C)]
pub struct Buffer<T, A: Backend = CpuBackend> {
    buf: RawBuffer<T, A>,
    len: usize,
}

unsafe impl<T, A: Backend> Send for Buffer<T, A> {}
unsafe impl<T, A: Backend> Sync for Buffer<T, A> {}

impl<T, A> Buffer<T, A>
where
    A: Backend,
{
    #[inline]
    #[must_use]
    pub fn with_capacity_in(capacity: usize, allocator: A) -> Self {
        let buf = RawBuffer::with_capacity_in(capacity, allocator);
        Self { buf, len: 0 }
    }

    #[inline]
    pub fn try_with_capacity_in(capacity: usize, allocator: A) -> Result<Self, TryReserveError> {
        let buf = RawBuffer::try_with_capacity_in(capacity, allocator)?;
        Ok(Self { buf, len: 0 })
    }

    /// Returns a new buffer from a pointer, length, and capacity.
    ///
    /// # Safety
    ///
    /// The pointer must be valid, it must have allocated memory in the size of
    /// capacity * size_of<T>, and the first `len` elements of the buffer must be initialized or
    /// about to be initialized in a foreign call.
    pub unsafe fn from_raw_parts(ptr: *mut T, length: usize, capacity: usize, alloc: A) -> Self {
        Self { buf: RawBuffer::from_raw_parts_in(ptr, capacity, alloc), len: length }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// # Safety
    ///
    /// This function is unsafe because it enables bypassing the lifetime of the buffer.
    #[inline]
    pub unsafe fn owned_unchecked(&self) -> ManuallyDrop<Self> {
        self.owned_unchecked_in(self.allocator().clone())
    }

    /// # Safety
    ///
    /// This function is unsafe because it enables bypassing the lifetime of the buffer.
    #[inline]
    pub unsafe fn owned_unchecked_in(&self, allocator: A) -> ManuallyDrop<Self> {
        let ptr = self.as_ptr() as *mut T;
        let len = self.len();
        let cap = self.capacity();
        ManuallyDrop::new(Self::from_raw_parts(ptr, len, cap, allocator))
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.buf.ptr()
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.buf.ptr()
    }

    /// # Safety
    ///
    /// TODO
    #[inline]
    pub unsafe fn set_len(&mut self, new_len: usize) {
        self.len = new_len;
    }

    /// # Safety
    ///
    /// TODO
    #[inline]
    pub unsafe fn assume_init(&mut self) {
        let cap = self.capacity();
        self.set_len(cap);
    }

    /// Copies all elements from `src` into `self`, using `copy_nonoverlapping`.
    ///
    /// The length of `src` must be the same as `self`.
    ///
    /// # Panics
    ///
    /// This function will panic if the two slices have different lengths or if the allocator
    /// returned an error.
    ///
    /// # Safety
    /// This operation is potentially asynchronous. The caller must insure the memory of the source
    /// is valid for the duration of the operation.
    #[track_caller]
    pub unsafe fn copy_from_host_slice(&mut self, src: &[T]) -> Result<(), CopyError> {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn len_mismatch_fail(dst_len: usize, src_len: usize) -> ! {
            panic!(
                "source slice length ({}) does not match destination slice length ({})",
                src_len, dst_len,
            );
        }

        if self.len() != src.len() {
            len_mismatch_fail(self.len(), src.len());
        }

        let layout = Layout::array::<T>(src.len()).unwrap();

        unsafe {
            self.buf.allocator().copy_nonoverlapping(
                src.as_ptr() as *const u8,
                self.buf.ptr() as *mut u8,
                layout.size(),
                CopyDirection::HostToDevice,
            )
        }
    }

    #[inline]
    pub fn allocator(&self) -> &A {
        self.buf.allocator()
    }

    /// # Safety
    #[inline]
    pub unsafe fn allocator_mut(&mut self) -> &mut A {
        self.buf.allocator_mut()
    }

    /// Appends all the elements from `src` into `self`, using `copy_nonoverlapping`.
    ///
    /// # Panics
    ///
    /// This function will panic if the resulting length will extend the buffer's capacity or if
    /// the allocator returned an error.
    ///
    ///  # Safety
    /// This operation is potentially asynchronous. The caller must insure the memory of the source
    /// is valid for the duration of the operation.
    #[track_caller]
    pub fn extend_from_device_slice(&mut self, src: &Slice<T, A>) -> Result<(), CopyError> {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn capacity_fail(dst_len: usize, src_len: usize, cap: usize) -> ! {
            panic!(
                "source slice length ({}) too long for buffer of length ({}) and capacity ({})",
                src_len, dst_len, cap
            );
        }

        if self.len() + src.len() > self.capacity() {
            capacity_fail(self.len(), src.len(), self.capacity());
        }

        let layout = Layout::array::<T>(src.len()).unwrap();

        unsafe {
            self.buf.allocator().copy_nonoverlapping(
                src.as_ptr() as *const u8,
                self.buf.ptr().add(self.len()) as *mut u8,
                layout.size(),
                CopyDirection::DeviceToDevice,
            )?;
        }

        // Extend the length of the buffer to include the new elements.
        self.len += src.len();

        Ok(())
    }

    /// Appends all the elements from `src` into `self`, using `copy_nonoverlapping`.
    ///
    /// # Panics
    ///
    /// This function will panic if the resulting length will extend the buffer's capacity or if
    /// the allocator returned an error.
    ///
    ///  # Safety
    /// This operation is potentially asynchronous. The caller must insure the memory of the source
    /// is valid for the duration of the operation.
    #[track_caller]
    pub fn extend_from_host_slice(&mut self, src: &[T]) -> Result<(), CopyError> {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn capacity_fail(dst_len: usize, src_len: usize, cap: usize) -> ! {
            panic!(
                "source slice length ({}) too long for buffer of length ({}) and capacity ({})",
                src_len, dst_len, cap
            );
        }

        if self.len() + src.len() > self.capacity() {
            capacity_fail(self.len(), src.len(), self.capacity());
        }

        let layout = Layout::array::<T>(src.len()).unwrap();

        unsafe {
            self.buf.allocator().copy_nonoverlapping(
                src.as_ptr() as *const u8,
                self.buf.ptr().add(self.len()) as *mut u8,
                layout.size(),
                CopyDirection::HostToDevice,
            )?;
        }

        // Extend the length of the buffer to include the new elements.
        self.len += src.len();

        Ok(())
    }

    /// Copies all elements from `self` into `dst`, using `copy_nonoverlapping`.
    ///
    /// The length of `dst` must be the same as `self`.
    ///
    /// **Note**: This function might be blocking.
    ///
    /// # Safety
    ///
    /// This operation is potentially asynchronous. The caller must insure the memory of the
    /// destination is valid for the duration of the operation.
    #[track_caller]
    pub unsafe fn copy_into_host(&self, dst: &mut [MaybeUninit<T>]) -> Result<(), CopyError> {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn len_mismatch_fail(dst_len: usize, src_len: usize) -> ! {
            panic!(
                "source slice length ({}) does not match destination slice length ({})",
                src_len, dst_len,
            );
        }

        if self.len() != dst.len() {
            len_mismatch_fail(dst.len(), self.len());
        }

        let layout = Layout::array::<T>(dst.len()).unwrap();

        unsafe {
            self.buf.allocator().copy_nonoverlapping(
                self.buf.ptr() as *const u8,
                dst.as_mut_ptr() as *mut u8,
                layout.size(),
                CopyDirection::DeviceToHost,
            )
        }
    }

    /// Copies all elements from `self` into a newely allocated [Vec<T>] and returns it.
    ///
    /// # Safety
    ///  See [Buffer::copy_into_host]
    pub unsafe fn copy_into_host_vec(&self) -> Vec<T> {
        let mut vec = Vec::with_capacity(self.len());
        self.copy_into_host(vec.spare_capacity_mut()).unwrap();
        unsafe {
            vec.set_len(self.len());
        }
        vec
    }

    /// Copies all elements from `self` into a newely allocated [Vec<T>] and returns it.
    ///
    /// # Safety
    ///  See [Buffer::copy_into_host]
    pub unsafe fn copy_into_host_buffer(&self) -> Buffer<T, CpuBackend> {
        let vec = self.copy_into_host_vec();
        Buffer::from(vec)
    }

    #[track_caller]
    pub fn write_bytes(&mut self, value: u8, len: usize) -> Result<(), CopyError> {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn capacity_fail(dst_len: usize, len: usize, cap: usize) -> ! {
            panic!(
                "Cannot write {} bytes to buffer of length {} and capacity {}",
                len, dst_len, cap
            );
        }

        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn align_fail(len: usize, size: usize) -> ! {
            panic!("Number of bytes ({}) does not match the size of the type ({})", len, size);
        }

        // Check that the number of bytes matches the size of the type.
        if len % std::mem::size_of::<T>() != 0 {
            align_fail(len, std::mem::size_of::<T>());
        }

        // Check that the buffer has enough capacity.
        if self.len() * std::mem::size_of::<T>() + len > self.capacity() * std::mem::size_of::<T>()
        {
            capacity_fail(self.len(), len, self.capacity());
        }

        // Write the bytes to the buffer.
        unsafe {
            self.buf.allocator().write_bytes(
                self.buf.ptr().add(self.len()) as *mut u8,
                value,
                len,
            )?;
        }

        // Extend the length of the buffer to include the new elements.
        self.len += len / std::mem::size_of::<T>();

        Ok(())
    }

    /// Reinterprets the values of the buffer as elements of the base field.
    pub fn flatten_to_base<E>(self) -> Buffer<E, A>
    where
        T: ExtensionField<E>,
        E: Field,
    {
        let mut buffer = ManuallyDrop::new(self);
        let (original_ptr, original_len, original_cap, allocator) =
            (buffer.as_mut_ptr(), buffer.len(), buffer.capacity(), buffer.allocator().clone());
        let ptr = original_ptr as *mut E;
        let len = original_len * T::D;
        let cap = original_cap * T::D;
        unsafe { Buffer::from_raw_parts(ptr, len, cap, allocator) }
    }

    pub fn into_extension<E>(self) -> Buffer<E, A>
    where
        T: Field,
        E: ExtensionField<T>,
    {
        let mut buffer = ManuallyDrop::new(self);
        let (original_ptr, original_len, original_cap, allocator) =
            (buffer.as_mut_ptr(), buffer.len(), buffer.capacity(), buffer.allocator().clone());
        let ptr = original_ptr as *mut E;
        let len = original_len.checked_div(E::D).unwrap();
        let cap = original_cap.checked_div(E::D).unwrap();
        unsafe { Buffer::from_raw_parts(ptr, len, cap, allocator) }
    }
}

impl<T, A: Backend> HasBackend for Buffer<T, A> {
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        self.buf.allocator()
    }
}

impl<T> Buffer<T, CpuBackend> {
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_in(capacity, GLOBAL_CPU_BACKEND)
    }

    #[inline]
    pub fn push(&mut self, value: T) {
        let take_self = std::mem::take(self);
        let mut vec = Vec::from(take_self);
        vec.push(value);
        *self = Self::from(vec);
    }

    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }

        // This is safe because we have just checked that the buffer is not empty.
        unsafe {
            let len = self.len();
            let ptr = &mut self[len - 1] as *mut _ as *mut T;
            let value = ptr.read();
            self.set_len(len - 1);
            std::ptr::drop_in_place(ptr);
            Some(value)
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        let elems: *mut [T] = self.as_mut_slice();

        // SAFETY:
        // - `elems` comes directly from `as_mut_slice` and is therefore valid.
        // - Setting `self.len` before calling `drop_in_place` means that,
        //   if an element's `Drop` impl panics, the vector's `Drop` impl will
        //   do nothing (leaking the rest of the elements) instead of dropping
        //   some twice.
        unsafe {
            self.len = 0;
            std::ptr::drop_in_place(elems);
        }
    }

    #[inline]
    pub fn resize(&mut self, new_len: usize, value: T)
    where
        T: Clone,
    {
        let owned_self = std::mem::take(self);
        let mut vec = Vec::from(owned_self);
        vec.resize(new_len, value);
        *self = Self::from(vec);
    }

    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[T]) {
        // Check to see if capacity needs to be increased.
        if self.len() + slice.len() > self.capacity() {
            let additional_capacity = self.len() + slice.len() - self.capacity();
            let owned_self = std::mem::take(self);
            let mut vec = Vec::from(owned_self);
            vec.reserve(vec.capacity() + additional_capacity);
            *self = Self::from(vec);
            assert!(self.capacity() >= self.len() + slice.len());
        }

        self.extend_from_host_slice(slice).unwrap()
    }

    #[inline]
    pub fn into_vec(self) -> Vec<T> {
        self.into()
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self[..]
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self[..]
    }

    pub fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<T>] {
        let mut vec = ManuallyDrop::new(unsafe {
            Vec::from_raw_parts(self.as_mut_ptr(), self.len(), self.capacity())
        });
        let slice = vec.spare_capacity_mut();
        let len = slice.len();
        let ptr = slice.as_mut_ptr();
        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }

    #[inline]
    pub fn insert(&mut self, index: usize, value: T) {
        let take_self = std::mem::take(self);
        let mut vec = Vec::from(take_self);
        vec.insert(index, value);
        *self = Self::from(vec);
    }
}

impl<T> From<Vec<T>> for Buffer<T, CpuBackend> {
    fn from(value: Vec<T>) -> Self {
        unsafe {
            let mut vec = ManuallyDrop::new(value);
            Buffer::from_raw_parts(vec.as_mut_ptr(), vec.len(), vec.capacity(), GLOBAL_CPU_BACKEND)
        }
    }
}

impl<T> Default for Buffer<T, CpuBackend> {
    #[inline]
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl<T> From<Buffer<T, CpuBackend>> for Vec<T> {
    fn from(value: Buffer<T, CpuBackend>) -> Self {
        let mut self_undropped = ManuallyDrop::new(value);
        unsafe {
            Vec::from_raw_parts(
                self_undropped.as_mut_ptr(),
                self_undropped.len(),
                self_undropped.capacity(),
            )
        }
    }
}

impl<T> FromIterator<T> for Buffer<T, CpuBackend> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let vec: Vec<T> = iter.into_iter().collect();
        Self::from(vec)
    }
}

// A macro buffer!() that just uses the vec!() macro and then converts it to a [Buffer<T>]
#[macro_export]
macro_rules! buffer {
    ($($x:expr),*) => {
       $crate::Buffer::from(vec![$($x),*])
    };
}

macro_rules! impl_index {
    ($($t:ty)*) => {
        $(
            impl<T, A: Backend> Index<$t> for Buffer<T, A>
            {
                type Output = Slice<T, A>;

                fn index(&self, index: $t) -> &Slice<T, A> {
                    unsafe {
                        Slice::from_slice(
                         std::slice::from_raw_parts(self.as_ptr(), self.len).index(index)
                    )
                  }
                }
            }

            impl<T, A: Backend> IndexMut<$t> for Buffer<T, A>
            {
                fn index_mut(&mut self, index: $t) -> &mut Slice<T, A> {
                    unsafe {
                        Slice::from_slice_mut(
                            std::slice::from_raw_parts_mut(self.as_mut_ptr(), self.len).index_mut(index)
                        )
                    }
                }
            }
        )*
    }
}

impl_index! {
    Range<usize>
    RangeFull
    RangeFrom<usize>
    RangeInclusive<usize>
    RangeTo<usize>
    RangeToInclusive<usize>
}

impl<T, A: Backend> Deref for Buffer<T, A> {
    type Target = Slice<T, A>;

    fn deref(&self) -> &Self::Target {
        &self[..]
    }
}

impl<T, A: Backend> DerefMut for Buffer<T, A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self[..]
    }
}

impl<T, A: Backend> Index<usize> for Buffer<T, A> {
    type Output = Init<T, A>;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self[..][index]
    }
}

impl<T, A: Backend> IndexMut<usize> for Buffer<T, A> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self[..][index]
    }
}

impl<T, A: Backend> Clone for Buffer<T, A> {
    #[inline]
    fn clone(&self) -> Self {
        let mut cloned = Self::with_capacity_in(self.len(), self.allocator().clone());
        let layout = Layout::array::<T>(self.len()).unwrap();
        unsafe {
            self.buf
                .allocator()
                .copy_nonoverlapping(
                    self.as_ptr() as *const u8,
                    cloned.as_mut_ptr() as *mut u8,
                    layout.size(),
                    CopyDirection::DeviceToDevice,
                )
                .unwrap();
            cloned.set_len(self.len());
        }
        cloned
    }
}

impl<T: PartialEq> PartialEq for Buffer<T, CpuBackend> {
    fn eq(&self, other: &Self) -> bool {
        self[..] == other[..]
    }
}

impl<T: Eq> Eq for Buffer<T, CpuBackend> {}

impl<T: Serialize> Serialize for Buffer<T, CpuBackend> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_slice().serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Buffer<T, CpuBackend> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec: Vec<T> = Vec::deserialize(deserializer)?;
        Ok(Buffer::from(vec))
    }
}
