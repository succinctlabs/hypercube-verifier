use std::{
    marker::PhantomData,
    mem::ManuallyDrop,
    ops::{Index, IndexMut},
};

use derive_where::derive_where;
use hypercube_alloc::{Backend, Buffer, CpuBackend, Init, TryReserveError, GLOBAL_CPU_BACKEND};
use p3_matrix::Matrix;
use rand::{distributions::Standard, prelude::Distribution, Rng};
use serde::{ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

use crate::{Dimensions, DimensionsError};

#[derive(Debug, Clone)]
#[derive_where(PartialEq, Eq; Buffer<T, A>)]
pub struct Tensor<T, A: Backend = CpuBackend> {
    pub storage: Buffer<T, A>,
    pub dimensions: Dimensions,
}

impl<T, A: Backend> Tensor<T, A> {
    #[inline]
    pub fn with_sizes_in(sizes: impl AsRef<[usize]>, allocator: A) -> Self {
        Self::try_with_sizes_in(sizes, allocator).unwrap()
    }

    #[inline]
    pub fn zeros_in(sizes: impl AsRef<[usize]>, allocator: A) -> Self {
        let mut tensor = Self::with_sizes_in(sizes, allocator);
        tensor.storage.write_bytes(0, tensor.total_len() * std::mem::size_of::<T>()).unwrap();
        tensor
    }

    #[inline]
    pub fn zeros_in_with_total_capacity(sizes: impl AsRef<[usize]>, allocator: A) -> Self {
        let mut tensor = Self::with_sizes_in(sizes, allocator);
        tensor.storage.write_bytes(0, tensor.total_len() * std::mem::size_of::<T>()).unwrap();
        tensor
    }

    #[inline]
    pub fn try_with_sizes_in(
        sizes: impl AsRef<[usize]>,
        allocator: A,
    ) -> Result<Self, TryReserveError> {
        let dimensions = Dimensions::try_from(sizes.as_ref()).unwrap();
        Ok(Self {
            storage: Buffer::try_with_capacity_in(dimensions.total_len(), allocator)?,
            dimensions,
        })
    }

    #[track_caller]
    pub fn reshape_in_place(&mut self, sizes: impl AsRef<[usize]>) {
        #[cold]
        #[track_caller]
        #[inline(never)]
        fn dimension_fail(new_dimensions: &Dimensions, old_dimensions: &Dimensions) -> ! {
            panic!(
                "TensorView::reshape: dimension mismatch: {:?} vs {:?}",
                new_dimensions, old_dimensions
            );
        }

        let dimensions: Dimensions = sizes.as_ref().try_into().unwrap();
        if self.dimensions.compatible(&dimensions).is_err() {
            dimension_fail(&dimensions, &self.dimensions);
        }
        self.dimensions = dimensions;
    }

    #[inline]
    #[track_caller]
    pub fn reshape(mut self, sizes: impl AsRef<[usize]>) -> Self {
        #[cold]
        #[track_caller]
        #[inline(never)]
        fn dimension_fail(new_dimensions: &Dimensions, old_dimensions: &Dimensions) -> ! {
            panic!(
                "TensorView::reshape: dimension mismatch: {:?} vs {:?}",
                new_dimensions, old_dimensions
            );
        }

        let dimensions: Dimensions = sizes.as_ref().try_into().unwrap();
        if self.dimensions.compatible(&dimensions).is_err() {
            dimension_fail(&dimensions, &self.dimensions);
        }
        self.dimensions = dimensions;
        self
    }

    #[inline]
    pub fn into_buffer(self) -> Buffer<T, A> {
        self.storage
    }

    #[inline]
    pub fn as_buffer(&self) -> &Buffer<T, A> {
        &self.storage
    }

    #[inline]
    pub fn as_mut_buffer(&mut self) -> &mut Buffer<T, A> {
        &mut self.storage
    }

    #[inline]
    pub fn backend(&self) -> &A {
        self.storage.allocator()
    }

    #[inline]
    pub fn shape(&self) -> &Dimensions {
        &self.dimensions
    }

    /// Returns the dimensions of the tensor.
    #[inline]
    pub fn sizes(&self) -> &[usize] {
        self.dimensions.sizes()
    }

    #[inline]
    pub fn strides(&self) -> &[usize] {
        self.dimensions.strides()
    }

    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.storage.as_ptr()
    }

    /// # Safety
    ///
    /// This function is unsafe because it enables bypassing the lifetime of the tensor.
    #[inline]
    pub unsafe fn owned_unchecked(&self) -> ManuallyDrop<Self> {
        self.owned_unchecked_in(self.storage.allocator().clone())
    }

    /// # Safety
    ///
    /// This function is unsafe because it enables bypassing the lifetime of the tensor.
    #[inline]
    pub unsafe fn owned_unchecked_in(&self, storage_allocator: A) -> ManuallyDrop<Self> {
        let dimensions = self.dimensions.clone();
        let storage = self.storage.owned_unchecked_in(storage_allocator);
        let storage = ManuallyDrop::into_inner(storage);
        ManuallyDrop::new(Self { storage, dimensions })
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        self.dimensions.total_len()
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.storage.as_mut_ptr()
    }

    #[inline]
    pub fn as_view(&self) -> TensorView<T, A> {
        TensorView { ptr: self.as_ptr(), dimensions: self.dimensions.clone(), _marker: PhantomData }
    }

    #[inline]
    pub fn as_view_mut(&mut self) -> TensorViewMut<T, A> {
        TensorViewMut {
            ptr: self.as_mut_ptr(),
            dimensions: self.dimensions.clone(),
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<TensorView<T, A>> {
        self.as_view().get(index)
    }

    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<TensorViewMut<T, A>> {
        self.as_view_mut().get(index)
    }

    #[inline]
    pub fn split(&self) -> impl Iterator<Item = TensorView<T, A>> {
        self.as_view().split()
    }

    #[inline]
    pub fn split_mut(&mut self) -> impl Iterator<Item = TensorViewMut<T, A>> {
        self.as_view_mut().split_mut()
    }

    /// # Safety
    ///
    /// See [std::mem::MaybeUninit::assume_init].
    #[inline]
    pub unsafe fn assume_init(&mut self) {
        self.storage.set_len(self.storage.capacity());
    }
}

impl<T, A: Backend, I: AsRef<[usize]>> Index<I> for Tensor<T, A> {
    type Output = Init<T, A>;

    #[track_caller]
    fn index(&self, index: I) -> &Self::Output {
        #[cold]
        #[track_caller]
        #[inline(never)]
        fn dimension_fail(index_len: usize, sizes_len: usize) -> ! {
            panic!(
                "Index length ({}) does not match tensor dimensions length ({})",
                index_len, sizes_len
            );
        }

        if index.as_ref().len() != self.dimensions.sizes().len() {
            dimension_fail(index.as_ref().len(), self.dimensions.sizes().len());
        }
        let index = self.dimensions.index_map(index);
        &self.storage[index]
    }
}

impl<T, A: Backend, I: AsRef<[usize]>> IndexMut<I> for Tensor<T, A> {
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        let index = self.dimensions.index_map(index);
        &mut self.storage[index]
    }
}

impl<T, A: Backend> From<Buffer<T, A>> for Tensor<T, A> {
    #[inline]
    fn from(buffer: Buffer<T, A>) -> Self {
        let dims = [buffer.len()].into_iter().collect();
        Self { storage: buffer, dimensions: dims }
    }
}

impl<T> From<Vec<T>> for Tensor<T, CpuBackend> {
    #[inline]
    fn from(vec: Vec<T>) -> Self {
        Self::from(Buffer::from(vec))
    }
}

impl<T> FromIterator<T> for Tensor<T, CpuBackend> {
    #[inline]
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::from(iter.into_iter().collect::<Vec<_>>())
    }
}

impl<T: Clone + Send + Sync> From<p3_matrix::dense::RowMajorMatrix<T>> for Tensor<T, CpuBackend> {
    fn from(value: p3_matrix::dense::RowMajorMatrix<T>) -> Self {
        let dimensions: Dimensions = [value.height(), value.width()].try_into().unwrap();
        let storage = Buffer::from(value.values);
        Self { storage, dimensions }
    }
}

impl<T: Clone + Send + Sync> TryFrom<Tensor<T, CpuBackend>>
    for p3_matrix::dense::RowMajorMatrix<T>
{
    type Error = DimensionsError;
    fn try_from(value: Tensor<T, CpuBackend>) -> Result<Self, Self::Error> {
        if value.sizes().len() != 2 {
            return Err(DimensionsError::TooManyDimensions(value.sizes().len()));
        }
        let width = value.sizes()[1];
        let values = value.storage.into_vec();
        Ok(Self::new(values, width))
    }
}

impl<T> Tensor<T, CpuBackend> {
    pub fn rand<R: Rng>(rng: &mut R, sizes: impl AsRef<[usize]>) -> Self
    where
        Standard: Distribution<T>,
    {
        let dimensions: Dimensions = sizes.as_ref().try_into().unwrap();
        let values = rng.sample_iter(Standard).take(dimensions.total_len()).collect::<Vec<_>>();
        Self { storage: Buffer::from(values), dimensions }
    }

    #[inline]
    pub fn with_sizes(sizes: impl AsRef<[usize]>) -> Self {
        Tensor::with_sizes_in(sizes, GLOBAL_CPU_BACKEND)
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.storage[..]
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.storage[..]
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct TensorView<'a, T, A: Backend = CpuBackend> {
    ptr: *const T,
    dimensions: Dimensions,
    /// Marker to ensure that the view is not used after the original tensor is freed.
    _marker: PhantomData<&'a Tensor<T, A>>,
}

impl<'a, T, A: Backend> TensorView<'a, T, A> {
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }

    #[inline]
    pub fn sizes(&self) -> &[usize] {
        self.dimensions.sizes()
    }

    #[inline]
    pub fn strides(&self) -> &[usize] {
        self.dimensions.strides()
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        self.dimensions.total_len()
    }

    #[inline]
    pub fn shape(&self) -> &Dimensions {
        &self.dimensions
    }

    #[inline]
    pub fn flatten(self) -> TensorView<'a, T, A> {
        let total_len = self.total_len();
        self.reshape([total_len])
    }

    #[inline]
    #[track_caller]
    pub fn reshape(self, sizes: impl AsRef<[usize]>) -> TensorView<'a, T, A> {
        #[cold]
        #[track_caller]
        #[inline(never)]
        fn dimension_fail(new_dimensions: &Dimensions, old_dimensions: &Dimensions) -> ! {
            panic!(
                "TensorView::reshape: dimension mismatch: {:?} vs {:?}",
                new_dimensions, old_dimensions
            );
        }

        let dimensions: Dimensions = sizes.as_ref().try_into().unwrap();
        if self.dimensions.compatible(&dimensions).is_err() {
            dimension_fail(&dimensions, &self.dimensions);
        }
        TensorView { ptr: self.ptr, dimensions, _marker: PhantomData }
    }

    #[inline]
    pub fn get(mut self, index: usize) -> Option<Self> {
        let size = self.dimensions.sizes_mut().remove(0);
        if index >= size {
            return None;
        }
        let stride = self.dimensions.strides_mut().remove(0);
        let offset = index * stride;

        let ptr = unsafe { self.ptr.add(offset) };
        Some(Self { ptr, dimensions: self.dimensions, _marker: PhantomData })
    }

    pub fn split(self) -> impl Iterator<Item = Self> {
        (0..self.dimensions.sizes()[0]).map(move |i| self.clone().get(i).unwrap())
    }
}

impl<'a, T, A: Backend> Clone for TensorView<'a, T, A> {
    fn clone(&self) -> Self {
        Self { ptr: self.ptr, dimensions: self.dimensions.clone(), _marker: PhantomData }
    }
}

impl<'a, T, A: Backend> From<&'a Tensor<T, A>> for TensorView<'a, T, A> {
    fn from(tensor: &'a Tensor<T, A>) -> Self {
        tensor.as_view()
    }
}

impl<'a, T, A: Backend, I: AsRef<[usize]>> Index<I> for TensorView<'a, T, A> {
    type Output = Init<T, A>;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        let index = self.dimensions.index_map(index);
        unsafe {
            let ptr = self.ptr.add(index) as *const Init<T, A>;
            ptr.as_ref().unwrap()
        }
    }
}

impl<T> Default for Tensor<T, CpuBackend> {
    fn default() -> Self {
        Self::from(Buffer::default())
    }
}

#[derive(Debug)]
pub struct TensorViewMut<'a, T, A: Backend = CpuBackend> {
    ptr: *mut T,
    dimensions: Dimensions,
    /// Marker to ensure that we get an exlusive reference, and that the view is not used after the
    /// original tensor is freed.
    _marker: PhantomData<&'a mut Tensor<T, A>>,
}

impl<'a, T, A: Backend> TensorViewMut<'a, T, A> {
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr
    }

    #[inline]
    pub fn sizes(&self) -> &[usize] {
        self.dimensions.sizes()
    }

    #[inline]
    pub fn shape(&self) -> &Dimensions {
        &self.dimensions
    }

    #[inline]
    pub fn strides(&self) -> &[usize] {
        self.dimensions.strides()
    }

    #[inline]
    pub fn flatten(self) -> TensorViewMut<'a, T, A> {
        let total_len = self.total_len();
        self.reshape([total_len])
    }

    #[inline]
    pub fn reshape(self, sizes: impl AsRef<[usize]>) -> TensorViewMut<'a, T, A> {
        let dimensions: Dimensions = sizes.as_ref().try_into().unwrap();
        self.dimensions.compatible(&dimensions).unwrap();
        TensorViewMut { ptr: self.ptr, dimensions, _marker: PhantomData }
    }

    #[inline]
    pub fn get(mut self, index: usize) -> Option<Self> {
        let size = self.dimensions.sizes_mut().remove(0);
        if index >= size {
            return None;
        }
        let stride = self.dimensions.strides_mut().remove(0);
        let offset = index * stride;

        let ptr = unsafe { self.ptr.add(offset) };
        Some(Self { ptr, dimensions: self.dimensions, _marker: PhantomData })
    }

    #[inline]
    pub fn split_mut(self) -> impl Iterator<Item = Self> {
        (0..self.dimensions.sizes()[0]).map(move |i| {
            let self_copy =
                Self { ptr: self.ptr, dimensions: self.dimensions.clone(), _marker: PhantomData };
            self_copy.get(i).unwrap()
        })
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        self.dimensions.total_len()
    }
}

impl<'a, T> TensorView<'a, T, CpuBackend> {
    #[inline]
    pub fn as_slice(self) -> &'a [T] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.dimensions.total_len()) }
    }
}

impl<'a, T> TensorViewMut<'a, T, CpuBackend> {
    #[inline]
    pub fn as_slice(self) -> &'a [T] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.dimensions.total_len()) }
    }

    #[inline]
    pub fn as_mut_slice(self) -> &'a mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.dimensions.total_len()) }
    }
}

impl<'a, T, A: Backend> From<&'a mut Tensor<T, A>> for TensorViewMut<'a, T, A> {
    fn from(tensor: &'a mut Tensor<T, A>) -> Self {
        tensor.as_view_mut()
    }
}

impl<'a, T, A: Backend, I: AsRef<[usize]>> Index<I> for TensorViewMut<'a, T, A> {
    type Output = Init<T, A>;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        let index = self.dimensions.index_map(index);
        unsafe {
            let ptr = self.ptr.add(index) as *const T as *const Init<T, A>;
            ptr.as_ref().unwrap()
        }
    }
}

impl<'a, T, A: Backend, I: AsRef<[usize]>> IndexMut<I> for TensorViewMut<'a, T, A> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        let index = self.dimensions.index_map(index);
        unsafe {
            let ptr = self.ptr.add(index) as *mut Init<T, A>;
            ptr.as_mut().unwrap()
        }
    }
}

// A macro to create a 1D or 2D tensor from a list of elements.
#[macro_export]
macro_rules! tensor {
    // ----- 2D pattern: e.g. tensor![[1,2,3], [4,5,6]] -----
    //
    // Matches a top-level array of sub-arrays: [ [a,b,c], [d,e,f], ... ].
    // Each sub-array is 1D. We gather them all in a Vec<Vec<_>>,
    // check that all rows have the same length, flatten them,
    // and reshape into a 2D Tensor.

    ($([$($elem:expr),* $(,)?]),+ $(,)?) => {{
        // Gather each sub-array into a temporary Vec<Vec<T>>.
        let rows = vec![
            $(
                vec![$($elem,)*]
            ),*
        ];

        // Check that all rows have the same length.
        let row_len = rows[0].len();
        let rows_count = rows.len();
        if !rows.iter().all(|r| r.len() == row_len) {
            panic!("All sub-lists must have the same length to form a 2D tensor.");
        }

        // Flatten everything into a single Vec<T>.
        let flattened = rows.into_iter().flatten().collect::<Vec<_>>();

        // Build the Tensor and reshape it to [rows_count, row_len].
        // (We assume .reshape([..]) returns Self in your code.)
        $crate::Tensor::from(flattened).reshape([rows_count, row_len])
    }};

    // ----- 1D pattern with outer brackets: e.g. tensor!([1, 2, 3]) -----
    //
    // If you do want “bare” bracket usage to produce a 1D Tensor (shape = [3]).

    ([$($elem:expr),* $(,)?]) => {{
        let v = vec![$($elem,)*];
        $crate::Tensor::from(v)
    }};

    // ----- 1D “bare” comma‐separated: e.g. tensor![1, 2, 3] -----
    //
    // Matches a simple comma list at top-level.

    ($($elem:expr),+ $(,)?) => {{
        let v = vec![$($elem,)*];
        $crate::Tensor::from(v)
    }};
}

// Make a serialize and deserialize for Tensor<T> using the fact that we can serialize the buffer
// and the dimensions.

impl<T: Serialize> Serialize for Tensor<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Tensor", 2)?;
        state.serialize_field("storage", &self.storage)?;
        state.serialize_field("dimensions", &self.dimensions)?;
        state.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Tensor<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Storage,
            Dimensions,
        }

        struct TensorVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for TensorVisitor<T> {
            type Value = Tensor<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct Tensor")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let storage = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let dimensions = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                Ok(Tensor { storage, dimensions })
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut storage = None;
                let mut dimensions = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Storage => {
                            if storage.is_some() {
                                return Err(serde::de::Error::duplicate_field("storage"));
                            }
                            storage = Some(map.next_value()?);
                        }
                        Field::Dimensions => {
                            if dimensions.is_some() {
                                return Err(serde::de::Error::duplicate_field("dimensions"));
                            }
                            dimensions = Some(map.next_value()?);
                        }
                    }
                }

                let storage = storage.ok_or_else(|| serde::de::Error::missing_field("storage"))?;
                let dimensions =
                    dimensions.ok_or_else(|| serde::de::Error::missing_field("dimensions"))?;
                Ok(Tensor { storage, dimensions })
            }
        }

        deserializer.deserialize_struct(
            "Tensor",
            &["storage", "dimensions"],
            TensorVisitor(PhantomData),
        )
    }
}
