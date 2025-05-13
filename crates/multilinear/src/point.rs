use std::{
    fmt::Debug,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut, Index, IndexMut},
};

use derive_where::derive_where;
use p3_field::AbstractField;
use rand::{distributions::Standard, prelude::Distribution};
use serde::{Deserialize, Serialize};
use slop_alloc::{
    buffer, Backend, Buffer, CanCopyFromRef, CanCopyIntoRef, CpuBackend, HasBackend, Init, Slice,
};
use slop_tensor::Tensor;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive_where(PartialEq, Eq; Buffer<T, A>)]
#[serde(bound(
    serialize = "Buffer<T, A>: Serialize",
    deserialize = "Buffer<T, A>: Deserialize<'de>"
))]
pub struct Point<T, A: Backend = CpuBackend> {
    values: Buffer<T, A>,
}

impl<T, A: Backend> Point<T, A> {
    #[inline]
    pub const fn new(values: Buffer<T, A>) -> Self {
        Self { values }
    }

    #[inline]
    pub fn values(&self) -> &Buffer<T, A> {
        &self.values
    }

    #[inline]
    pub fn values_mut(&mut self) -> &mut Buffer<T, A> {
        &mut self.values
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.len() == 0
    }

    #[inline]
    pub fn into_values(self) -> Buffer<T, A> {
        self.values
    }

    #[inline]
    pub fn dimension(&self) -> usize {
        self.values.len()
    }

    /// # Safety
    #[inline]
    pub unsafe fn assume_init(&mut self) {
        self.values.assume_init();
    }

    #[inline]
    pub fn backend(&self) -> &A {
        self.values.allocator()
    }

    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.values.as_ptr()
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.values.as_mut_ptr()
    }

    /// # Safety
    ///
    /// This function is unsafe because it violates the lifetime rules. Users should make sure any
    /// side effects remain in the scope of nthe original point.
    #[inline]
    pub unsafe fn onwed_unchecked(&self) -> ManuallyDrop<Self> {
        let ptr = self.values.as_ptr() as *mut _;
        let len = self.values.len();
        let cap = self.values.capacity();
        let allocator = self.values.allocator().clone();
        let values = Buffer::from_raw_parts(ptr, len, cap, allocator);
        ManuallyDrop::new(Self { values })
    }

    // #[inline]
    // pub fn copy_into_host(&self) -> Point<T, CpuBackend> {
    //     Point::new(unsafe { Buffer::from(self.values.copy_into_host_vec()) })
    // }
}

impl<T, A: Backend> Index<usize> for Point<T, A> {
    type Output = Init<T, A>;

    fn index(&self, index: usize) -> &Self::Output {
        self.values.index(index)
    }
}

impl<T, A: Backend> IndexMut<usize> for Point<T, A> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.values.index_mut(index)
    }
}

impl<T> Point<T, CpuBackend> {
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.values.iter()
    }

    // Creates a bool hypercube point that is the big endian binary representation of `num`.
    pub fn from_usize(num: usize, dimension: usize) -> Self
    where
        T: AbstractField,
    {
        Point::from(
            (0..dimension)
                .rev()
                .map(|i| T::from_canonical_usize((num >> i) & 1))
                .collect::<Vec<_>>(),
        )
    }

    pub fn bit_string_evaluation(&self) -> T
    where
        T: AbstractField,
    {
        self.values
            .iter()
            .enumerate()
            .map(|(i, x)| x.clone() * T::from_canonical_usize(1 << (self.values.len() - i - 1)))
            .sum()
    }

    pub fn remove_last_coordinate(&mut self) -> T {
        self.values.pop().expect("Point is empty")
    }

    pub fn rand<R: rand::Rng>(rng: &mut R, dimension: u32) -> Self
    where
        Standard: Distribution<T>,
    {
        Self::new(Tensor::rand(rng, [dimension as usize]).into_buffer())
    }

    pub fn split_at(&self, k: usize) -> (Self, Self)
    where
        T: Clone,
    {
        let (left, right) = self.values.split_at(k);
        let left_values = Buffer::from(left.to_vec());
        let right_values = Buffer::from(right.to_vec());
        (Self::new(left_values), Self::new(right_values))
    }

    #[inline]
    pub fn mle_eval_zero(&self) -> T
    where
        T: AbstractField,
    {
        self.values.iter().map(|x| T::one() - x.clone()).product()
    }

    #[inline]
    pub fn mle_eval_one(&self) -> T
    where
        T: AbstractField,
    {
        self.values.iter().cloned().product()
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.values.to_vec()
    }

    #[inline]
    pub fn reverse(&mut self) {
        self.values.reverse();
    }

    #[inline]
    pub fn reversed(&self) -> Self
    where
        T: Clone,
    {
        let mut point = self.clone();
        point.reverse();
        point
    }

    #[inline]
    pub fn last_k(&self, k: usize) -> Self
    where
        T: Clone,
    {
        Point::new(Buffer::from(self.to_vec()[self.values.len() - k..].to_vec()))
    }

    pub fn copy_into<A: Backend>(&self, alloc: &A) -> Point<T, A> {
        let mut buffer = Buffer::with_capacity_in(self.values.len(), alloc.clone());
        buffer.extend_from_host_slice(&self.values).unwrap();
        Point::new(buffer)
    }

    /// Adds `dim_val` to the front of the point.
    #[inline]
    pub fn add_dimension(&mut self, dim_val: T) {
        self.values.insert(0, dim_val);
    }

    /// Adds `dim_val` to the back of the point.
    #[inline]
    pub fn add_dimension_back(&mut self, dim_val: T) {
        self.values.push(dim_val);
    }

    #[inline]
    pub fn extend(&mut self, other: &Self) {
        self.values.extend_from_slice(&other.values);
    }
}

// impl<T> Debug for Point<T, CpuBackend>
// where
//     T: Debug,
// {
//     fn fmt(&self, f: &mut Formatter<'_>) -> Result {
//         write!(f, "Point({:?})", self.values.as_slice())
//     }
// }

impl<T> From<Vec<T>> for Point<T, CpuBackend> {
    fn from(values: Vec<T>) -> Self {
        Self::new(Buffer::from(values))
    }
}

impl<T> FromIterator<T> for Point<T, CpuBackend> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::from(iter.into_iter().collect::<Vec<_>>())
    }
}

impl<T: Default> Default for Point<T, CpuBackend> {
    fn default() -> Self {
        Self::new(buffer![])
    }
}

impl<T, A: Backend> Deref for Point<T, A> {
    type Target = Slice<T, A>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T, A: Backend> DerefMut for Point<T, A> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}

impl<T, A: Backend> HasBackend for Point<T, A> {
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        self.values.allocator()
    }
}

pub trait PointBackend<T>:
    CanCopyFromRef<Point<T>, CpuBackend, Output = Point<T, Self>>
    + CanCopyIntoRef<Point<T, Self>, CpuBackend, Output = Point<T>>
{
}

impl<T, A> PointBackend<T> for A where
    A: CanCopyFromRef<Point<T>, CpuBackend, Output = Point<T, Self>>
        + CanCopyIntoRef<Point<T, A>, CpuBackend, Output = Point<T>>
{
}
