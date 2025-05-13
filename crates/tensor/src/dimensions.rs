use arrayvec::ArrayVec;
use itertools::Itertools;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const MAX_DIMENSIONS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(C)]
pub struct Dimensions {
    sizes: ArrayVec<usize, MAX_DIMENSIONS>,
    strides: ArrayVec<usize, MAX_DIMENSIONS>,
}

#[derive(Debug, Clone, Copy, Error)]
pub enum DimensionsError {
    #[error("Too many dimensions {0}, maximum number allowed is {MAX_DIMENSIONS}")]
    TooManyDimensions(usize),
    #[error("total number of elements must match, expected {0}, got {1}")]
    NumElementsMismatch(usize, usize),
}

impl Dimensions {
    fn new(sizes: ArrayVec<usize, MAX_DIMENSIONS>) -> Self {
        let mut strides = ArrayVec::new();
        let mut stride = 1;
        for size in sizes.iter().rev() {
            strides.push(stride);
            stride *= size;
        }
        strides.reverse();
        Self { sizes, strides }
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        self.sizes.iter().product()
    }

    #[inline]
    pub(crate) fn compatible(&self, other: &Dimensions) -> Result<(), DimensionsError> {
        if self.total_len() != other.total_len() {
            return Err(DimensionsError::NumElementsMismatch(self.total_len(), other.total_len()));
        }
        Ok(())
    }

    #[inline]
    pub fn sizes(&self) -> &[usize] {
        &self.sizes
    }

    pub(crate) fn sizes_mut(&mut self) -> &mut ArrayVec<usize, MAX_DIMENSIONS> {
        &mut self.sizes
    }

    pub(crate) fn strides_mut(&mut self) -> &mut ArrayVec<usize, MAX_DIMENSIONS> {
        &mut self.strides
    }

    #[inline]
    pub fn strides(&self) -> &[usize] {
        &self.strides
    }

    #[inline]
    pub(crate) fn index_map(&self, index: impl AsRef<[usize]>) -> usize {
        index.as_ref().iter().zip_eq(self.strides.iter()).map(|(i, s)| i * s).sum()
    }
}

impl TryFrom<&[usize]> for Dimensions {
    type Error = DimensionsError;

    fn try_from(value: &[usize]) -> Result<Self, Self::Error> {
        let sizes = ArrayVec::try_from(value)
            .map_err(|_| DimensionsError::TooManyDimensions(value.len()))?;
        Ok(Self::new(sizes))
    }
}

impl TryFrom<Vec<usize>> for Dimensions {
    type Error = DimensionsError;

    fn try_from(value: Vec<usize>) -> Result<Self, Self::Error> {
        let sizes = ArrayVec::try_from(value.as_slice())
            .map_err(|_| DimensionsError::TooManyDimensions(value.len()))?;
        Ok(Self::new(sizes))
    }
}

impl<const N: usize> TryFrom<[usize; N]> for Dimensions {
    type Error = DimensionsError;

    fn try_from(value: [usize; N]) -> Result<Self, Self::Error> {
        let sizes = ArrayVec::try_from(value.as_slice())
            .map_err(|_| DimensionsError::TooManyDimensions(value.len()))?;
        Ok(Self::new(sizes))
    }
}

impl FromIterator<usize> for Dimensions {
    #[inline]
    fn from_iter<T: IntoIterator<Item = usize>>(iter: T) -> Self {
        let sizes = ArrayVec::from_iter(iter);
        Self::new(sizes)
    }
}

impl Serialize for Dimensions {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.sizes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Dimensions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let sizes = Vec::deserialize(deserializer)?;
        Ok(Self::try_from(sizes).expect("invalid dimension length"))
    }
}
