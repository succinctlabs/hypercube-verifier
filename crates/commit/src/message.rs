use std::{ops::Deref, sync::Arc};

use serde::{Deserialize, Serialize};

/// A message sent to a prover.
///
/// In a commitment scheme, the prover can send messages to the verifier and later make structural
/// claims about them. The [Message] struct is used as input to the prover when sending the actual
/// data. The main usefulness of this struct is that it is cheap to clone if the number of different
/// message batches sent is small.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Message<T> {
    values: Vec<Arc<T>>,
}

impl<T> Default for Message<T> {
    fn default() -> Self {
        Self { values: vec![] }
    }
}

impl<T> From<Vec<T>> for Message<T> {
    fn from(value: Vec<T>) -> Self {
        let values = value.into_iter().map(|t| Arc::new(t)).collect();
        Self { values }
    }
}

impl<T> From<Vec<Arc<T>>> for Message<T> {
    fn from(value: Vec<Arc<T>>) -> Self {
        Self { values: value }
    }
}

impl<T> FromIterator<T> for Message<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let values = iter.into_iter().map(|t| Arc::new(t)).collect::<Vec<_>>();
        Self { values }
    }
}

impl<T> FromIterator<Arc<T>> for Message<T> {
    fn from_iter<I: IntoIterator<Item = Arc<T>>>(iter: I) -> Self {
        let values = iter.into_iter().collect::<Vec<_>>();
        Self { values }
    }
}

impl<T> IntoIterator for Message<T> {
    type Item = Arc<T>;
    type IntoIter = <Vec<Arc<T>> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

impl<T> Deref for Message<T> {
    type Target = Vec<Arc<T>>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T> From<Arc<T>> for Message<T> {
    #[inline]
    fn from(value: Arc<T>) -> Self {
        Self { values: vec![value] }
    }
}

impl<T> From<T> for Message<T> {
    #[inline]
    fn from(value: T) -> Self {
        Self::from(Arc::new(value))
    }
}

impl<T> Extend<T> for Message<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.values.extend(iter.into_iter().map(|t| Arc::new(t)));
    }
}

impl<T> Extend<Arc<T>> for Message<T> {
    fn extend<I: IntoIterator<Item = Arc<T>>>(&mut self, iter: I) {
        self.values.extend(iter);
    }
}
