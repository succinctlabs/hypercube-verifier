use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};
use slop_alloc::HasBackend;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rounds<M> {
    pub rounds: Vec<M>,
}

impl<M> Rounds<M> {
    #[inline]
    pub const fn new() -> Self {
        Self { rounds: vec![] }
    }
}

impl<M> Default for Rounds<M> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<M> Deref for Rounds<M> {
    type Target = Vec<M>;

    fn deref(&self) -> &Self::Target {
        &self.rounds
    }
}

impl<M> DerefMut for Rounds<M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rounds
    }
}

impl<M> FromIterator<M> for Rounds<M> {
    fn from_iter<T: IntoIterator<Item = M>>(iter: T) -> Self {
        Rounds { rounds: iter.into_iter().collect() }
    }
}

impl<M> IntoIterator for Rounds<M> {
    type Item = M;
    type IntoIter = <Vec<M> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.rounds.into_iter()
    }
}

impl<M> Extend<M> for Rounds<M> {
    fn extend<T: IntoIterator<Item = M>>(&mut self, iter: T) {
        self.rounds.extend(iter);
    }
}

impl<M> HasBackend for Rounds<M>
where
    M: HasBackend,
{
    type Backend = M::Backend;

    fn backend(&self) -> &Self::Backend {
        assert!(!self.rounds.is_empty(), "Rounds must not be empty");
        self.rounds.first().unwrap().backend()
    }
}
