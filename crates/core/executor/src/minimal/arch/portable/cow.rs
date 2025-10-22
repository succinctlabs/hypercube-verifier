use crate::memory::{Entry, PagedMemory};

/// A memory backed by [`PagedMemory`], which can be in either owned or COW mode.
pub enum MaybeCowMemory<T: Copy> {
    Cow { copy: PagedMemory<T>, original: PagedMemory<T> },
    Owned { memory: PagedMemory<T> },
}

impl<T: Copy> MaybeCowMemory<T> {
    /// Create a new owned memory.
    pub fn new_owned() -> Self {
        Self::Owned { memory: PagedMemory::default() }
    }

    /// Create a new cow memory.
    pub fn new_cow(original: PagedMemory<T>) -> Self {
        Self::Cow { copy: PagedMemory::default(), original }
    }

    /// Initialize the cow memory.
    ///
    /// If the memory is already in COW mode, this is a no-op.
    pub fn copy_on_write(&mut self) {
        match self {
            Self::Cow { .. } => {}
            Self::Owned { memory } => {
                *self = Self::new_cow(std::mem::take(memory));
            }
        }
    }

    /// Convert the memory to owned mode, discarding any of the memory in the COW.
    pub fn owned(&mut self) {
        match self {
            Self::Cow { copy: _, original } => {
                *self = Self::Owned { memory: std::mem::take(original) };
            }
            Self::Owned { .. } => {}
        }
    }

    /// Get a value from the memory.
    pub fn get(&self, addr: u64) -> Option<&T> {
        assert!(addr.is_multiple_of(8), "Address must be a multiple of 8");

        match self {
            Self::Cow { copy, original } => copy.get(addr).or_else(|| original.get(addr)),
            Self::Owned { memory } => memory.get(addr),
        }
    }

    /// Get an entry for the given address.
    pub fn entry(&mut self, addr: u64) -> Entry<'_, T> {
        assert!(addr.is_multiple_of(8), "Address must be a multiple of 8");

        // First we ensure that the copy has the value, if it exisits in the original.
        match self {
            Self::Cow { copy, original } => match copy.entry(addr) {
                Entry::Vacant(entry) => {
                    if let Some(value) = original.get(addr) {
                        entry.insert(*value);
                    }
                }
                Entry::Occupied(_) => {}
            },
            Self::Owned { .. } => {}
        }

        match self {
            Self::Cow { copy, original: _ } => copy.entry(addr),
            Self::Owned { memory } => memory.entry(addr),
        }
    }

    /// Insert a value into the memory.
    pub fn insert(&mut self, addr: u64, value: T) -> Option<T> {
        assert!(addr.is_multiple_of(8), "Address must be a multiple of 8");

        match self {
            Self::Cow { copy, original: _ } => copy.insert(addr, value),
            Self::Owned { memory } => memory.insert(addr, value),
        }
    }
}
