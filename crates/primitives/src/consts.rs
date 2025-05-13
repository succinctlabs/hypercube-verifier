/// The maximum size of the memory in bytes.
pub const MAXIMUM_MEMORY_SIZE: u32 = u32::MAX;

/// The number of bits in a byte.
pub const BYTE_SIZE: usize = 8;

/// The size of a word in limbs.
pub const WORD_SIZE: usize = 2;

/// The size of a word in bytes.
pub const WORD_BYTE_SIZE: usize = 4;

/// The number of bytes necessary to represent a 64-bit integer.
pub const LONG_WORD_BYTE_SIZE: usize = 2 * WORD_BYTE_SIZE;

/// The Baby Bear prime.
pub const BABYBEAR_PRIME: u32 = 0x78000001;
