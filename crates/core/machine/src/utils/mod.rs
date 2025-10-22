pub mod concurrency;
mod logger;
mod prove;
mod span;
#[cfg(test)]
mod test;
mod zerocheck_unit_test;

pub use logger::*;
pub use prove::*;
use slop_algebra::{AbstractField, Field};
pub use span::*;
#[cfg(test)]
pub use test::*;
pub use zerocheck_unit_test::*;

use slop_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use sp1_hypercube::{air::SP1AirBuilder, Word};
use sp1_primitives::consts::WORD_BYTE_SIZE;
pub use sp1_primitives::consts::{
    bytes_to_words_le, bytes_to_words_le_vec, num_to_comma_separated, words_to_bytes_le,
    words_to_bytes_le_vec,
};

pub use sp1_hypercube::{indices_arr, next_multiple_of_32, pad_rows_fixed};

pub fn limbs_to_words<AB: SP1AirBuilder>(limbs: Vec<AB::Var>) -> Vec<Word<AB::Expr>> {
    let base = AB::Expr::from_canonical_u32(1 << 8);
    let result_words: Vec<Word<AB::Expr>> = limbs
        .chunks_exact(WORD_BYTE_SIZE)
        .map(|l| {
            Word([
                l[0] + l[1] * base.clone(),
                l[2] + l[3] * base.clone(),
                l[4] + l[5] * base.clone(),
                l[6] + l[7] * base.clone(),
            ])
        })
        .collect();
    result_words
}

pub fn u32_to_half_word<F: Field>(value: u32) -> [F; 2] {
    [F::from_canonical_u16((value & 0xFFFF) as u16), F::from_canonical_u16((value >> 16) as u16)]
}

pub fn chunk_vec<T>(mut vec: Vec<T>, chunk_size: usize) -> Vec<Vec<T>> {
    let mut result = Vec::new();
    while !vec.is_empty() {
        let current_chunk_size = std::cmp::min(chunk_size, vec.len());
        let current_chunk = vec.drain(..current_chunk_size).collect::<Vec<T>>();
        result.push(current_chunk);
    }
    result
}

#[inline]
pub fn log2_strict_usize(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert_eq!(n.wrapping_shr(res), 1, "Not a power of two: {n}");
    res as usize
}

pub fn par_for_each_row<P, F>(vec: &mut [F], num_elements_per_event: usize, processor: P)
where
    F: Send,
    P: Fn(usize, &mut [F]) + Send + Sync,
{
    // Split the vector into `num_cpus` chunks, but at least `num_cpus` rows per chunk.
    assert!(vec.len().is_multiple_of(num_elements_per_event));
    let len = vec.len() / num_elements_per_event;
    let cpus = num_cpus::get();
    let ceil_div = len.div_ceil(cpus);
    let chunk_size = std::cmp::max(ceil_div, cpus);

    vec.chunks_mut(chunk_size * num_elements_per_event).enumerate().par_bridge().for_each(
        |(i, chunk)| {
            chunk.chunks_mut(num_elements_per_event).enumerate().for_each(|(j, row)| {
                assert!(row.len() == num_elements_per_event);
                processor(i * chunk_size + j, row);
            });
        },
    );
}

/// Returns whether the `SP1_DEBUG` environment variable is enabled or disabled.
///
/// This variable controls whether backtraces are attached to compiled circuit programs, as well
/// as whether cycle tracking is performed for circuit programs.
///
/// By default, the variable is disabled.
pub fn sp1_debug_mode() -> bool {
    let value = std::env::var("SP1_DEBUG").unwrap_or_else(|_| "false".to_string());
    value == "1" || value.to_lowercase() == "true"
}

/// Returns a vector of zeros of the given length. This is faster than vec![F::zero(); len] which
/// requires copying.
///
/// This function is safe to use only for fields that can be transmuted from 0u32.
pub fn zeroed_f_vec<F: Field>(len: usize) -> Vec<F> {
    debug_assert!(std::mem::size_of::<F>() == 4);

    let vec = vec![0u32; len];
    unsafe { std::mem::transmute::<Vec<u32>, Vec<F>>(vec) }
}

/// Reverse the bits of an integer within a specified bit length.
///
/// Takes an integer `x` and reverses its bits within the least significant `bit_len` bits.
/// For example, reverse_bits_len(0b101, 3) = 0b101 (reversed) = 0b101.
/// reverse_bits_len(0b001, 3) = 0b100.
pub fn reverse_bits_len(x: usize, bit_len: usize) -> usize {
    let mut result = 0;
    let mut x = x;
    for _ in 0..bit_len {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

/// Reverse the order of elements in a slice using bit-reversed indices.
///
/// This function reorders the elements of a slice such that the element at index `i`
/// is moved to index `reverse_bits_len(i, log2(len))`.
pub fn reverse_slice_index_bits<T>(slice: &mut [T]) {
    let n = slice.len();
    assert!(n.is_power_of_two(), "Slice length must be a power of two");
    let log_n = log2_strict_usize(n);

    for i in 0..n {
        let j = reverse_bits_len(i, log_n);
        if i < j {
            slice.swap(i, j);
        }
    }
}
