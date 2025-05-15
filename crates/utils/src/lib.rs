mod logger;

pub use logger::setup_logger;

pub use p3_util::log2_ceil_usize;
pub use p3_util::log2_strict_usize;
pub use p3_util::reverse_bits_len;

pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

/// Returns the internal value of the option if it is set, otherwise returns the next multiple of
/// 32.
#[track_caller]
#[inline]
pub fn next_multiple_of_32(n: usize, fixed_height: Option<usize>) -> usize {
    match fixed_height {
        Some(height) => {
            if n > height {
                panic!("fixed height is too small: got height {} for number of rows {}", height, n);
            }
            height
        }
        None => {
            let mut padded_nb_rows = n.next_multiple_of(32);
            if padded_nb_rows < 16 {
                padded_nb_rows = 16;
            }
            padded_nb_rows
        }
    }
}
