use slop_algebra::Field;
use sp1_primitives::{poseidon2_init, SP1Perm};

/// The digest size.
pub const DIGEST_SIZE: usize = 8;

/// An implementation of `batch_multiplicative_inverse` that operates in place.
#[allow(dead_code)]
pub fn batch_multiplicative_inverse_inplace<F: Field>(values: &mut [F]) {
    // Check if values are zero and construct a new vector with only nonzero values.
    let mut nonzero_values = Vec::with_capacity(values.len());
    let mut indices = Vec::with_capacity(values.len());
    for (i, value) in values.iter().copied().enumerate() {
        if value.is_zero() {
            continue;
        }
        nonzero_values.push(value);
        indices.push(i);
    }

    // Compute the multiplicative inverse of nonzero values.
    let inverse_nonzero_values = slop_algebra::batch_multiplicative_inverse(&nonzero_values);

    // Reconstruct the original vector.
    for (i, index) in indices.into_iter().enumerate() {
        values[index] = inverse_nonzero_values[i];
    }
}

/// Compute the ceiling of the base-2 logarithm of a number.
#[must_use]
pub fn log2_ceil_usize(n: usize) -> usize {
    // println!("n: {}", n);
    n.next_power_of_two().ilog2() as usize
}

/// Get the inner perm
#[must_use]
pub fn inner_perm() -> SP1Perm {
    poseidon2_init()
}

/// Get an array `xs` such that `xs[i] = i`.
#[must_use]
pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

/// Pad to the next multiple of 32, with an option to specify the fixed height.
//
// The `rows` argument represents the rows of a matrix stored in row-major order. The function will
// pad the rows using `row_fn` to create the padded rows. The padding will be to the next multiple
// of 32 if `height` is `None`, or to the specified `height` if it is not `None`. The
// function will panic of the number of rows is larger than the specified `height`.
pub fn pad_rows_fixed<R: Clone>(rows: &mut Vec<R>, row_fn: impl Fn() -> R, height: Option<usize>) {
    let nb_rows = rows.len();
    let dummy_row = row_fn();
    rows.resize(next_multiple_of_32(nb_rows, height), dummy_row);
}

/// Returns the internal value of the option if it is set, otherwise returns the next multiple of
/// 32.
#[track_caller]
#[inline]
#[allow(clippy::uninlined_format_args)]
#[must_use]
pub fn next_multiple_of_32(n: usize, fixed_height: Option<usize>) -> usize {
    if let Some(height) = fixed_height {
        if n > height {
            panic!("fixed height is too small: got height {} for number of rows {}", height, n);
        }
        height
    } else {
        n.next_multiple_of(32).max(16)
    }
}
