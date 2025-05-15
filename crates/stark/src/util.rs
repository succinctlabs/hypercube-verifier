use p3_field::Field;
use slop_merkle_tree::my_bb_16_perm;

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
    let inverse_nonzero_values = p3_field::batch_multiplicative_inverse(&nonzero_values);

    // Reconstruct the original vector.
    for (i, index) in indices.into_iter().enumerate() {
        values[index] = inverse_nonzero_values[i];
    }
}

/// Compute the ceiling of the base-2 logarithm of a number.
#[must_use]
pub fn log2_ceil_usize(n: usize) -> usize {
    n.next_power_of_two().ilog2() as usize
}

/// Get the inner perm
#[must_use]
pub fn inner_perm() -> slop_merkle_tree::Perm {
    my_bb_16_perm()
}
