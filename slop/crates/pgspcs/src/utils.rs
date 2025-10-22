use slop_algebra::Field;

pub fn vector_to_bit_matrix<'a, F: Field>(
    input: impl IntoIterator<Item = &'a usize>,
    k: usize,
    n: usize,
) -> Vec<Vec<F>> {
    let mut matrix = vec![vec![F::zero(); k]; n];

    for (j, value) in input.into_iter().enumerate() {
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            // Extract the (n - 1 - i)-th bit (MSB first)
            matrix[i][j] = F::from_canonical_u8(((value >> (n - 1 - i)) & 1) as u8);
        }
    }

    matrix
}
