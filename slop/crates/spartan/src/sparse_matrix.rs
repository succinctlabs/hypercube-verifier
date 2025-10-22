use std::ops::{Mul, Range};

use slop_algebra::{ExtensionField, Field};
use slop_pgspcs::sparse_poly::SparsePolynomial;

/// A sparse matrix with interned field elements
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMatrix<F> {
    /// The number of rows in the matrix.
    pub num_rows: usize,

    /// The number of columns in the matrix.
    pub num_cols: usize,

    // List of indices in `col_indices` such that the column index is the start of a new row.
    pub new_row_indices: Vec<u32>,

    // List of column indices that have values
    pub col_indices: Vec<u32>,

    // List of values
    pub values: Vec<F>,
}

impl<F> SparseMatrix<F>
where
    F: Clone,
{
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            num_rows: rows,
            num_cols: cols,
            new_row_indices: vec![0; rows],
            col_indices: Vec::new(),
            values: Vec::new(),
        }
    }

    pub fn num_entries(&self) -> usize {
        self.values.len()
    }

    pub fn grow(&mut self, rows: usize, cols: usize) {
        // TODO: Make it default infinite size instead.
        assert!(rows >= self.num_rows);
        assert!(cols >= self.num_cols);
        self.num_rows = rows.next_power_of_two();
        self.num_cols = cols;
        self.new_row_indices.resize(self.num_rows, self.values.len() as u32);
    }

    pub fn pad_rows(&mut self) {
        self.grow(self.num_rows, self.num_cols);
    }

    /// Set the value at the given row and column.
    pub fn set(&mut self, row: usize, col: usize, value: F) {
        assert!(row < self.num_rows, "row index out of bounds");
        assert!(col < self.num_cols, "column index out of bounds");

        // Find the row
        let row_range = self.row_range(row);
        let cols = &self.col_indices[row_range.clone()];

        // Find the column
        match cols.binary_search(&(col as u32)) {
            Ok(i) => {
                // Column already exists
                self.values[row_range][i] = value;
            }
            Err(i) => {
                // Need to insert column at i
                let i = i + row_range.start;
                self.col_indices.insert(i, col as u32);
                self.values.insert(i, value);
                for index in &mut self.new_row_indices[row + 1..] {
                    *index += 1;
                }
            }
        }
    }

    /// Iterate over the non-default entries of a row of the matrix.
    pub fn iter_row(&self, row: usize) -> impl Iterator<Item = (usize, F)> + '_ {
        let row_range = self.row_range(row);
        let cols = self.col_indices[row_range.clone()].iter().copied();
        let values = self.values[row_range].iter().cloned();
        cols.zip(values).map(|(col, value)| (col as usize, value))
    }

    /// Iterate over the non-default entries of the matrix.
    pub fn iter(&self) -> impl Iterator<Item = ((usize, usize), F)> + '_ {
        (0..self.new_row_indices.len())
            .flat_map(|row| self.iter_row(row).map(move |(col, value)| ((row, col), value)))
    }

    fn row_range(&self, row: usize) -> Range<usize> {
        let start = *self.new_row_indices.get(row).expect("Row index out of bounds") as usize;
        let end = self.new_row_indices.get(row + 1).map_or(self.values.len(), |&v| v as usize);
        start..end
    }
}

impl<F: Field> SparseMatrix<F> {
    /// Convert the sparse matrix into a sparse polynomial representation.
    pub fn to_sparse_polynomial(&self) -> SparsePolynomial<F> {
        let row_bits = self.num_rows.next_power_of_two().ilog2();
        let col_bits = self.num_cols.next_power_of_two().ilog2();
        let total_bits = (row_bits + col_bits) as usize;

        let values: Vec<(usize, F)> = self
            .iter()
            .map(|((row, col), val)| {
                let index = (row << col_bits) | col; // bin(row) || bin(col)
                (index, val)
            })
            .collect();

        SparsePolynomial::new(values, total_bits)
    }
}

/// Right multiplication by vector
///
/// TODO: Parallelize
impl<F, EF> Mul<&[EF]> for &SparseMatrix<F>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type Output = Vec<EF>;

    fn mul(self, rhs: &[EF]) -> Self::Output {
        assert_eq!(self.num_cols, rhs.len(), "Vector length does not match number of columns.");
        let mut result = vec![EF::zero(); self.num_rows];
        for ((i, j), value) in self.iter() {
            result[i] += EF::from_base(value) * rhs[j];
        }
        result
    }
}

/// Left multiplication by vector
// OPT: Paralelize
impl<F, EF> Mul<&SparseMatrix<F>> for &[EF]
where
    F: Field,
    EF: ExtensionField<F>,
{
    type Output = Vec<EF>;

    fn mul(self, rhs: &SparseMatrix<F>) -> Self::Output {
        assert_eq!(self.len(), rhs.num_rows, "Vector length does not match number of rows.");
        let mut result = vec![EF::zero(); rhs.num_cols];
        for ((i, j), value) in rhs.iter() {
            result[j] += self[i] * value;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use slop_algebra::AbstractExtensionField;

    #[tokio::test]
    async fn test_matrix_to_polynomial_consistency() {
        use super::*;
        use rand::Rng;
        use slop_algebra::extension::BinomialExtensionField;
        use slop_baby_bear::BabyBear;
        use slop_multilinear::Point;

        type F = BabyBear;
        type EF = BinomialExtensionField<BabyBear, 4>;

        // Matrix dimensions
        let num_rows = 4;
        let num_cols = 8;
        let mut matrix = SparseMatrix::<F>::new(num_rows, num_cols);

        // Populate the matrix with some random entries
        let mut rng = rand::thread_rng();
        for row in 0..num_rows {
            for col in 0..num_cols {
                if rng.gen_bool(0.2) {
                    matrix.set(row, col, rng.gen());
                }
            }
        }

        // Convert the matrix into a sparse polynomial
        let poly = matrix.to_sparse_polynomial();

        // Build the input point: binary encoding of (row || col)
        let col_bits = num_cols.next_power_of_two().ilog2();
        let total_bits = (num_rows * num_cols).next_power_of_two().ilog2() as usize;

        // For each matrix entry (row, col), compare direct value with polynomial eval
        for ((row, col), value) in matrix.iter() {
            let index = (row << col_bits) | col;
            let point = Point::<EF>::from_usize(index, total_bits);

            // Evaluate the polynomial at this binary point
            let eval = poly.eval_at(&point);

            // Should match the original matrix value
            assert_eq!(eval, EF::from_base(value), "Mismatch at row={row}, col={col}");
        }
    }
}
