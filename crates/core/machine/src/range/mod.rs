pub mod air;
pub mod columns;
pub mod trace;

use core::borrow::BorrowMut;
use std::marker::PhantomData;

use slop_algebra::Field;
use slop_matrix::dense::RowMajorMatrix;

use self::columns::{RangePreprocessedCols, NUM_RANGE_PREPROCESSED_COLS};
use crate::{range::trace::NUM_ROWS, utils::zeroed_f_vec};

/// A chip for range checking a limb with maximum number of bits.
#[derive(Debug, Clone, Copy, Default)]
pub struct RangeChip<F>(PhantomData<F>);

impl<F: Field> RangeChip<F> {
    /// Creates the preprocessed range table trace.
    pub fn trace() -> RowMajorMatrix<F> {
        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace = RowMajorMatrix::new(
            zeroed_f_vec(NUM_ROWS * NUM_RANGE_PREPROCESSED_COLS),
            NUM_RANGE_PREPROCESSED_COLS,
        );

        // Set the first row to (0, 0).
        let col: &mut RangePreprocessedCols<F> = initial_trace.row_mut(0).borrow_mut();
        col.a = F::zero();
        col.bits = F::zero();

        // For `0 <= bits <= 16`, put `(a, bits)` with `0 <= a < 2^bits` into the trace.
        for bits in 0..=16u32 {
            for a in 0..(1u32 << bits) {
                let row_index = (1 << bits) + a;
                let col: &mut RangePreprocessedCols<F> =
                    initial_trace.row_mut(row_index as usize).borrow_mut();
                col.a = F::from_canonical_u32(a);
                col.bits = F::from_canonical_u32(bits);
            }
        }

        initial_trace
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use sp1_primitives::SP1Field;
    use std::time::Instant;

    use super::*;

    #[test]
    pub fn test_trace_and_map() {
        let start = Instant::now();
        RangeChip::<SP1Field>::trace();
        println!("trace and map: {:?}", start.elapsed());
    }
}
