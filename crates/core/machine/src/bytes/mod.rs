pub mod air;
pub mod columns;
pub mod trace;

use sp1_core_executor::ByteOpcode;

use core::borrow::BorrowMut;
use std::marker::PhantomData;

use itertools::Itertools;
use slop_algebra::Field;
use slop_matrix::dense::RowMajorMatrix;

use self::columns::{BytePreprocessedCols, NUM_BYTE_PREPROCESSED_COLS};
use crate::{bytes::trace::NUM_ROWS, utils::zeroed_f_vec};

/// The number of different byte operations in the byte table.
pub const NUM_BYTE_OPS: usize = 6;

/// A chip for computing byte operations.
///
/// The chip contains a preprocessed table of all possible byte operations. Other chips can then
/// use lookups into this table to compute their own operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct ByteChip<F>(PhantomData<F>);

impl<F: Field> ByteChip<F> {
    /// Creates the preprocessed byte trace.
    ///
    /// This function returns a `trace` which is a matrix containing all possible byte operations.
    pub fn trace() -> RowMajorMatrix<F> {
        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace = RowMajorMatrix::new(
            zeroed_f_vec(NUM_ROWS * NUM_BYTE_PREPROCESSED_COLS),
            NUM_BYTE_PREPROCESSED_COLS,
        );

        // Record all the necessary operations for each byte lookup.
        let opcodes = ByteOpcode::byte_table();

        // Iterate over all options for pairs of bytes `a` and `b`.
        for (row_index, (b, c)) in (0..=u8::MAX).cartesian_product(0..=u8::MAX).enumerate() {
            let b = b as u8;
            let c = c as u8;
            let col: &mut BytePreprocessedCols<F> = initial_trace.row_mut(row_index).borrow_mut();

            // Set the values of `b` and `c`.
            col.b = F::from_canonical_u8(b);
            col.c = F::from_canonical_u8(c);

            // Iterate over all operations for results and updating the table map.
            for opcode in opcodes.iter() {
                match opcode {
                    ByteOpcode::AND => {
                        let and = b & c;
                        col.and = F::from_canonical_u8(and);
                    }
                    ByteOpcode::OR => {
                        let or = b | c;
                        col.or = F::from_canonical_u8(or);
                    }
                    ByteOpcode::XOR => {
                        let xor = b ^ c;
                        col.xor = F::from_canonical_u8(xor);
                    }
                    ByteOpcode::U8Range => {}
                    ByteOpcode::LTU => {
                        let ltu = b < c;
                        col.ltu = F::from_bool(ltu);
                    }
                    ByteOpcode::MSB => {
                        let msb = (b & 0b1000_0000) != 0;
                        col.msb = F::from_bool(msb);
                    }
                    _ => panic!("invalid opcode found in byte table"),
                };
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
        ByteChip::<SP1Field>::trace();
        println!("trace and map: {:?}", start.elapsed());
    }
}
