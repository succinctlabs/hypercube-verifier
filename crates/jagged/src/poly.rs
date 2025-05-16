//! This module contains the implementation of the special multilinear polynomial appearing in the
//! jagged sumcheck protocol.
//!
//! More precisely, given a collection of L tables with areas [a_1, a_2, ..., a_L] and column counts
//! [c_1, c_2, ..., c_L], lay out those tables in a 3D array, aligning their top-left corners. Then,
//! imagine padding all the tables with zeroes so that the have the same number of rows. On the other
//! hand, imagine laying out all the tables (considered in RowMajor form) in a single long vector.
//! The jagged multilinear polynomial is the multilinear extension of the function which determines,
//! given a table, row, and column index in the 3D array, and an index in the long vector, whether
//! the index in the long vector corresponds to the table, row, and column index in the 3D array.
//! More explicitly, it's the function checking whether
//!
//! index = (a_1 + ... + a_{tab}) + row * c_{tab} + col.
//!
//! Since there is an efficient algorithm to implement this "indicator" function as a branching
//! program, following [HR18](https://eccc.weizmann.ac.il/report/2018/161/) there is a concise
//! algorithm for the evaluation of the corresponding multilinear polynomial. The algorithm to
//! compute the indicator uses the prefix sums [t_0=0, t_1=a_1, t_2 = a_1+a_2, ..., t_L], reads
//! t_{tab}, t_{tab+1}, index, tab, row, and col bit-by-bit from LSB to MSB, checks the equality
//! above, and also checks that index < t_{tab+1}. Assuming that c_{tab} is a power of 2, the
//! multiplication `row * c_{tab}` can be done by bit-shift, and the addition is checked via the
//! grade-school algorithm.
use core::fmt;
use std::array;

use rayon::prelude::*;

use p3_field::{AbstractExtensionField, AbstractField};
use rayon::iter::ParallelIterator;
use serde::{Deserialize, Serialize};

use slop_multilinear::{Mle, Point};

/// A struct recording the state of the memory of the branching program. Because the program performs
/// a two-way addition and one u32 comparison, the memory needed is a carry (which lies in {0,1})
/// and a boolean to store the comparison of the u32s up to the current bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemoryState {
    pub carry: bool,

    pub comparison_so_far: bool,
}

impl fmt::Display for MemoryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "COMPARISON_SO_FAR_{}__CARRY_{}",
            self.comparison_so_far as usize, self.carry as usize
        )
    }
}

impl MemoryState {
    pub fn get_index(&self) -> usize {
        (self.carry as usize) + ((self.comparison_so_far as usize) << 1)
    }
}

impl MemoryState {
    /// The memory state which indicates success in the last layer of the branching program.
    fn success() -> Self {
        MemoryState { carry: false, comparison_so_far: true }
    }

    fn initial_state() -> Self {
        MemoryState { carry: false, comparison_so_far: false }
    }
}

/// An enum to represent a potentially failed computation at a layer of the branching program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StateOrFail {
    State(MemoryState),
    Fail,
}

impl fmt::Display for StateOrFail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateOrFail::State(memory_state) => write!(f, "{}", memory_state),
            StateOrFail::Fail => write!(f, "FAIL"),
        }
    }
}

/// A struct representing the four bits the branching program needs to read in order to go to the next
/// layer of the program. The program streams the bits of the row, column, index, and the
/// "table area prefix sum".
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BitState<T> {
    pub row_bit: T,
    pub index_bit: T,
    pub curr_col_prefix_sum_bit: T,
    pub next_col_prefix_sum_bit: T,
}

/// Enumerate all the possible memory states.
pub fn all_memory_states() -> Vec<MemoryState> {
    (0..2)
        .flat_map(|comparison_so_far| {
            (0..2).map(move |carry| MemoryState {
                carry: carry != 0,
                comparison_so_far: comparison_so_far != 0,
            })
        })
        .collect()
}

/// Enumerate all the possible bit states.
pub fn all_bit_states() -> Vec<BitState<bool>> {
    (0..2)
        .flat_map(|row_bit| {
            (0..2).flat_map(move |index_bit| {
                (0..2).flat_map(move |last_col_bit| {
                    (0..2).map(move |curr_col_bit| BitState {
                        row_bit: row_bit != 0,
                        index_bit: index_bit != 0,
                        curr_col_prefix_sum_bit: last_col_bit != 0,
                        next_col_prefix_sum_bit: curr_col_bit != 0,
                    })
                })
            })
        })
        .collect()
}

/// The transition function that determines the next memory state given the current memory state and
/// the current bits being read. The branching program reads bits from LSB to MSB.
pub fn transition_function(bit_state: BitState<bool>, memory_state: MemoryState) -> StateOrFail {
    // If the current (most significant bit read so far) index_bit matches the current next_tab_bit,
    // then defer to the comparison so far. Otherwise, the comparison is correct only if
    // `next_tab_bit` is 1 and `index_bit` is 0.
    let new_comparison_so_far = if bit_state.index_bit == bit_state.next_col_prefix_sum_bit {
        memory_state.comparison_so_far
    } else {
        bit_state.next_col_prefix_sum_bit
    };

    // Compute the carry according to the logic of three-way addition, or fail if the current bits
    // are not consistent with the three-way addition.
    //
    // However, we are checking that index = curr_tab + row * (1<<log_column_count) + col, so we
    // need to read the row bit only if the layer is after log_column_count.
    let new_carry = {
        if (bit_state.index_bit as usize)
            != ((bit_state.row_bit as usize)
                + Into::<usize>::into(memory_state.carry)
                + bit_state.curr_col_prefix_sum_bit as usize)
                & 1
        {
            return StateOrFail::Fail;
        }
        (bit_state.row_bit as usize
            + Into::<usize>::into(memory_state.carry)
            + bit_state.curr_col_prefix_sum_bit as usize)
            >> 1
    };
    // Successful transition.
    StateOrFail::State(MemoryState {
        carry: new_carry != 0,
        comparison_so_far: new_comparison_so_far,
    })
}

/// A struct to hold all the parameters sufficient to determine the special multilinear polynopmial
/// appearing in the jagged sumcheck protocol. All usize parameters are intended to be inferred from
/// the proving context, while the `Vec<Point<K>>` fields are intended to be recieved directly from
/// the prover as field elements. The verifier program thus depends only on the usize parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JaggedLittlePolynomialVerifierParams<K> {
    pub col_prefix_sums: Vec<Point<K>>,
    pub max_log_row_count: usize,
}

impl<F: AbstractField + 'static + Send + Sync> JaggedLittlePolynomialVerifierParams<F> {
    /// Given `z_index`, evaluate the special multilinear polynomial appearing in the jagged sumcheck
    /// protocol.
    pub fn full_jagged_little_polynomial_evaluation<
        EF: AbstractExtensionField<F> + 'static + Send + Sync,
    >(
        &self,
        z_row: &Point<EF>,
        z_col: &Point<EF>,
        z_index: &Point<EF>,
    ) -> (EF, Vec<EF>) {
        let z_col_partial_lagrange = Mle::blocking_partial_lagrange(z_col);
        let z_col_partial_lagrange = z_col_partial_lagrange.guts().as_slice();

        // The program below reads only the first log_m +1 bits of z_row, but z_row could in theory
        // be longer than that if the total trace area is less than the padded height. This
        // correction ensures that the higher bits are zero.
        let log_m = z_index.dimension();
        let z_row_correction: EF = z_row
            .reversed()
            .to_vec()
            .iter()
            .skip(log_m + 1)
            .cloned()
            .map(|x| EF::one() - x)
            .product();

        let branching_program = BranchingProgram::new(z_row.clone(), z_index.clone());

        // Iterate over all column. For each column, we need to know the total length of all the columns
        // up to the current one, this number - 1, and the
        // number of rows in the current column.
        let mut branching_program_evals = Vec::with_capacity(self.col_prefix_sums.len() - 1);
        #[allow(clippy::uninit_vec)]
        unsafe {
            branching_program_evals.set_len(self.col_prefix_sums.len() - 1);
        }
        let next_col_prefix_sums = self.col_prefix_sums.iter().skip(1);
        let res = self
            .col_prefix_sums
            .iter()
            .zip(next_col_prefix_sums)
            .zip(branching_program_evals.iter_mut())
            .enumerate()
            .par_bridge()
            .map(|(col_num, ((prefix_sum, next_prefix_sum), branching_program_eval))| {
                // For `z_col` on the Boolean hypercube, this is the delta function to pick out
                // the right column count for the current table.
                let c_tab_correction = z_col_partial_lagrange[col_num].clone();

                let prefix_sum_ef =
                    prefix_sum.iter().map(|x| EF::from(x.clone())).collect::<Point<EF>>();
                let next_prefix_sum_ef =
                    next_prefix_sum.iter().map(|x| EF::from(x.clone())).collect::<Point<EF>>();
                *branching_program_eval =
                    branching_program.eval(&prefix_sum_ef, &next_prefix_sum_ef);

                // Perform the multiplication outside of the main loop to avoid redundant
                // multiplications.
                z_row_correction.clone() * c_tab_correction.clone() * branching_program_eval.clone()
            })
            .sum::<EF>();

        (res, branching_program_evals)
    }
}

#[derive(Debug, Clone, Default)]
pub struct BranchingProgram<K: AbstractField> {
    z_row: Point<K>,
    z_index: Point<K>,
    memory_states: Vec<MemoryState>,
    bit_states: Vec<BitState<bool>>,
    pub(crate) num_vars: usize,
}

impl<K: AbstractField + 'static> BranchingProgram<K> {
    pub fn new(z_row: Point<K>, z_index: Point<K>) -> Self {
        let log_m = z_index.dimension();

        Self {
            z_row,
            z_index,
            memory_states: all_memory_states(),
            bit_states: all_bit_states(),
            num_vars: log_m,
        }
    }

    pub fn eval(&self, prefix_sum: &Point<K>, next_prefix_sum: &Point<K>) -> K {
        let mut state_by_state_results: [K; 4] = array::from_fn(|_| K::zero());
        state_by_state_results[MemoryState::success().get_index()] = K::one();

        // The dynamic programming algorithm to output the result of the branching
        // iterates over the layers of the branching program in reverse order.
        for layer in (0..self.num_vars + 1).rev() {
            let mut new_state_by_state_results: [K; 4] =
                [K::zero(), K::zero(), K::zero(), K::zero()];

            // We assume that bits are aligned in big-endian order. The algorithm,
            // in the ith layer, looks at the ith least significant bit, which is
            // the m - 1 - i th bit if the bits are in a bit array in big-endian.
            let point = [
                Self::get_ith_least_significant_val(&self.z_row, layer),
                Self::get_ith_least_significant_val(&self.z_index, layer),
                Self::get_ith_least_significant_val(prefix_sum, layer),
                Self::get_ith_least_significant_val(next_prefix_sum, layer),
            ]
            .into_iter()
            .collect::<Point<K>>();

            let four_var_eq: Mle<K> = Mle::blocking_partial_lagrange(&point);

            // For each memory state in the new layer, compute the result of the branching
            // program that starts at that memory state and in the current layer.

            for memory_state in &self.memory_states {
                // For each possible bit state, compute the result of the branching
                // program transition function and modify the accumulator accordingly.
                let mut accum_elems: [K; 4] = array::from_fn(|_| K::zero());

                for (i, elem) in four_var_eq.guts().as_slice().iter().enumerate() {
                    let bit_state = &self.bit_states[i];

                    let state_or_fail = transition_function(*bit_state, *memory_state);

                    if let StateOrFail::State(output_state) = state_or_fail {
                        accum_elems[output_state.get_index()] += elem.clone();
                    }
                    // If the state is a fail state, we don't need to add anything to the accumulator.
                }

                let accum = accum_elems.iter().zip(state_by_state_results.iter()).fold(
                    K::zero(),
                    |acc, (accum_elem, state_by_state_result)| {
                        acc + accum_elem.clone() * state_by_state_result.clone()
                    },
                );

                new_state_by_state_results[memory_state.get_index()] = accum;
            }
            state_by_state_results = new_state_by_state_results;
        }

        state_by_state_results[MemoryState::initial_state().get_index()].clone()
    }

    /// We assume that the point is in big-endian order.
    fn get_ith_least_significant_val(point: &Point<K>, i: usize) -> K {
        let dim = point.dimension();
        if dim <= i {
            K::zero()
        } else {
            point.get(dim - i - 1).expect("index out of bounds").clone()
        }
    }
}
