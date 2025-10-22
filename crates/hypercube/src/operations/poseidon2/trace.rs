//! Trace (witness) population functions for the Poseidon2 operation.

use std::borrow::Borrow;

use slop_algebra::PrimeField32;
use slop_koala_bear::{
    KoalaBear_BEGIN_EXT_CONSTS, KoalaBear_END_EXT_CONSTS, KoalaBear_PARTIAL_CONSTS,
};

use super::{
    air::{external_linear_layer, external_linear_layer_mut, internal_linear_layer_mut},
    permutation::permutation_mut,
    Poseidon2Operation, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_POSEIDON2_OPERATION_COLUMNS,
    WIDTH,
};

/// Populate a degree 3 `Poseidon2Operation`.
pub fn populate_perm_deg3<F: PrimeField32>(
    input: [F; WIDTH],
    expected_output: Option<[F; WIDTH]>,
) -> Poseidon2Operation<F> {
    let mut row: Vec<F> = vec![F::zero(); NUM_POSEIDON2_OPERATION_COLUMNS];
    populate_perm::<F, 3>(input, expected_output, row.as_mut_slice());
    let op: &Poseidon2Operation<F> = row.as_slice().borrow();
    *op
}

/// Populate a Poseidon2 AIR row.
pub fn populate_perm<F: PrimeField32, const DEGREE: usize>(
    input: [F; WIDTH],
    expected_output: Option<[F; WIDTH]>,
    input_row: &mut [F],
) {
    {
        let permutation = permutation_mut::<F, DEGREE>(input_row);

        let (external_rounds_state, internal_rounds_state, internal_rounds_s0, output_state) =
            permutation.get_cols_mut();

        external_rounds_state[0] = input;

        // Apply the first half of external rounds.
        for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
            let next_state = populate_external_round::<F, DEGREE>(external_rounds_state, r);
            if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
                *internal_rounds_state = next_state;
            } else {
                external_rounds_state[r + 1] = next_state;
            }
        }

        // Apply the internal rounds.
        external_rounds_state[NUM_EXTERNAL_ROUNDS / 2] =
            populate_internal_rounds(internal_rounds_state, internal_rounds_s0);

        // Apply the second half of external rounds.
        for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
            let next_state = populate_external_round::<F, DEGREE>(external_rounds_state, r);
            if r == NUM_EXTERNAL_ROUNDS - 1 {
                for i in 0..WIDTH {
                    output_state[i] = next_state[i];
                    if let Some(expected_output) = expected_output {
                        assert_eq!(expected_output[i], next_state[i]);
                    }
                }
            } else {
                external_rounds_state[r + 1] = next_state;
            }
        }
    }
}

/// Populate the `r`th external round.
pub fn populate_external_round<F: PrimeField32, const DEGREE: usize>(
    external_rounds_state: &[[F; WIDTH]],
    r: usize,
) -> [F; WIDTH] {
    let mut state = {
        // For the first round, apply the linear layer.
        let round_state: &[F; WIDTH] = if r == 0 {
            &external_linear_layer(&external_rounds_state[r])
        } else {
            &external_rounds_state[r]
        };

        // Add round constants.
        //
        // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
        // columns for it, and instead include it in the constraint for the x^3 part of the
        // sbox.
        let mut add_rc = *round_state;
        for i in 0..WIDTH {
            add_rc[i] += if r < NUM_EXTERNAL_ROUNDS / 2 {
                F::from_canonical_u32(KoalaBear_BEGIN_EXT_CONSTS[r][i].as_canonical_u32())
            } else {
                F::from_canonical_u32(
                    KoalaBear_END_EXT_CONSTS[r - NUM_EXTERNAL_ROUNDS / 2][i].as_canonical_u32(),
                )
            };
        }

        // Apply the sboxes.
        // Optimization: since the linear layer that comes after the sbox is degree 1, we can
        // avoid adding columns for the result of the sbox, and instead include the x^3 -> x^7
        // part of the sbox in the constraint for the linear layer
        let mut sbox_deg_3: [F; 16] = [F::zero(); WIDTH];
        for i in 0..WIDTH {
            sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
        }

        sbox_deg_3
    };

    // Apply the linear layer.
    external_linear_layer_mut(&mut state);
    state
}

/// Populate all internal rounds.
pub fn populate_internal_rounds<F: PrimeField32>(
    internal_rounds_state: &[F; WIDTH],
    internal_rounds_s0: &mut [F; NUM_INTERNAL_ROUNDS - 1],
) -> [F; WIDTH] {
    let mut state: [F; WIDTH] = *internal_rounds_state;
    for r in 0..NUM_INTERNAL_ROUNDS {
        // Add the round constant to the 0th state element.
        // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
        // columns for it, just like for external rounds.
        let add_rc =
            state[0] + F::from_canonical_u32(KoalaBear_PARTIAL_CONSTS[r].as_canonical_u32());

        // Apply the sboxes.
        // Optimization: since the linear layer that comes after the sbox is degree 1, we can
        // avoid adding columns for the result of the sbox, just like for external rounds.
        let sbox_deg_3 = add_rc * add_rc * add_rc;

        // Apply the linear layer.
        state[0] = sbox_deg_3;
        internal_linear_layer_mut(&mut state);

        // Optimization: since we're only applying the sbox to the 0th state element, we only
        // need to have columns for the 0th state element at every step. This is because the
        // linear layer is degree 1, so all state elements at the end can be expressed as a
        // degree-3 polynomial of the state at the beginning of the internal rounds and the 0th
        // state element at rounds prior to the current round
        if r < NUM_INTERNAL_ROUNDS - 1 {
            internal_rounds_s0[r] = state[0];
        }
    }

    state
}
