use hypercube_recursion_executor::DIGEST_SIZE;
use hypercube_stark::{log2_ceil_usize, BabyBearPoseidon2};
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use slop_alloc::CpuBackend;
use slop_basefold::{BasefoldConfig, BasefoldProof, Poseidon2BabyBear16BasefoldConfig};
use slop_commit::{Rounds, TensorCsOpening};
use slop_jagged::{JaggedLittlePolynomialVerifierParams, JaggedPcsProof, JaggedSumcheckEvalProof};
use slop_merkle_tree::MerkleTreeTcsProof;
use slop_multilinear::{Evaluations, Point};
use slop_stacked::StackedPcsProof;
use slop_tensor::Tensor;

use crate::machine::{InnerChallenge, InnerVal};

use super::sumcheck::dummy_sumcheck_proof;

pub fn dummy_hash() -> [BabyBear; DIGEST_SIZE] {
    [BabyBear::zero(); DIGEST_SIZE]
}

pub fn dummy_query_proof(
    max_height: usize,
    log_blowup: usize,
    num_queries: usize,
) -> Vec<TensorCsOpening<<Poseidon2BabyBear16BasefoldConfig as BasefoldConfig>::Tcs>> {
    // The outer Vec is an iteration over the commit-phase rounds, of which there should be
    // `log_max_height-1` (perhaps there's an off-by-one error here). The TensorCsOpening is
    // laid out so that the tensor shape is [num_queries, 8 (degree of extension field*folding
    // parameter)].
    (0..max_height)
        .map(|i| {
            let openings = Tensor::<BabyBear, _>::zeros_in([num_queries, 4 * 2], CpuBackend);
            let proof = Tensor::<[BabyBear; DIGEST_SIZE], _>::zeros_in(
                [num_queries, max_height - i + log_blowup - 1],
                CpuBackend,
            );

            TensorCsOpening { values: openings, proof: MerkleTreeTcsProof { paths: proof } }
        })
        .collect::<Vec<_>>()
    // QueryProof {
    //     commit_phase_openings: (0..height)
    //         .map(|i| CommitPhaseProofStep {
    //             sibling_value: InnerChallenge::zero(),
    //             opening_proof: vec![dummy_hash().into(); height - i + log_blowup - 1],
    //         })
    //         .collect(),
    // };
}

/// Make a dummy PCS proof for a given proof shape. Used to generate vkey information for fixed
/// proof shapes.
///
/// The parameter `batch_shapes` contains (width, height) data for each matrix in each batch.
pub fn dummy_pcs_proof(
    fri_queries: usize,
    log_stacking_height_multiples: &[usize],
    log_stacking_height: usize,
    log_blowup: usize,
    total_machine_cols: usize,
    max_log_row_count: usize,
) -> JaggedPcsProof<BabyBearPoseidon2> {
    let max_pcs_height = log_stacking_height;
    let dummy_component_polys = log_stacking_height_multiples.iter().map(|&x| {
        let proof = Tensor::<[BabyBear; DIGEST_SIZE], _>::zeros_in(
            [fri_queries, max_pcs_height + log_blowup],
            CpuBackend,
        );
        TensorCsOpening {
            values: Tensor::<BabyBear, _>::zeros_in([fri_queries, x], CpuBackend),
            proof: MerkleTreeTcsProof { paths: proof },
        }
    });
    let basefold_proof = BasefoldProof::<Poseidon2BabyBear16BasefoldConfig> {
        univariate_messages: vec![[InnerChallenge::zero(); 2]; max_pcs_height],
        fri_commitments: vec![dummy_hash(); max_pcs_height],
        final_poly: InnerChallenge::zero(),
        pow_witness: InnerVal::zero(),
        component_polynomials_query_openings: dummy_component_polys.collect(),
        query_phase_openings: dummy_query_proof(max_pcs_height, log_blowup, fri_queries),
    };

    let batch_evaluations: Rounds<Evaluations<InnerChallenge, CpuBackend>> = Rounds {
        rounds: log_stacking_height_multiples
            .iter()
            .map(|&x| Evaluations {
                round_evaluations: vec![vec![InnerChallenge::zero(); x].into()],
            })
            .collect(),
    };

    let stacked_proof = StackedPcsProof { pcs_proof: basefold_proof, batch_evaluations };

    let total_num_variables = log2_ceil_usize(
        log_stacking_height_multiples.iter().sum::<usize>() * (1 << log_stacking_height),
    );

    // Add 2 because of the dummy columns after the preprocessed and main rounds, and then one more
    // because the prefix sums start at 0 and end at total trace area (so there is one more prefix
    // sum than the number of columns).
    let col_prefix_sums = (0..total_machine_cols + 3)
        .map(|_| Point::<InnerVal>::from_usize(0, total_num_variables + 1))
        .collect::<Vec<_>>();

    let jagged_params = JaggedLittlePolynomialVerifierParams { col_prefix_sums, max_log_row_count };

    let partial_sumcheck_proof = dummy_sumcheck_proof(total_num_variables, 2);

    // Add 2 because the there is a dummy column after the preprocessed and main rounds to round
    // area to a multiple of `1<<log_stacking_height`.
    let branching_program_evals = vec![InnerChallenge::zero(); total_machine_cols + 2];

    let eval_sumcheck_proof = dummy_sumcheck_proof(2 * (total_num_variables + 1), 2);

    let jagged_eval_proof = JaggedSumcheckEvalProof {
        branching_program_evals,
        partial_sumcheck_proof: eval_sumcheck_proof,
    };

    JaggedPcsProof {
        stacked_pcs_proof: stacked_proof,
        params: jagged_params,
        jagged_eval_proof,
        sumcheck_proof: partial_sumcheck_proof,
    }
}
// For each query, create a dummy batch opening for each matrix in the batch. `batch_shapes`
// determines the sizes of each dummy batch opening.
// let query_openings = (0..fri_queries)
//     .map(|_| {
//         batch_shapes
//             .iter()
//             .map(|shapes| {
//                 let batch_max_height =
//                     shapes.shapes.iter().map(|shape| shape.log_degree).max().unwrap();
//                 BatchOpening {
//                     opened_values: shapes
//                         .shapes
//                         .iter()
//                         .map(|shape| vec![BabyBear::zero(); shape.width])
//                         .collect(),
//                     opening_proof: vec![dummy_hash().into(); batch_max_height + log_blowup],
//                 }
//             })
//             .collect::<Vec<_>>()
//     })
//     .collect::<Vec<_>>();
// TwoAdicFriPcsProof { fri_proof: basefold_proof, query_openings }
