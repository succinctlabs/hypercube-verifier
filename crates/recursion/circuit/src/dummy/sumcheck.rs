use slop_algebra::{Field, UnivariatePolynomial};
use slop_multilinear::Point;
use slop_sumcheck::PartialSumcheckProof;

pub fn dummy_sumcheck_proof<F: Field>(
    num_variables: usize,
    degree: usize,
) -> PartialSumcheckProof<F> {
    PartialSumcheckProof {
        univariate_polys: vec![
            UnivariatePolynomial::new(vec![F::one(); degree + 1]);
            num_variables
        ],
        claimed_sum: F::zero(),
        point_and_eval: (Point::<F>::from_usize(0, num_variables), F::zero()),
    }
}
