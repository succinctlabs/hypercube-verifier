use hypercube_algebra::UnivariatePolynomial;
use hypercube_multilinear::Point;
use serde::{Deserialize, Serialize};

/// A sumcheck proof that does not include the evaluation proofs.
///
/// Verifying a partial sumcheck proof is equivalent to verifying the sumcheck claim on the
/// condition of having evaluation proofs for the given componment polynomials at the given points.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PartialSumcheckProof<K> {
    pub univariate_polys: Vec<UnivariatePolynomial<K>>,
    pub claimed_sum: K,
    pub point_and_eval: (Point<K>, K),
}
