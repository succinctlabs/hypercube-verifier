use slop_multilinear::Point;
use slop_sumcheck::PartialSumcheckProof;

pub struct PartialSpartanProof<EF> {
    pub alpha: Point<EF>,
    pub beta: Point<EF>,

    // The intermediate values (after prodcheck)
    pub v_a: EF,
    pub v_b: EF,
    pub v_c: EF,

    // z[beta] = z_claim
    pub z_claim: EF,

    // A[alpha, beta] = a_claim
    pub a_claim: EF,
    // B[alpha, beta] = b_claim
    pub b_claim: EF,
    // C[alpha, beta] = c_claim
    pub c_claim: EF,

    // The sumcheck proofs
    pub prodcheck_proof: PartialSumcheckProof<EF>,
    pub lincheck_proof: PartialSumcheckProof<EF>,
}
