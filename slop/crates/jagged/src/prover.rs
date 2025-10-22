use serde::{Deserialize, Serialize};

use slop_tensor::TransposeBackend;
use std::{fmt::Debug, iter::once, sync::Arc};
use tracing::Instrument;

use slop_algebra::{AbstractField, ExtensionField, Field};
use slop_alloc::{mem::CopyError, Buffer, HasBackend, ToHost};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_commit::{Message, Rounds};
use slop_multilinear::{
    Evaluations, Mle, MleBaseBackend, MleEvaluationBackend, MultilinearPcsProver, PaddedMle, Point,
};
use slop_stacked::{FixedRateInterleaveBackend, InterleaveMultilinears, ToMle};
use slop_sumcheck::{
    reduce_sumcheck_to_evaluation, ComponentPolyEvalBackend, SumCheckPolyFirstRoundBackend,
    SumcheckPolyBackend,
};
use slop_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use thiserror::Error;

use crate::{
    HadamardProduct, JaggedConfig, JaggedEvalProver, JaggedLittlePolynomialProverParams,
    JaggedPcsProof, JaggedPcsVerifier, JaggedSumcheckProver,
};

pub trait JaggedBackend<F: Field, EF: ExtensionField<F>>:
    MleBaseBackend<F>
    + MleBaseBackend<EF>
    + MleEvaluationBackend<F, EF>
    + MleEvaluationBackend<EF, EF>
    + FixedRateInterleaveBackend<F>
    + ComponentPolyEvalBackend<HadamardProduct<F, EF, Self>, EF>
    + ComponentPolyEvalBackend<HadamardProduct<EF, EF, Self>, EF>
    + SumcheckPolyBackend<HadamardProduct<EF, EF, Self>, EF>
    + SumCheckPolyFirstRoundBackend<HadamardProduct<F, EF, Self>, EF, NextRoundPoly: Send + Sync>
    + TransposeBackend<F>
{
}

impl<F, EF, A> JaggedBackend<F, EF> for A
where
    F: Field,
    EF: ExtensionField<F>,
    A: MleBaseBackend<F>
        + MleBaseBackend<EF>
        + MleEvaluationBackend<F, EF>
        + MleEvaluationBackend<EF, EF>
        + FixedRateInterleaveBackend<F>
        + ComponentPolyEvalBackend<HadamardProduct<F, EF, Self>, EF>
        + ComponentPolyEvalBackend<HadamardProduct<EF, EF, Self>, EF>
        + SumcheckPolyBackend<HadamardProduct<EF, EF, Self>, EF>
        + SumCheckPolyFirstRoundBackend<HadamardProduct<F, EF, Self>, EF>
        + TransposeBackend<F>,
    <A as SumCheckPolyFirstRoundBackend<HadamardProduct<F, EF, Self>, EF>>::NextRoundPoly:
        Send + Sync,
{
}

pub trait JaggedProverComponents<GC: IopCtx>: Clone + Send + Sync + 'static {
    type A: JaggedBackend<GC::F, GC::EF>;

    type Config: JaggedConfig<GC> + 'static + Send + Sync + Clone;

    type JaggedSumcheckProver: JaggedSumcheckProver<GC::F, GC::EF, Self::A>;

    type BatchPcsProver: MultilinearPcsProver<
        GC,
        A = Self::A,
        Verifier = <Self::Config as JaggedConfig<GC>>::PcsVerifier,
        ProverData: ToMle<GC::F, Self::A>,
    >;
    type Stacker: InterleaveMultilinears<GC::F, Self::A>;

    type JaggedEvalProver: JaggedEvalProver<GC::F, GC::EF, GC::Challenger, A = Self::A>
        + 'static
        + Send
        + Sync;

    fn log_stacking_height(prover: &JaggedProver<GC, Self>) -> u32;
}

#[derive(Clone)]
pub struct JaggedProver<GC: IopCtx, C: JaggedProverComponents<GC>> {
    pub pcs_prover: C::BatchPcsProver,
    jagged_sumcheck_prover: C::JaggedSumcheckProver,
    jagged_eval_prover: C::JaggedEvalProver,
    pub max_log_row_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JaggedProverData<GC: IopCtx, ProverData> {
    pub pcs_prover_data: ProverData,
    pub row_counts: Arc<Vec<usize>>,
    pub column_counts: Arc<Vec<usize>>,
    /// The number of columns added as a result of padding in the undedrlying stacked PCS.
    pub padding_column_count: usize,
    pub original_commitment: GC::Digest,
}

#[derive(Debug, Error)]
pub enum JaggedProverError<Error> {
    #[error("batch pcs prover error: {0}")]
    BatchPcsProverError(Error),
    #[error("copy error: {0}")]
    CopyError(#[from] CopyError),
}

pub trait DefaultJaggedProver<GC: IopCtx>: JaggedProverComponents<GC> {
    fn prover_from_verifier(
        verifier: &JaggedPcsVerifier<GC, Self::Config>,
    ) -> JaggedProver<GC, Self>;
}

impl<GC: IopCtx, C: JaggedProverComponents<GC>> JaggedProver<GC, C> {
    pub const fn new(
        max_log_row_count: usize,
        pcs_prover: C::BatchPcsProver,
        jagged_sumcheck_prover: C::JaggedSumcheckProver,
        jagged_eval_prover: C::JaggedEvalProver,
    ) -> Self {
        Self { pcs_prover, jagged_sumcheck_prover, jagged_eval_prover, max_log_row_count }
    }

    pub fn from_verifier(verifier: &JaggedPcsVerifier<GC, C::Config>) -> Self
    where
        C: DefaultJaggedProver<GC>,
    {
        C::prover_from_verifier(verifier)
    }

    /// Commit to a batch of padded multilinears.
    ///
    /// The jagged polyniomial commitments scheme is able to commit to sparse polynomials having
    /// very few or no real rows.
    /// **Note** the padding values will be ignored and treated as though they are zero.
    pub async fn commit_multilinears(
        &self,
        multilinears: Vec<PaddedMle<GC::F, C::A>>,
    ) -> Result<
        (
            GC::Digest,
            JaggedProverData<GC, <C::BatchPcsProver as MultilinearPcsProver<GC>>::ProverData>,
        ),
        JaggedProverError<<C::BatchPcsProver as MultilinearPcsProver<GC>>::ProverError>,
    > {
        let mut row_counts = multilinears.iter().map(|x| x.num_real_entries()).collect::<Vec<_>>();
        let mut column_counts =
            multilinears.iter().map(|x| x.num_polynomials()).collect::<Vec<_>>();

        // Check the validity of the input multilinears.
        for padded_mle in multilinears.iter() {
            // Check that the number of variables matches what the prover expects.
            assert_eq!(padded_mle.num_variables(), self.max_log_row_count as u32);
        }

        // Because of the padding in the stacked PCS, it's necessary to add a "dummy columns" in the
        // jagged commitment scheme to pad the area to the next multiple of the stacking height.
        // We do this in the form of two dummy tables, one with the maximum number of rows and
        // possibly multiple columns, and one with a single column and the remaining number
        // of "leftover" values.

        // Collect all the multilinears that have at least one non-zero entry into a commit message
        // for the dense PCS.
        let message =
            multilinears.into_iter().filter_map(|mle| mle.into_inner()).collect::<Message<_>>();

        let (commitment, data, num_added_vals) =
            self.pcs_prover.commit_multilinear(message).await.unwrap();

        let num_added_cols = num_added_vals.div_ceil(1 << self.max_log_row_count).max(1);

        row_counts.push(1 << self.max_log_row_count);
        row_counts.push(num_added_vals - (num_added_cols - 1) * (1 << self.max_log_row_count));
        column_counts.push(num_added_cols - 1);
        column_counts.push(1);

        let (hasher, compressor) = GC::default_hasher_and_compressor();

        let hash = hasher.hash_iter(
            once(GC::F::from_canonical_usize(row_counts.len()))
                .chain(row_counts.clone().into_iter().map(GC::F::from_canonical_usize))
                .chain(column_counts.clone().into_iter().map(GC::F::from_canonical_usize)),
        );

        let final_commitment = compressor.compress([commitment, hash]);

        let jagged_prover_data = JaggedProverData {
            pcs_prover_data: data,
            row_counts: Arc::new(row_counts),
            column_counts: Arc::new(column_counts),
            padding_column_count: num_added_cols,
            original_commitment: commitment,
        };

        Ok((final_commitment, jagged_prover_data))
    }

    pub async fn prove_trusted_evaluations(
        &self,
        eval_point: Point<GC::EF>,
        evaluation_claims: Rounds<Evaluations<GC::EF, C::A>>,
        prover_data: Rounds<
            JaggedProverData<GC, <C::BatchPcsProver as MultilinearPcsProver<GC>>::ProverData>,
        >,
        challenger: &mut GC::Challenger,
    ) -> Result<
        JaggedPcsProof<GC, C::Config>,
        JaggedProverError<<C::BatchPcsProver as MultilinearPcsProver<GC>>::ProverError>,
    > {
        let num_col_variables = prover_data
            .iter()
            .map(|data| data.column_counts.iter().sum::<usize>())
            .sum::<usize>()
            .next_power_of_two()
            .ilog2();
        let z_col = (0..num_col_variables)
            .map(|_| challenger.sample_ext_element::<GC::EF>())
            .collect::<Point<_>>();

        let z_row = eval_point;

        let backend = evaluation_claims[0][0].backend().clone();

        // First, allocate a buffer for all of the column claims on device.
        let total_column_claims = evaluation_claims
            .iter()
            .map(|evals| evals.iter().map(|evals| evals.num_polynomials()).sum::<usize>())
            .sum::<usize>();

        let total_len = total_column_claims
        // Add in the dummy padding columns added during the stacked PCS commitment.
            + prover_data.iter().map(|data| data.padding_column_count).sum::<usize>();

        let mut column_claims: Buffer<GC::EF, C::A> =
            Buffer::with_capacity_in(total_len, backend.clone());

        // Then, copy the column claims from the evaluation claims into the buffer, inserting extra
        // zeros for the dummy columns.
        for (column_claim_round, data) in evaluation_claims.into_iter().zip(prover_data.iter()) {
            for column_claim in column_claim_round.into_iter() {
                column_claims
                    .extend_from_device_slice(column_claim.into_evaluations().as_buffer())?;
            }
            column_claims.extend_from_host_slice(
                vec![GC::EF::zero(); data.padding_column_count].as_slice(),
            )?;
        }

        assert!(prover_data
            .iter()
            .flat_map(|data| data.row_counts.iter())
            .all(|x| *x <= 1 << self.max_log_row_count));

        let row_data =
            prover_data.iter().map(|data| data.row_counts.clone()).collect::<Rounds<_>>();
        let column_data =
            prover_data.iter().map(|data| data.column_counts.clone()).collect::<Rounds<_>>();

        // Collect the jagged polynomial parameters.
        let params = JaggedLittlePolynomialProverParams::new(
            prover_data
                .iter()
                .flat_map(|data| {
                    data.row_counts
                        .iter()
                        .copied()
                        .zip(data.column_counts.iter().copied())
                        .flat_map(|(row_count, column_count)| {
                            std::iter::repeat_n(row_count, column_count)
                        })
                })
                .collect(),
            self.max_log_row_count,
        );

        // Generate the jagged sumcheck proof.
        let z_row_backend = z_row.copy_into(&backend);
        let z_col_backend = z_col.copy_into(&backend);

        let all_mles = prover_data
            .iter()
            .map(|data| data.pcs_prover_data.interleaved_mles().clone())
            .collect::<Rounds<_>>();

        let sumcheck_poly = self
            .jagged_sumcheck_prover
            .jagged_sumcheck_poly(
                all_mles.clone(),
                &params,
                row_data,
                column_data,
                <C as JaggedProverComponents<_>>::log_stacking_height(self),
                &z_row_backend,
                &z_col_backend,
            )
            .instrument(tracing::debug_span!("create jagged sumcheck poly"))
            .await;

        // The overall evaluation claim of the sparse polynomial is inferred from the individual
        // table claims.

        let column_claims: Mle<GC::EF, C::A> = Mle::from_buffer(column_claims);

        let sumcheck_claims = column_claims.eval_at(&z_col_backend).await;
        let sumcheck_claims_host = sumcheck_claims.to_host().await.unwrap();
        let sumcheck_claim = sumcheck_claims_host[0];

        let (sumcheck_proof, component_poly_evals) = reduce_sumcheck_to_evaluation(
            vec![sumcheck_poly],
            challenger,
            vec![sumcheck_claim],
            1,
            GC::EF::one(),
        )
        .instrument(tracing::debug_span!("jagged sumcheck"))
        .await;

        let final_eval_point = sumcheck_proof.point_and_eval.0.clone();

        let jagged_eval_proof = self
            .jagged_eval_prover
            .prove_jagged_evaluation(
                &params,
                &z_row,
                &z_col,
                &final_eval_point,
                challenger,
                backend.clone(),
            )
            .instrument(tracing::debug_span!("jagged evaluation proof"))
            .await;
        let (row_counts, column_counts): (Rounds<_>, Rounds<_>) = prover_data
            .iter()
            .map(|data| {
                (Clone::clone(data.row_counts.as_ref()), Clone::clone(data.column_counts.as_ref()))
            })
            .unzip();

        let original_commitments: Rounds<_> =
            prover_data.iter().map(|data| data.original_commitment).collect();

        let stacked_prover_data =
            prover_data.into_iter().map(|data| data.pcs_prover_data).collect::<Rounds<_>>();

        let pcs_proof = self
            .pcs_prover
            .prove_trusted_evaluation(
                final_eval_point,
                component_poly_evals[0][0],
                stacked_prover_data,
                challenger,
            )
            .instrument(tracing::debug_span!("Dense PCS evaluation proof"))
            .await
            .unwrap();

        let row_counts_and_column_counts: Rounds<Vec<(usize, usize)>> = row_counts
            .into_iter()
            .zip(column_counts.into_iter())
            .map(|(r, c)| r.into_iter().zip(c.into_iter()).collect())
            .collect();

        Ok(JaggedPcsProof {
            pcs_proof,
            sumcheck_proof,
            jagged_eval_proof,
            params: params.into_verifier_params(),
            row_counts_and_column_counts,
            merkle_tree_commitments: original_commitments,
        })
    }
}
