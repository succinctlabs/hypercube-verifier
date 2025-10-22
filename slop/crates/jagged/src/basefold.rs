use serde::{Deserialize, Serialize};
use slop_algebra::{extension::BinomialExtensionField, TwoAdicField};
use slop_alloc::CpuBackend;
use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
use slop_basefold::BasefoldVerifier;
use slop_basefold_prover::{
    BasefoldProver, BasefoldProverComponents, DefaultBasefoldProver,
    Poseidon2BabyBear16BasefoldCpuProverComponents, Poseidon2Bn254BasefoldCpuProverComponents,
    Poseidon2KoalaBear16BasefoldCpuProverComponents,
};
use slop_bn254::BNGC;
use slop_challenger::IopCtx;
use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex};
use slop_stacked::{FixedRateInterleave, StackedPcsProver, StackedPcsVerifier};
use std::{fmt::Debug, marker::PhantomData};

use crate::{
    CpuJaggedMleGenerator, DefaultJaggedProver, HadamardJaggedSumcheckProver,
    JaggedAssistSumAsPolyCPUImpl, JaggedBackend, JaggedConfig, JaggedEvalProver,
    JaggedEvalSumcheckProver, JaggedPcsVerifier, JaggedProver, JaggedProverComponents,
    JaggedSumcheckProver,
};

pub type BabyBearPoseidon2 = JaggedBasefoldConfig<BabyBearDegree4Duplex>;

pub type KoalaBearPoseidon2 = JaggedBasefoldConfig<KoalaBearDegree4Duplex>;

pub type Bn254JaggedConfig<F, EF> = JaggedBasefoldConfig<BNGC<F, EF>>;

pub type SP1OuterConfig = Bn254JaggedConfig<KoalaBear, BinomialExtensionField<KoalaBear, 4>>;

pub type Poseidon2BabyBearJaggedCpuProverComponents = JaggedBasefoldProverComponents<
    Poseidon2BabyBear16BasefoldCpuProverComponents,
    HadamardJaggedSumcheckProver<CpuJaggedMleGenerator>,
    JaggedEvalSumcheckProver<
        BabyBear,
        JaggedAssistSumAsPolyCPUImpl<
            BabyBear,
            BinomialExtensionField<BabyBear, 4>,
            <BabyBearDegree4Duplex as IopCtx>::Challenger,
        >,
        CpuBackend,
        <BabyBearDegree4Duplex as IopCtx>::Challenger,
    >,
    BabyBearDegree4Duplex,
>;

pub type Poseidon2KoalaBearJaggedCpuProverComponents = JaggedBasefoldProverComponents<
    Poseidon2KoalaBear16BasefoldCpuProverComponents,
    HadamardJaggedSumcheckProver<CpuJaggedMleGenerator>,
    JaggedEvalSumcheckProver<
        KoalaBear,
        JaggedAssistSumAsPolyCPUImpl<
            KoalaBear,
            BinomialExtensionField<KoalaBear, 4>,
            <KoalaBearDegree4Duplex as IopCtx>::Challenger,
        >,
        CpuBackend,
        <KoalaBearDegree4Duplex as IopCtx>::Challenger,
    >,
    KoalaBearDegree4Duplex,
>;

pub type Poseidon2Bn254JaggedCpuProverComponents<F, EF> = JaggedBasefoldProverComponents<
    Poseidon2Bn254BasefoldCpuProverComponents<F>,
    HadamardJaggedSumcheckProver<CpuJaggedMleGenerator>,
    JaggedEvalSumcheckProver<
        F,
        JaggedAssistSumAsPolyCPUImpl<
            F,
            BinomialExtensionField<F, 4>,
            <BNGC<F, EF> as IopCtx>::Challenger,
        >,
        CpuBackend,
        <BNGC<F, EF> as IopCtx>::Challenger,
    >,
    BNGC<F, EF>,
>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JaggedBasefoldConfig<GC>(PhantomData<GC>);

impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>> JaggedConfig<GC> for JaggedBasefoldConfig<GC>
where
    GC::Digest: Debug,
{
    type PcsVerifier = StackedPcsVerifier<GC, BasefoldVerifier<GC>>;

    fn log_stacking_height(verifier: &Self::PcsVerifier) -> u32 {
        verifier.log_stacking_height
    }

    fn round_multiples(
        proof: &<Self::PcsVerifier as slop_multilinear::MultilinearPcsVerifier<GC>>::Proof,
    ) -> Vec<usize> {
        proof.batch_evaluations.iter().map(|e| e.iter().count()).collect()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JaggedBasefoldProverComponents<B, J, E, GC>(B, J, E, PhantomData<GC>);

impl<Bpc, JaggedSCProver, EvalProver, GC> JaggedProverComponents<GC>
    for JaggedBasefoldProverComponents<Bpc, JaggedSCProver, EvalProver, GC>
where
    GC: IopCtx,
    GC::F: TwoAdicField,
    GC::EF: TwoAdicField,
    Bpc: BasefoldProverComponents<GC>,
    Bpc::A: JaggedBackend<GC::F, GC::EF>,
    JaggedSCProver: JaggedSumcheckProver<GC::F, GC::EF, Bpc::A>,
    EvalProver:
        JaggedEvalProver<GC::F, GC::EF, GC::Challenger, A = Bpc::A> + 'static + Send + Sync + Clone,
{
    type A = Bpc::A;
    type Config = JaggedBasefoldConfig<GC>;

    type JaggedSumcheckProver = JaggedSCProver;
    type BatchPcsProver = StackedPcsProver<BasefoldProver<GC, Bpc>, Self::Stacker, GC>;
    type Stacker = FixedRateInterleave<GC::F, Bpc::A>;
    type JaggedEvalProver = EvalProver;

    fn log_stacking_height(prover: &JaggedProver<GC, Self>) -> u32 {
        prover.pcs_prover.log_stacking_height
    }
}

impl<GC> JaggedPcsVerifier<GC, JaggedBasefoldConfig<GC>>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
{
    pub fn new(
        log_blowup: usize,
        log_stacking_height: u32,
        max_log_row_count: usize,
        expected_number_of_commits: usize,
    ) -> Self {
        let basefold_verifer = BasefoldVerifier::<GC>::new(log_blowup, expected_number_of_commits);
        let stacked_pcs_verifier = StackedPcsVerifier::new(basefold_verifer, log_stacking_height);
        Self { pcs_verifier: stacked_pcs_verifier, max_log_row_count }
    }
}

impl<GC, Bpc, JP, E> JaggedProver<GC, JaggedBasefoldProverComponents<Bpc, JP, E, GC>>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    Bpc: BasefoldProverComponents<GC> + DefaultBasefoldProver<GC>,
    Bpc::A: JaggedBackend<GC::F, GC::EF>,
    JP: JaggedSumcheckProver<GC::F, GC::EF, Bpc::A>,
    E: JaggedEvalProver<GC::F, GC::EF, GC::Challenger, A = Bpc::A> + Default,
{
    pub fn from_basefold_components(
        verifier: &JaggedPcsVerifier<GC, JaggedBasefoldConfig<GC>>,
        jagged_generator: JP,
        interleave_batch_size: usize,
    ) -> Self {
        let pcs_prover = BasefoldProver::new(&verifier.pcs_verifier.pcs_verifier);
        let stacker = FixedRateInterleave::new(interleave_batch_size);
        let stacked_pcs_prover =
            StackedPcsProver::new(pcs_prover, stacker, verifier.pcs_verifier.log_stacking_height);

        Self::new(verifier.max_log_row_count, stacked_pcs_prover, jagged_generator, E::default())
    }
}

const DEFAULT_INTERLEAVE_BATCH_SIZE: usize = 32;

impl<Bpc, JP, E, GC> DefaultJaggedProver<GC> for JaggedBasefoldProverComponents<Bpc, JP, E, GC>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    Bpc: BasefoldProverComponents<GC> + DefaultBasefoldProver<GC>,
    Bpc::A: JaggedBackend<GC::F, GC::EF>,
    JP: JaggedSumcheckProver<GC::F, GC::EF, Bpc::A> + Default,
    E: JaggedEvalProver<GC::F, GC::EF, GC::Challenger, A = Bpc::A> + Default,
{
    fn prover_from_verifier(
        verifier: &JaggedPcsVerifier<GC, Self::Config>,
    ) -> JaggedProver<GC, Self> {
        JaggedProver::from_basefold_components(
            verifier,
            JP::default(),
            DEFAULT_INTERLEAVE_BATCH_SIZE,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rand::{thread_rng, Rng};
    use slop_challenger::CanObserve;
    use slop_commit::Rounds;
    use slop_multilinear::{Evaluations, Mle, MleEval, PaddedMle, Point};

    use super::*;

    #[tokio::test]
    async fn test_baby_bear_jagged_basefold() {
        test_jagged_basefold::<BabyBearDegree4Duplex, Poseidon2BabyBearJaggedCpuProverComponents>()
            .await;
    }

    #[tokio::test]
    async fn test_koala_bear_jagged_basefold() {
        test_jagged_basefold::<
            KoalaBearDegree4Duplex,
            Poseidon2KoalaBearJaggedCpuProverComponents,
        >()
        .await;
    }

    #[tokio::test]
    async fn test_bn254_jagged_basefold() {
        test_jagged_basefold::<
            BNGC<BabyBear, BinomialExtensionField<BabyBear, 4>>,
            Poseidon2Bn254JaggedCpuProverComponents<BabyBear, BinomialExtensionField<BabyBear, 4>>,
        >()
        .await;
    }

    #[tokio::test]
    async fn test_bn254_jagged_kb_basefold() {
        test_jagged_basefold::<
            BNGC<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
            Poseidon2Bn254JaggedCpuProverComponents<
                KoalaBear,
                BinomialExtensionField<KoalaBear, 4>,
            >,
        >()
        .await;
    }

    // #[tokio::test]
    async fn test_jagged_basefold<
        GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
        Prover: JaggedProverComponents<GC, Config = JaggedBasefoldConfig<GC>, A = CpuBackend>
            + DefaultJaggedProver<GC>,
    >()
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        let row_counts_rounds = vec![vec![1 << 10, 0, 1 << 10], vec![1 << 8]];
        let column_counts_rounds = vec![vec![128, 45, 32], vec![512]];
        let num_rounds = row_counts_rounds.len();

        let log_blowup = 1;
        let log_stacking_height = 11;
        let max_log_row_count = 10;

        let row_counts = row_counts_rounds.into_iter().collect::<Rounds<Vec<usize>>>();
        let column_counts = column_counts_rounds.into_iter().collect::<Rounds<Vec<usize>>>();

        assert!(row_counts.len() == column_counts.len());

        let mut rng = thread_rng();

        let round_mles = row_counts
            .iter()
            .zip(column_counts.iter())
            .map(|(row_counts, col_counts)| {
                row_counts
                    .iter()
                    .zip(col_counts.iter())
                    .map(|(num_rows, num_cols)| {
                        if *num_rows == 0 {
                            PaddedMle::zeros(*num_cols, max_log_row_count)
                        } else {
                            let mle = Mle::<GC::F>::rand(&mut rng, *num_cols, num_rows.ilog(2));
                            PaddedMle::padded_with_zeros(Arc::new(mle), max_log_row_count)
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Rounds<_>>();

        let jagged_verifier = JaggedPcsVerifier::<GC, JaggedBasefoldConfig<GC>>::new(
            log_blowup,
            log_stacking_height,
            max_log_row_count as usize,
            num_rounds,
        );

        let jagged_prover = JaggedProver::<GC, Prover>::from_verifier(&jagged_verifier);

        let eval_point = (0..max_log_row_count).map(|_| rng.gen::<GC::EF>()).collect::<Point<_>>();

        // Begin the commit rounds
        let mut challenger = jagged_verifier.challenger();

        let mut prover_data = Rounds::new();
        let mut commitments = Rounds::new();
        for round in round_mles.iter() {
            let (commit, data) =
                jagged_prover.commit_multilinears(round.clone()).await.ok().unwrap();
            challenger.observe(commit);
            prover_data.push(data);
            commitments.push(commit);
        }

        let mut evaluation_claims = Rounds::new();
        for round in round_mles.iter() {
            let mut evals = Evaluations::default();
            for mle in round.iter() {
                let eval = mle.eval_at(&eval_point).await;
                evals.push(eval);
            }
            evaluation_claims.push(evals);
        }

        let proof = jagged_prover
            .prove_trusted_evaluations(
                eval_point.clone(),
                evaluation_claims.clone(),
                prover_data,
                &mut challenger,
            )
            .await
            .ok()
            .unwrap();

        let mut challenger = jagged_verifier.challenger();
        for commitment in commitments.iter() {
            challenger.observe(*commitment);
        }

        let evaluation_claims = evaluation_claims
            .iter()
            .map(|round| {
                round.iter().flat_map(|evals| evals.iter().cloned()).collect::<MleEval<_>>()
            })
            .collect::<Vec<_>>();

        jagged_verifier
            .verify_trusted_evaluations(
                &commitments,
                eval_point,
                &evaluation_claims,
                &proof,
                &mut challenger,
            )
            .unwrap();
    }
}
