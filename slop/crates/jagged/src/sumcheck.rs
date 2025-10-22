use std::{future::Future, sync::Arc};

use slop_algebra::{ExtensionField, Field};
use slop_alloc::Backend;
use slop_commit::{Message, Rounds};
use slop_multilinear::{Mle, Point};
use slop_stacked::{FixedRateInterleave, InterleaveMultilinears};
use slop_sumcheck::SumcheckPolyFirstRound;

use crate::{
    HadamardProduct, JaggedBackend, JaggedLittlePolynomialProverParams, JaggedMleGenerator, LongMle,
};

pub trait JaggedSumcheckProver<F: Field, EF: ExtensionField<F>, B: Backend>:
    'static + Send + Sync + Clone + std::fmt::Debug
{
    type Polynomial: SumcheckPolyFirstRound<EF, NextRoundPoly: Send + Sync> + Send + Sync;

    #[allow(clippy::too_many_arguments)]
    fn jagged_sumcheck_poly(
        &self,
        base: Rounds<Message<Mle<F, B>>>,
        jagged_params: &JaggedLittlePolynomialProverParams,
        row_data: Rounds<Arc<Vec<usize>>>,
        column_data: Rounds<Arc<Vec<usize>>>,
        log_stacking_height: u32,
        z_row: &Point<EF, B>,
        z_col: &Point<EF, B>,
    ) -> impl Future<Output = Self::Polynomial> + Send;
}

#[derive(Debug, Clone, Default)]
pub struct HadamardJaggedSumcheckProver<P> {
    pub jagged_generator: P,
}

impl<F, EF, B, P> JaggedSumcheckProver<F, EF, B> for HadamardJaggedSumcheckProver<P>
where
    F: Field,
    EF: ExtensionField<F>,
    B: JaggedBackend<F, EF>,
    P: JaggedMleGenerator<EF, B>,
{
    type Polynomial = HadamardProduct<F, EF, B>;

    async fn jagged_sumcheck_poly(
        &self,
        base: Rounds<Message<Mle<F, B>>>,
        jagged_params: &JaggedLittlePolynomialProverParams,
        row_data: Rounds<Arc<Vec<usize>>>,
        column_data: Rounds<Arc<Vec<usize>>>,
        log_stacking_height: u32,
        z_row: &Point<EF, B>,
        z_col: &Point<EF, B>,
    ) -> Self::Polynomial {
        let base = base.into_iter().flatten().collect::<Message<Mle<_, _>>>();
        let long_mle = LongMle::from_message(base, log_stacking_height);
        let jaggled_mle = self
            .jagged_generator
            .partial_jagged_multilinear(jagged_params, row_data, column_data, z_row, z_col, 1)
            .await;

        let total_num_variables = jaggled_mle.num_variables();

        let stacker = FixedRateInterleave::<F, B>::new(1);
        let restacked_mle = LongMle::from_message(
            stacker
                .interleave_multilinears(long_mle.components().clone(), total_num_variables)
                .await,
            total_num_variables,
        );

        HadamardProduct { base: restacked_mle, ext: jaggled_mle }
    }
}
