use std::{fmt::Debug, future::Future, sync::Arc};

use serde::{Deserialize, Serialize};
use slop_commit::Rounds;
use tokio::sync::oneshot;

use slop_algebra::Field;
use slop_alloc::{Backend, CpuBackend};
use slop_multilinear::Point;

use crate::{JaggedLittlePolynomialProverParams, LongMle};

pub trait JaggedMleGenerator<F: Field, A: Backend>: 'static + Clone + Send + Sync + Debug {
    fn partial_jagged_multilinear(
        &self,
        jagged_params: &JaggedLittlePolynomialProverParams,
        row_data: Rounds<Arc<Vec<usize>>>,
        column_data: Rounds<Arc<Vec<usize>>>,
        z_row: &Point<F, A>,
        z_col: &Point<F, A>,
        num_components: usize,
    ) -> impl Future<Output = LongMle<F, A>> + Send;
}

#[derive(Debug, Clone, Default, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuJaggedMleGenerator;

impl<F: Field> JaggedMleGenerator<F, CpuBackend> for CpuJaggedMleGenerator {
    async fn partial_jagged_multilinear(
        &self,
        jagged_params: &JaggedLittlePolynomialProverParams,
        _row_data: Rounds<Arc<Vec<usize>>>,
        _column_data: Rounds<Arc<Vec<usize>>>,
        z_row: &Point<F>,
        z_col: &Point<F>,
        num_components: usize,
    ) -> LongMle<F, CpuBackend> {
        let (tx, rx) = oneshot::channel();
        assert_eq!(num_components, 1, "only one component is supported for now");

        let z_row = z_row.clone();
        let z_col = z_col.clone();
        let jagged_params = jagged_params.clone();
        slop_futures::rayon::spawn(move || {
            let values = jagged_params.partial_jagged_little_polynomial_evaluation(&z_row, &z_col);
            let log_stacking_height = values.num_variables();
            let mle = LongMle::from_components(vec![values], log_stacking_height);
            tx.send(mle).unwrap();
        });

        rx.await.unwrap()
    }
}
