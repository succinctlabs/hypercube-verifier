mod sumcheck_eval;

pub use sumcheck_eval::*;

use std::{error::Error, fmt::Debug};

use p3_field::{ExtensionField, Field};
use serde::{de::DeserializeOwned, Serialize};
use slop_multilinear::Point;

use crate::JaggedLittlePolynomialVerifierParams;

pub trait JaggedEvalConfig<F: Field, EF: ExtensionField<F>, Challenger>:
    'static + Send + Sync + Serialize + DeserializeOwned + std::fmt::Debug + Clone
{
    type JaggedEvalProof: 'static + Debug + Clone + Send + Sync + Serialize + DeserializeOwned;

    type JaggedEvalError: Error + 'static + Send + Sync;

    fn jagged_evaluation(
        &self,
        params: &JaggedLittlePolynomialVerifierParams<F>,
        z_row: &Point<EF>,
        z_col: &Point<EF>,
        z_trace: &Point<EF>,
        proof: &Self::JaggedEvalProof,
        challenger: &mut Challenger,
    ) -> Result<EF, Self::JaggedEvalError>;
}
