use std::{convert::Infallible, fmt::Debug};

use p3_field::{ExtensionField, Field};
use serde::{Deserialize, Serialize};
use slop_multilinear::Point;

use crate::JaggedLittlePolynomialVerifierParams;

use super::JaggedEvalConfig;

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct TrivialJaggedEvalConfig;

impl<F: Field, EF: ExtensionField<F>, C: Send + Sync> JaggedEvalConfig<F, EF, C>
    for TrivialJaggedEvalConfig
{
    type JaggedEvalProof = ();
    type JaggedEvalError = Infallible;

    fn jagged_evaluation(
        &self,
        params: &JaggedLittlePolynomialVerifierParams<F>,
        z_row: &Point<EF>,
        z_col: &Point<EF>,
        z_trace: &Point<EF>,
        _proof: &Self::JaggedEvalProof,
        _challenger: &mut C,
    ) -> Result<EF, Self::JaggedEvalError> {
        let (result, _) = params.full_jagged_little_polynomial_evaluation(z_row, z_col, z_trace);
        Ok(result)
    }
}
