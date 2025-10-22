use std::future::Future;

use slop_algebra::{Field, UnivariatePolynomial};

/// The basic functionality required of a struct for which a sumcheck proof can be generated.
pub trait SumcheckPolyBase {
    fn num_variables(&self) -> u32;
}

pub trait ComponentPoly<K: Field> {
    fn get_component_poly_evals(&self) -> impl Future<Output = Vec<K>> + Send;
}

/// The fix_first_variable function applied to a sumcheck's first round's polynomial .
pub trait SumcheckPolyFirstRound<K: Field>: SumcheckPolyBase {
    type NextRoundPoly: SumcheckPoly<K>;
    fn fix_t_variables(
        self,
        alpha: K,
        t: usize,
    ) -> impl Future<Output = Self::NextRoundPoly> + Send;

    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<K>,
        t: usize,
    ) -> impl Future<Output = UnivariatePolynomial<K>> + Send;
}

/// The fix_first_variable function applied to a sumcheck's post first rounds' polynomial.
pub trait SumcheckPoly<K: Field>: SumcheckPolyBase + ComponentPoly<K> + Sized {
    fn fix_last_variable(self, alpha: K) -> impl Future<Output = Self> + Send;

    fn sum_as_poly_in_last_variable(
        &self,
        claim: Option<K>,
    ) -> impl Future<Output = UnivariatePolynomial<K>> + Send;
}
