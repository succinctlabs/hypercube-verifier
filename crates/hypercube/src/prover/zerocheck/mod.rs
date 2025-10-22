//! Zerocheck Sumcheck polynomial.

mod fix_last_variable;
mod sum_as_poly;

use slop_air::Air;
use slop_uni_stark::SymbolicAirBuilder;

use std::marker::PhantomData;

pub use fix_last_variable::*;
use slop_algebra::{ExtensionField, Field, UnivariatePolynomial};
use slop_alloc::{Backend, CpuBackend, HasBackend};
use slop_multilinear::{MleBaseBackend, PaddedMle, Point, VirtualGeq};
use slop_sumcheck::{
    ComponentPolyEvalBackend, SumCheckPolyFirstRoundBackend, SumcheckPolyBackend, SumcheckPolyBase,
};
pub use sum_as_poly::*;

use crate::{air::MachineAir, debug::DebugConstraintBuilder, ConstraintSumcheckFolder};

/// A zerocheck backend. This trait is automatically implemented for any backend satisfying the
/// required bounds.
pub trait ZercocheckBackend<
    F: Field,
    EF: ExtensionField<F>,
    ProverData: ZerocheckProverData<F, EF, Self>,
>:
    Backend
    + MleBaseBackend<EF>
    + MleBaseBackend<F>
    + ComponentPolyEvalBackend<
        ZeroCheckPoly<
            EF,
            F,
            EF,
            <ProverData as ZerocheckProverData<F, EF, Self>>::RoundProver,
            Self,
        >,
        EF,
    > + ComponentPolyEvalBackend<
        ZeroCheckPoly<
            F,
            F,
            EF,
            <ProverData as ZerocheckProverData<F, EF, Self>>::RoundProver,
            Self,
        >,
        EF,
    > + SumcheckPolyBackend<
        ZeroCheckPoly<
            EF,
            F,
            EF,
            <ProverData as ZerocheckProverData<F, EF, Self>>::RoundProver,
            Self,
        >,
        EF,
    > + SumCheckPolyFirstRoundBackend<
        ZeroCheckPoly<
            F,
            F,
            EF,
            <ProverData as ZerocheckProverData<F, EF, Self>>::RoundProver,
            Self,
        >,
        EF,
        NextRoundPoly = ZeroCheckPoly<
            EF,
            F,
            EF,
            <ProverData as ZerocheckProverData<F, EF, Self>>::RoundProver,
            Self,
        >,
    >
{
}

/// An AIR compatible with the standard zerocheck prover.
pub trait ZerocheckAir<F: Field, EF: ExtensionField<F>>:
    MachineAir<F>
    + Air<SymbolicAirBuilder<F>>
    + for<'b> Air<ConstraintSumcheckFolder<'b, F, F, EF>>
    + for<'b> Air<ConstraintSumcheckFolder<'b, F, EF, EF>>
    + for<'b> Air<DebugConstraintBuilder<'b, F, EF>>
{
}

impl<F: Field, EF: ExtensionField<F>, A> ZerocheckAir<F, EF> for A where
    A: MachineAir<F>
        + Air<SymbolicAirBuilder<F>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, F, F, EF>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, F, EF, EF>>
        + for<'b> Air<DebugConstraintBuilder<'b, F, EF>>
{
}

impl<F: Field, EF: ExtensionField<F>, ProverData: ZerocheckProverData<F, EF, B>, B>
    ZercocheckBackend<F, EF, ProverData> for B
where
    B: Backend
        + MleBaseBackend<EF>
        + MleBaseBackend<F>
        + ComponentPolyEvalBackend<
            ZeroCheckPoly<
                EF,
                F,
                EF,
                <ProverData as ZerocheckProverData<F, EF, Self>>::RoundProver,
                Self,
            >,
            EF,
        > + ComponentPolyEvalBackend<
            ZeroCheckPoly<
                F,
                F,
                EF,
                <ProverData as ZerocheckProverData<F, EF, Self>>::RoundProver,
                Self,
            >,
            EF,
        > + SumcheckPolyBackend<
            ZeroCheckPoly<
                EF,
                F,
                EF,
                <ProverData as ZerocheckProverData<F, EF, Self>>::RoundProver,
                Self,
            >,
            EF,
        > + SumCheckPolyFirstRoundBackend<
            ZeroCheckPoly<
                F,
                F,
                EF,
                <ProverData as ZerocheckProverData<F, EF, Self>>::RoundProver,
                Self,
            >,
            EF,
            NextRoundPoly = ZeroCheckPoly<
                EF,
                F,
                EF,
                <ProverData as ZerocheckProverData<F, EF, Self>>::RoundProver,
                Self,
            >,
        >,
{
}

/// Zerocheck sumcheck polynomial.
#[derive(Debug, Clone)]
pub struct ZeroCheckPoly<K, F, EF, AirData, B: Backend = CpuBackend> {
    /// The data that contains the constraint polynomial.
    pub air_data: AirData,
    /// The random challenge point at which the polynomial is evaluated.
    pub zeta: Point<EF>,
    /// The preprocessed trace.
    pub preprocessed_columns: Option<PaddedMle<K, B>>,
    /// The main trace.
    pub main_columns: PaddedMle<K, B>,
    /// The adjustment factor from the constant part of the eq polynomial.
    pub eq_adjustment: EF,
    ///  The geq polynomial value.  This will be 0 for all zerocheck polys that are at least one
    /// non-padded variable.
    pub geq_value: EF,
    /// Num padded variables.  These padded variables are the first-most (e.g. the most
    /// significant) variables.
    // pub num_padded_vars: usize,
    /// The padded row adjustment.
    pub padded_row_adjustment: EF,

    /// A virtual materialization keeping track the geq polynomial which is used to adjust the sums
    /// for airs in which the zero row doesn't satisfy the constraints.
    pub virtual_geq: VirtualGeq<K>,

    _marker: PhantomData<F>,
}

impl<K: Field, F: Field, EF: ExtensionField<F>, AirData, B: Backend + MleBaseBackend<K>>
    ZeroCheckPoly<K, F, EF, AirData, B>
{
    /// Creates a new `ZeroCheckPoly`.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn new(
        air_data: AirData,
        zeta: Point<EF>,
        preprocessed_values: Option<PaddedMle<K, B>>,
        main_values: PaddedMle<K, B>,
        eq_adjustment: EF,
        geq_value: EF,
        padded_row_adjustment: EF,
        virtual_geq: VirtualGeq<K>,
    ) -> Self {
        Self {
            air_data,
            zeta,
            preprocessed_columns: preprocessed_values,
            main_columns: main_values,
            eq_adjustment,
            geq_value,
            padded_row_adjustment,
            virtual_geq,
            _marker: PhantomData,
        }
    }
}

impl<K: Field, F: Field, EF, AirData, B> SumcheckPolyBase for ZeroCheckPoly<K, F, EF, AirData, B>
where
    K: Field,
    B: MleBaseBackend<K>,
{
    #[inline]
    fn num_variables(&self) -> u32 {
        self.main_columns.num_variables()
    }
}

impl<K, F, EF, AirData> ComponentPolyEvalBackend<ZeroCheckPoly<K, F, EF, AirData>, EF>
    for CpuBackend
where
    K: Field,
    F: Field,
    EF: ExtensionField<F> + ExtensionField<K>,
    AirData: Sync,
{
    async fn get_component_poly_evals(poly: &ZeroCheckPoly<K, F, EF, AirData>) -> Vec<EF> {
        assert!(poly.num_variables() == 0);

        let prep_columns = poly.preprocessed_columns.as_ref();
        // First get the preprocessed values.
        let prep_evals = if let Some(preprocessed_values) = prep_columns {
            preprocessed_values.inner().as_ref().unwrap().guts().as_slice()
        } else {
            &[]
        };

        let main_evals = poly
            .main_columns
            .inner()
            .as_ref()
            .map(|mle| mle.guts().as_slice().to_vec())
            .unwrap_or(vec![K::zero(); poly.main_columns.num_polynomials()]);

        // Add the main values.
        prep_evals.iter().copied().chain(main_evals).map(Into::into).collect::<Vec<_>>()
    }
}

impl<F, EF, AirData> SumCheckPolyFirstRoundBackend<ZeroCheckPoly<F, F, EF, AirData>, EF>
    for CpuBackend
where
    F: Field,
    EF: ExtensionField<F>,
    AirData: ZerocheckRoundProver<F, F, EF> + ZerocheckRoundProver<F, EF, EF>,
{
    type NextRoundPoly = ZeroCheckPoly<EF, F, EF, AirData>;

    #[inline]
    async fn fix_t_variables(
        poly: ZeroCheckPoly<F, F, EF, AirData>,
        alpha: EF,
        t: usize,
    ) -> Self::NextRoundPoly {
        debug_assert!(t == 1);
        zerocheck_fix_last_variable(poly, alpha).await
    }

    #[inline]
    async fn sum_as_poly_in_last_t_variables(
        poly: &ZeroCheckPoly<F, F, EF, AirData>,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        debug_assert!(t == 1);
        debug_assert!(poly.num_variables() > 0);
        zerocheck_sum_as_poly_in_last_variable::<F, F, EF, AirData, CpuBackend, true>(poly, claim)
            .await
    }
}

impl<F, EF, AirData> SumcheckPolyBackend<ZeroCheckPoly<EF, F, EF, AirData>, EF> for CpuBackend
where
    F: Field,
    EF: ExtensionField<F>,
    AirData: ZerocheckRoundProver<F, F, EF> + ZerocheckRoundProver<F, EF, EF>,
{
    #[inline]
    async fn fix_last_variable(
        poly: ZeroCheckPoly<EF, F, EF, AirData>,
        alpha: EF,
    ) -> ZeroCheckPoly<EF, F, EF, AirData> {
        zerocheck_fix_last_variable(poly, alpha).await
    }

    #[inline]
    async fn sum_as_poly_in_last_variable(
        poly: &ZeroCheckPoly<EF, F, EF, AirData>,
        claim: Option<EF>,
    ) -> UnivariatePolynomial<EF> {
        debug_assert!(poly.num_variables() > 0);
        zerocheck_sum_as_poly_in_last_variable::<EF, F, EF, AirData, CpuBackend, false>(poly, claim)
            .await
    }
}

impl<K, F, EF, AirData, B: Backend> HasBackend for ZeroCheckPoly<K, F, EF, AirData, B> {
    type Backend = B;

    #[inline]
    fn backend(&self) -> &Self::Backend {
        self.main_columns.backend()
    }
}
