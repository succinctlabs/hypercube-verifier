use crate::operations::GlobalInteractionOperation;
use slop_algebra::{AbstractExtensionField, AbstractField, Field, PrimeField32};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, SP1AirBuilder, SepticExtensionAirBuilder},
    septic_curve::{SepticCurve, SepticCurveComplete},
    septic_extension::{SepticBlock, SepticExtension},
    InteractionKind,
};

/// A set of columns needed to compute the global interaction elliptic curve digest.
/// It is critical that this struct is at the end of the main trace, as the permutation constraints
/// will be dependent on this fact. It is also critical the the cumulative sum is at the end of this
/// struct, for the same reason.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct GlobalAccumulationOperation<T> {
    pub initial_digest: [SepticBlock<T>; 2],
    pub sum_checker: SepticBlock<T>,
    pub cumulative_sum: [SepticBlock<T>; 2],
}

impl<T: Default> Default for GlobalAccumulationOperation<T> {
    fn default() -> Self {
        Self {
            initial_digest: core::array::from_fn(|_| SepticBlock::<T>::default()),
            sum_checker: SepticBlock::<T>::default(),
            cumulative_sum: core::array::from_fn(|_| SepticBlock::<T>::default()),
        }
    }
}

impl<F: PrimeField32> GlobalAccumulationOperation<F> {
    pub fn populate(
        &mut self,
        initial_digest: &mut SepticCurve<F>,
        global_interaction_cols: GlobalInteractionOperation<F>,
        is_real: F,
    ) {
        self.initial_digest[0] = SepticBlock::from(initial_digest.x.0);
        self.initial_digest[1] = SepticBlock::from(initial_digest.y.0);

        let point_cur = SepticCurve {
            x: SepticExtension(global_interaction_cols.x_coordinate.0),
            y: SepticExtension(global_interaction_cols.y_coordinate.0),
        };
        debug_assert!(is_real == F::one() || is_real == F::zero());
        let sum_point = if is_real == F::one() {
            point_cur.add_incomplete(*initial_digest)
        } else {
            *initial_digest
        };
        let sum_checker = if is_real == F::one() {
            SepticExtension::<F>::zero()
        } else {
            SepticCurve::<F>::sum_checker_x(*initial_digest, point_cur, sum_point)
        };
        self.sum_checker = SepticBlock::from(sum_checker.0);
        self.cumulative_sum[0] = SepticBlock::from(sum_point.x.0);
        self.cumulative_sum[1] = SepticBlock::from(sum_point.y.0);
        *initial_digest = sum_point;
    }

    pub fn populate_dummy(
        &mut self,
        final_digest: SepticCurve<F>,
        final_sum_checker: SepticExtension<F>,
    ) {
        self.initial_digest[0] = SepticBlock::from(final_digest.x.0);
        self.initial_digest[1] = SepticBlock::from(final_digest.y.0);
        self.sum_checker = SepticBlock::from(final_sum_checker.0);
        self.cumulative_sum[0] = SepticBlock::from(final_digest.x.0);
        self.cumulative_sum[1] = SepticBlock::from(final_digest.y.0);
    }

    pub fn populate_real(
        &mut self,
        sums: &[SepticCurveComplete<F>],
        final_digest: SepticCurve<F>,
        final_sum_checker: SepticExtension<F>,
    ) {
        let len = sums.len();
        let sums = sums.iter().map(|complete_point| complete_point.point()).collect::<Vec<_>>();
        self.initial_digest[0] = SepticBlock::from(sums[0].x.0);
        self.initial_digest[1] = SepticBlock::from(sums[0].y.0);
        if len >= 2 {
            self.sum_checker = SepticBlock([F::zero(); 7]);
            self.cumulative_sum[0] = SepticBlock::from(sums[1].x.0);
            self.cumulative_sum[1] = SepticBlock::from(sums[1].y.0);
        } else {
            self.sum_checker = SepticBlock::from(final_sum_checker.0);
            self.cumulative_sum[0] = SepticBlock::from(final_digest.x.0);
            self.cumulative_sum[1] = SepticBlock::from(final_digest.y.0);
        }
    }
}

impl<F: Field> GlobalAccumulationOperation<F> {
    pub fn eval_accumulation<AB: SP1AirBuilder>(
        builder: &mut AB,
        global_interaction_cols: GlobalInteractionOperation<AB::Var>,
        local_is_real: AB::Var,
        local_index: AB::Var,
        local_accumulation: GlobalAccumulationOperation<AB::Var>,
    ) {
        // First, constrain the control flow regarding `is_real`.
        // Constrain that all `is_real` values are boolean.
        builder.assert_bool(local_is_real);

        // Receive the initial digest.
        builder.receive(
            AirInteraction::new(
                vec![local_index]
                    .into_iter()
                    .chain(
                        local_accumulation.initial_digest.into_iter().flat_map(|septic| septic.0),
                    )
                    .map(Into::into)
                    .collect(),
                local_is_real.into(),
                InteractionKind::GlobalAccumulation,
            ),
            InteractionScope::Local,
        );

        // Next, constrain the accumulation.
        let initial_digest = SepticCurve::<AB::Expr> {
            x: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.initial_digest[0][i].into()
            }),
            y: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.initial_digest[1][i].into()
            }),
        };

        let cumulative_sum = SepticCurve::<AB::Expr> {
            x: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.cumulative_sum[0].0[i].into()
            }),
            y: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.cumulative_sum[1].0[i].into()
            }),
        };

        let point_to_add = SepticCurve::<AB::Expr> {
            x: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                global_interaction_cols.x_coordinate.0[i].into()
            }),
            y: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                global_interaction_cols.y_coordinate.0[i].into()
            }),
        };

        // Constrain that if `is_real = 0`, the sum remains the same.
        // If `is_real == 1`, initial_digest + point_to_add == cumulative_sum must hold.
        // Constrain that `sum_checker_x` and `sum_checker_y` are both zero when `is_real == 1`.
        let sum_checker_x = SepticCurve::<AB::Expr>::sum_checker_x(
            initial_digest.clone(),
            point_to_add.clone(),
            cumulative_sum.clone(),
        );
        let sum_checker_y = SepticCurve::<AB::Expr>::sum_checker_y(
            initial_digest.clone(),
            point_to_add,
            cumulative_sum.clone(),
        );
        let witnessed_sum_checker_x = SepticExtension::<AB::Expr>::from_base_fn(|idx| {
            local_accumulation.sum_checker.0[idx].into()
        });
        // Since `sum_checker_x` is degree 3, we constrain it to be equal to
        // `witnessed_sum_checker_x` first.
        builder.assert_septic_ext_eq(sum_checker_x, witnessed_sum_checker_x.clone());
        // Now we can constrain that when `is_real == 1`, the two `sum_checker` values are zero.
        builder
            .when(local_is_real)
            .assert_septic_ext_eq(witnessed_sum_checker_x, SepticExtension::<AB::Expr>::zero());
        builder
            .when(local_is_real)
            .assert_septic_ext_eq(sum_checker_y, SepticExtension::<AB::Expr>::zero());

        // If `is_real == 0`, initial_digest == cumulative_sum must hold.
        builder
            .when_not(local_is_real)
            .assert_septic_ext_eq(initial_digest.x.clone(), cumulative_sum.x.clone());
        builder.when_not(local_is_real).assert_septic_ext_eq(initial_digest.y, cumulative_sum.y);

        // Send the next digest, with the incremented `index`.
        builder.send(
            AirInteraction::new(
                vec![local_index + AB::Expr::one()]
                    .into_iter()
                    .chain(
                        local_accumulation
                            .cumulative_sum
                            .into_iter()
                            .flat_map(|septic| septic.0)
                            .map(Into::into),
                    )
                    .collect(),
                local_is_real.into(),
                InteractionKind::GlobalAccumulation,
            ),
            InteractionScope::Local,
        );
    }
}
