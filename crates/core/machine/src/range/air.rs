use core::borrow::Borrow;

use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::{AbstractField, Field};
use slop_matrix::Matrix;
use sp1_core_executor::ByteOpcode;
use sp1_hypercube::air::SP1AirBuilder;

use super::{
    columns::{RangeMultCols, RangePreprocessedCols, NUM_RANGE_MULT_COLS},
    RangeChip,
};

impl<F: Field> BaseAir<F> for RangeChip<F> {
    fn width(&self) -> usize {
        NUM_RANGE_MULT_COLS
    }
}

impl<AB: SP1AirBuilder + PairBuilder> Air<AB> for RangeChip<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_mult = main.row_slice(0);
        let local_mult: &RangeMultCols<AB::Var> = (*local_mult).borrow();

        let prep = builder.preprocessed();
        let prep = prep.row_slice(0);
        let local: &RangePreprocessedCols<AB::Var> = (*prep).borrow();

        let field_op = ByteOpcode::Range.as_field::<AB::F>();
        let mult = local_mult.multiplicity;
        builder.receive_byte(field_op, local.a, local.bits, AB::F::zero(), mult);
    }
}
