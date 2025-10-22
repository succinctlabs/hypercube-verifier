use slop_algebra::{ExtensionField, Field};

use crate::{
    ir::{ExprExtRef, ExprRef, Shape},
    Word,
};

impl<F: Field, EF: ExtensionField<F>> From<()> for Shape<ExprRef<F>, ExprExtRef<EF>> {
    fn from(_val: ()) -> Self {
        Shape::Unit
    }
}

impl<F: Field, EF: ExtensionField<F>> From<ExprRef<F>> for Shape<ExprRef<F>, ExprExtRef<EF>> {
    fn from(val: ExprRef<F>) -> Self {
        Shape::Expr(val)
    }
}

impl<F: Field, EF: ExtensionField<F>> From<ExprExtRef<EF>> for Shape<ExprRef<F>, ExprExtRef<EF>> {
    fn from(val: ExprExtRef<EF>) -> Self {
        Shape::ExprExt(val)
    }
}

impl<F: Field, EF: ExtensionField<F>, T: Into<ExprRef<F>>> From<Word<T>>
    for Shape<ExprRef<F>, ExprExtRef<EF>>
{
    fn from(val: Word<T>) -> Self {
        let [a, b, c, d] = val.0;
        Shape::Word([a.into(), b.into(), c.into(), d.into()])
    }
}

impl<
        F: Field,
        EF: ExtensionField<F>,
        T: Into<Shape<ExprRef<F>, ExprExtRef<EF>>>,
        const N: usize,
    > From<[T; N]> for Shape<ExprRef<F>, ExprExtRef<EF>>
{
    fn from(val: [T; N]) -> Self {
        Shape::Array(val.map(|x| Box::new(x.into())).to_vec())
    }
}
