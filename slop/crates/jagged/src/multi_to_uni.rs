use slop_algebra::{interpolate_univariate_polynomial, Field, UnivariatePolynomial};
use slop_multilinear::Point;
pub struct MultiToUni<F> {
    pub polys: Vec<UnivariatePolynomial<F>>,
}

impl<F: Field> MultiToUni<F> {
    pub fn new(num_bits: usize) -> Self {
        let mut polys = Vec::with_capacity(1 << num_bits);
        let xs = (0..(1 << num_bits)).map(F::from_canonical_u32).collect::<Vec<_>>();
        for j in 0..num_bits {
            let ys = (0..(1 << num_bits))
                .map(|i| F::from_canonical_u32((i >> j) & 1))
                .collect::<Vec<_>>();
            polys.push(interpolate_univariate_polynomial(&xs, &ys));
        }
        // Arrange them so that the first polynomial corresponds to the most significant bit.
        polys.reverse();
        Self { polys }
    }

    pub fn evaluate(&self, x: F) -> Point<F> {
        self.polys.iter().map(|poly| poly.eval_at_point(x)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slop_algebra::AbstractField;
    use slop_baby_bear::BabyBear;
    use slop_multilinear::Point;

    #[test]
    fn test_multi_to_uni() {
        let num_bits = 6;
        let multi_to_uni = MultiToUni::<BabyBear>::new(num_bits);
        for i in 0..(1 << num_bits) {
            let x = BabyBear::from_canonical_usize(i);
            let expected = Point::from_usize(i, num_bits);
            let actual = multi_to_uni.evaluate(x);
            assert_eq!(expected, actual);
        }
    }
}
