use std::collections::BTreeMap;

use slop_algebra::{ExtensionField, Field};
use slop_multilinear::{Mle, Point};

use crate::utils::vector_to_bit_matrix;

// A representation of a sparse polynomial
pub struct SparsePolynomial<F: Field> {
    // the i-th coefficient is the coeff of the eval of f(bin(i))
    pub values: BTreeMap<usize, F>,
    pub num_variables: usize,
}

// Implement a function that takes as input a Btree map and pads it to the desired length by adding
// zeros
fn pad_btree_map<F: Field>(map: &mut BTreeMap<usize, F>, desired_length: usize) {
    let mut i = 0;
    while map.len() < desired_length {
        map.entry(i).or_insert_with(F::zero);
        i += 1;
    }
    assert_eq!(map.len(), desired_length);
}

impl<F: Field> SparsePolynomial<F> {
    pub fn new(values: Vec<(usize, F)>, num_variables: usize) -> Self {
        // Check the values are well formed
        assert!(values.iter().map(|(index, _)| index).all(|i| *i < 1 << num_variables));

        let sparsity = values.len().next_power_of_two();
        let mut values = values.into_iter().collect();
        pad_btree_map(&mut values, sparsity);
        SparsePolynomial { values, num_variables }
    }

    // Dense repr of the value MLE
    pub fn val_mle<EF>(&self) -> Mle<EF>
    where
        EF: ExtensionField<F>,
    {
        self.values.values().map(|i| EF::from_base(*i)).collect::<Vec<_>>().into()
    }

    // Dense repr of the value MLE
    pub fn index_mles<EF>(&self) -> Vec<Mle<EF>>
    where
        EF: ExtensionField<F>,
    {
        vector_to_bit_matrix::<EF>(self.values.keys(), self.values.len(), self.num_variables)
            .into_iter()
            .map(|i| i.into())
            .collect()
    }

    pub fn eval_at<EF>(&self, point: &Point<EF>) -> EF
    where
        EF: ExtensionField<F>,
    {
        assert_eq!(point.dimension(), self.num_variables);
        self.values
            .iter()
            .map(|(index, val)| {
                Mle::full_lagrange_eval(point, &Point::<EF>::from_usize(*index, self.num_variables))
                    * *val
            })
            .sum()
    }

    pub fn dense_repr(&self) -> Mle<F> {
        (0..1 << self.num_variables)
            .map(|i| self.values.get(&i).copied().unwrap_or(F::zero()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::BabyBear;
    use slop_multilinear::Point;

    use super::SparsePolynomial;

    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;

    #[tokio::test]
    async fn test_consistency_with_mle() {
        let mut rng = rand::thread_rng();

        let log_sparsity = 8;
        let num_variables = 16;
        let sparsity = 1 << log_sparsity;

        let coeffs: Vec<_> =
            (0..sparsity).map(|_| (rng.gen_range(0..1 << num_variables), rng.gen::<F>())).collect();

        let sparse = SparsePolynomial::new(coeffs, num_variables);

        let alpha = Point::new((0..num_variables).map(|_| rng.gen::<EF>()).collect());

        assert_eq!(sparse.eval_at(&alpha), sparse.dense_repr().eval_at(&alpha).await[0])
    }
}
