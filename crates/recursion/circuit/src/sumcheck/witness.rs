use crate::{
    witness::{WitnessWriter, Witnessable},
    CircuitConfig,
};
use slop_algebra::UnivariatePolynomial;
use slop_multilinear::Point;
use slop_sumcheck::PartialSumcheckProof;
use sp1_recursion_compiler::ir::Builder;

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for PartialSumcheckProof<T> {
    type WitnessVariable = PartialSumcheckProof<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        PartialSumcheckProof {
            univariate_polys: self.univariate_polys.read(builder),
            claimed_sum: self.claimed_sum.read(builder),
            point_and_eval: (
                self.point_and_eval.0.read(builder),
                self.point_and_eval.1.read(builder),
            ),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.univariate_polys.write(witness);
        self.claimed_sum.write(witness);
        self.point_and_eval.0.write(witness);
        self.point_and_eval.1.write(witness);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for UnivariatePolynomial<T> {
    type WitnessVariable = UnivariatePolynomial<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        UnivariatePolynomial { coefficients: self.coefficients.read(builder) }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.coefficients.write(witness);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for Point<T> {
    type WitnessVariable = Point<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        Point::from(self.iter().map(|x| x.read(builder)).collect::<Vec<_>>())
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for x in self.iter() {
            x.write(witness);
        }
    }
}
