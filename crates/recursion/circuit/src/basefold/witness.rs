use crate::{
    basefold::tcs::{RecursiveTcs, RecursiveTensorCsOpening},
    witness::{WitnessWriter, Witnessable},
    AsRecursive, CircuitConfig,
};
use hypercube_recursion_compiler::ir::{Builder, Ext, Felt};
use p3_challenger::GrindingChallenger;
use slop_alloc::Buffer;
use slop_basefold::{BasefoldConfig, BasefoldProof};
use slop_commit::{TensorCs, TensorCsOpening};
use slop_merkle_tree::MerkleTreeTcsProof;
use slop_multilinear::{Evaluations, Mle, MleEval};
use slop_stacked::StackedPcsProof;
use slop_tensor::Tensor;

use super::{stacked::RecursiveStackedPcsProof, RecursiveBasefoldConfig, RecursiveBasefoldProof};

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for Tensor<T> {
    type WitnessVariable = Tensor<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        Tensor {
            storage: Buffer::from(
                self.as_slice().iter().map(|x| x.read(builder)).collect::<Vec<_>>(),
            ),
            dimensions: self.dimensions.clone(),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for x in self.as_slice() {
            x.write(witness);
        }
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for Mle<T> {
    type WitnessVariable = Mle<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let guts = self.guts().read(builder);
        Mle::new(guts)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.guts().write(witness);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for MleEval<T> {
    type WitnessVariable = MleEval<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let evaluations = self.evaluations().read(builder);
        MleEval::new(evaluations)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.evaluations().write(witness);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for Evaluations<T> {
    type WitnessVariable = Evaluations<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let round_evaluations = self.round_evaluations.read(builder);
        Evaluations { round_evaluations }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.round_evaluations.write(witness);
    }
}

impl<C, TC> Witnessable<C> for TensorCsOpening<TC>
where
    C: CircuitConfig,
    TC: TensorCs<Data = C::F> + AsRecursive<C>,
    <TC as TensorCs>::Proof: Witnessable<C>,
    TC::Recursive: RecursiveTcs<
        Data = Felt<C::F>,
        Proof = <<TC as TensorCs>::Proof as Witnessable<C>>::WitnessVariable,
    >,
    C::F: Witnessable<C, WitnessVariable = Felt<C::F>>,
{
    type WitnessVariable = RecursiveTensorCsOpening<TC::Recursive>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let values: Tensor<Felt<C::F>> = self.values.read(builder);
        let proof = self.proof.read(builder);
        RecursiveTensorCsOpening::<TC::Recursive> { values, proof }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.values.write(witness);
        self.proof.write(witness);
    }
}

impl<C, T> Witnessable<C> for MerkleTreeTcsProof<T>
where
    C: CircuitConfig,
    T: Witnessable<C>,
{
    type WitnessVariable = MerkleTreeTcsProof<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let paths = self.paths.read(builder);
        MerkleTreeTcsProof { paths }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.paths.write(witness);
    }
}

impl<C, BC> Witnessable<C> for BasefoldProof<BC>
where
    C: CircuitConfig,
    C::EF: Witnessable<C, WitnessVariable = Ext<C::F, C::EF>>,
    BC: BasefoldConfig<F = C::F, EF = C::EF> + AsRecursive<C>,
    <BC::Challenger as GrindingChallenger>::Witness: Witnessable<C, WitnessVariable = Felt<C::F>>,
    BC::Recursive: RecursiveBasefoldConfig<F = C::F, EF = C::EF, Circuit = C>,
    BC::Commitment:
        Witnessable<C, WitnessVariable = <BC::Recursive as RecursiveBasefoldConfig>::Commitment>,
    TensorCsOpening<BC::Tcs>: Witnessable<
        C,
        WitnessVariable = RecursiveTensorCsOpening<<BC::Recursive as RecursiveBasefoldConfig>::Tcs>,
    >,
{
    type WitnessVariable = RecursiveBasefoldProof<BC::Recursive>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let univariate_messages = self.univariate_messages.read(builder);
        let fri_commitments = self.fri_commitments.read(builder);
        let component_polynomials_query_openings =
            self.component_polynomials_query_openings.read(builder);
        let query_phase_openings = self.query_phase_openings.read(builder);
        let final_poly = self.final_poly.read(builder);
        let pow_witness = self.pow_witness.read(builder);
        RecursiveBasefoldProof::<BC::Recursive> {
            univariate_messages,
            fri_commitments,
            component_polynomials_query_openings,
            query_phase_openings,
            final_poly,
            pow_witness,
        }
    }
    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.univariate_messages.write(witness);
        self.fri_commitments.write(witness);
        self.component_polynomials_query_openings.write(witness);
        self.query_phase_openings.write(witness);
        self.final_poly.write(witness);
        self.pow_witness.write(witness);
    }
}

impl<C, PcsProof, RecursivePcsProof, EF> Witnessable<C> for StackedPcsProof<PcsProof, EF>
where
    C: CircuitConfig<EF = EF>,
    C::EF: Witnessable<C, WitnessVariable = Ext<C::F, C::EF>>,
    PcsProof: Witnessable<C, WitnessVariable = RecursivePcsProof>,
{
    type WitnessVariable = RecursiveStackedPcsProof<RecursivePcsProof, C::F, C::EF>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let batch_evaluations = self.batch_evaluations.read(builder);
        let pcs_proof = self.pcs_proof.read(builder);
        RecursiveStackedPcsProof::<RecursivePcsProof, C::F, C::EF> { pcs_proof, batch_evaluations }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.batch_evaluations.write(witness);
        self.pcs_proof.write(witness);
    }
}
