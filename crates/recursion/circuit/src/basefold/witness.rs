use crate::{
    basefold::tcs::RecursiveTensorCsOpening,
    hash::FieldHasherVariable,
    witness::{WitnessWriter, Witnessable},
    CircuitConfig, SP1FieldConfigVariable,
};
use slop_alloc::Buffer;
use slop_basefold::BasefoldProof;
use slop_challenger::{GrindingChallenger, IopCtx};
use slop_merkle_tree::{MerkleTreeOpeningAndProof, MerkleTreeTcsProof};
use slop_multilinear::{Evaluations, Mle, MleEval};
use slop_stacked::StackedPcsProof;
use slop_tensor::Tensor;
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::ir::{Builder, Felt};

use super::{stacked::RecursiveStackedPcsProof, RecursiveBasefoldProof};

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

impl<GC: IopCtx<F = SP1Field>, C: CircuitConfig> Witnessable<C> for MerkleTreeOpeningAndProof<GC>
where
    GC::Digest: Witnessable<C>,
{
    type WitnessVariable =
        RecursiveTensorCsOpening<<GC::Digest as Witnessable<C>>::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let values: Tensor<Felt<SP1Field>> = self.values.read(builder);
        let proof = self.proof.read(builder);
        RecursiveTensorCsOpening::<<GC::Digest as Witnessable<C>>::WitnessVariable> {
            values,
            proof: proof.paths,
            merkle_root: proof.merkle_root,
            log_height: proof.log_tensor_height,
            width: proof.width,
        }
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
        let merkle_root = self.merkle_root.read(builder);
        MerkleTreeTcsProof {
            paths,
            merkle_root,
            log_tensor_height: self.log_tensor_height,
            width: self.width,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.paths.write(witness);
        self.merkle_root.write(witness);
    }
}

impl<C, GC> Witnessable<C> for BasefoldProof<GC>
where
    C: CircuitConfig,
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + SP1FieldConfigVariable<C>,
    <GC::Challenger as GrindingChallenger>::Witness:
        Witnessable<C, WitnessVariable = Felt<SP1Field>>,
    <GC as IopCtx>::Digest:
        Witnessable<C, WitnessVariable = <GC as FieldHasherVariable<C>>::DigestVariable>,
    MerkleTreeOpeningAndProof<GC>: Witnessable<
        C,
        WitnessVariable = RecursiveTensorCsOpening<<GC as FieldHasherVariable<C>>::DigestVariable>,
    >,
{
    type WitnessVariable = RecursiveBasefoldProof<C, GC>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let univariate_messages = self.univariate_messages.read(builder);
        let fri_commitments = self.fri_commitments.read(builder);
        let component_polynomials_query_openings =
            self.component_polynomials_query_openings_and_proofs.read(builder);
        let query_phase_openings = self.query_phase_openings_and_proofs.read(builder);
        let final_poly = self.final_poly.read(builder);
        let pow_witness = self.pow_witness.read(builder);
        RecursiveBasefoldProof::<C, GC> {
            univariate_messages,
            fri_commitments,
            component_polynomials_query_openings_and_proofs: component_polynomials_query_openings,
            query_phase_openings_and_proofs: query_phase_openings,
            final_poly,
            pow_witness,
        }
    }
    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.univariate_messages.write(witness);
        self.fri_commitments.write(witness);
        self.component_polynomials_query_openings_and_proofs.write(witness);
        self.query_phase_openings_and_proofs.write(witness);
        self.final_poly.write(witness);
        self.pow_witness.write(witness);
    }
}

impl<C, PcsProof, RecursivePcsProof> Witnessable<C> for StackedPcsProof<PcsProof, SP1ExtensionField>
where
    C: CircuitConfig,
    PcsProof: Witnessable<C, WitnessVariable = RecursivePcsProof>,
{
    type WitnessVariable = RecursiveStackedPcsProof<RecursivePcsProof, SP1Field, SP1ExtensionField>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let batch_evaluations = self.batch_evaluations.read(builder);
        let pcs_proof = self.pcs_proof.read(builder);
        RecursiveStackedPcsProof::<RecursivePcsProof, SP1Field, SP1ExtensionField> {
            pcs_proof,
            batch_evaluations,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.batch_evaluations.write(witness);
        self.pcs_proof.write(witness);
    }
}
