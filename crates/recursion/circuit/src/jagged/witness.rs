use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_jagged::{
    JaggedConfig, JaggedLittlePolynomialVerifierParams, JaggedPcsProof, JaggedSumcheckEvalProof,
};
use slop_multilinear::MultilinearPcsVerifier;
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::ir::Builder;

use crate::{
    basefold::{stacked::RecursiveStackedPcsProof, RecursiveBasefoldProof},
    witness::{WitnessWriter, Witnessable},
    CircuitConfig, SP1FieldConfigVariable,
};

use super::verifier::JaggedPcsProofVariable;

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for JaggedSumcheckEvalProof<T> {
    type WitnessVariable = JaggedSumcheckEvalProof<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        JaggedSumcheckEvalProof {
            partial_sumcheck_proof: self.partial_sumcheck_proof.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.partial_sumcheck_proof.write(witness);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C>
    for JaggedLittlePolynomialVerifierParams<T>
{
    type WitnessVariable = JaggedLittlePolynomialVerifierParams<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        JaggedLittlePolynomialVerifierParams {
            col_prefix_sums: self
                .col_prefix_sums
                .iter()
                .map(|x| (*x).read(builder))
                .collect::<Vec<_>>(),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for x in &self.col_prefix_sums {
            x.write(witness);
        }
    }
}

impl<GC, C, JC: JaggedConfig<GC>> Witnessable<C> for JaggedPcsProof<GC, JC>
where
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + SP1FieldConfigVariable<C>,
    C: CircuitConfig,
    <<JC as JaggedConfig<GC>>::PcsVerifier as MultilinearPcsVerifier<GC>>::Proof: Witnessable<
        C,
        WitnessVariable = RecursiveStackedPcsProof<
            RecursiveBasefoldProof<C, GC>,
            SP1Field,
            SP1ExtensionField,
        >,
    >,
    GC::Digest: Witnessable<C, WitnessVariable = GC::DigestVariable>,
{
    type WitnessVariable =
        JaggedPcsProofVariable<RecursiveBasefoldProof<C, GC>, GC::DigestVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let params = self.params.read(builder);
        let sumcheck_proof = self.sumcheck_proof.read(builder);
        let jagged_eval_proof = self.jagged_eval_proof.read(builder);
        let pcs_proof = self.pcs_proof.read(builder);

        let (row_counts, column_counts): (Vec<Vec<usize>>, Vec<Vec<usize>>) = self
            .row_counts_and_column_counts
            .clone()
            .into_iter()
            .map(|x| x.into_iter().unzip())
            .unzip();
        let row_counts = row_counts
            .into_iter()
            .map(|x| x.into_iter().map(SP1Field::from_canonical_usize).collect::<Vec<_>>())
            .collect::<Vec<_>>()
            .read(builder);
        let original_commitments =
            self.merkle_tree_commitments.clone().into_iter().collect::<Vec<_>>().read(builder);

        JaggedPcsProofVariable {
            pcs_proof,
            sumcheck_proof,
            jagged_eval_proof,
            params,
            column_counts,
            row_counts,
            original_commitments,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.params.write(witness);
        self.sumcheck_proof.write(witness);
        self.jagged_eval_proof.write(witness);
        self.pcs_proof.write(witness);
        self.row_counts_and_column_counts
            .clone()
            .into_iter()
            .map(|x| x.into_iter().map(|x| SP1Field::from_canonical_usize(x.0)).collect::<Vec<_>>())
            .collect::<Vec<_>>()
            .write(witness);
        self.merkle_tree_commitments.write(witness);
    }
}
