use hypercube_recursion_compiler::ir::{Builder, Ext};
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use slop_jagged::{
    JaggedConfig, JaggedEvalConfig, JaggedLittlePolynomialVerifierParams, JaggedPcsProof,
    JaggedSumcheckEvalProof,
};

use crate::{
    witness::{WitnessWriter, Witnessable},
    AsRecursive, CircuitConfig,
};

use super::verifier::{JaggedPcsProofVariable, RecursiveJaggedConfig};

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for JaggedSumcheckEvalProof<T> {
    type WitnessVariable = JaggedSumcheckEvalProof<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        JaggedSumcheckEvalProof {
            branching_program_evals: self
                .branching_program_evals
                .iter()
                .map(|x| x.read(builder))
                .collect(),
            partial_sumcheck_proof: self.partial_sumcheck_proof.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for x in &self.branching_program_evals {
            x.write(witness);
        }
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
            max_log_row_count: self.max_log_row_count,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for x in &self.col_prefix_sums {
            x.write(witness);
        }
    }
}

impl<C, SC, RecursiveStackedPcsProof, RecursiveJaggedEvalProof> Witnessable<C>
    for JaggedPcsProof<SC>
where
    C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
    SC: JaggedConfig<
            F = C::F,
            EF = C::EF,
            BatchPcsProof: Witnessable<C, WitnessVariable = RecursiveStackedPcsProof>,
        > + AsRecursive<C>,
    <<SC as JaggedConfig>::JaggedEvaluator as JaggedEvalConfig<
        C::F,
        C::EF,
        <SC as JaggedConfig>::Challenger,
    >>::JaggedEvalProof: Witnessable<C, WitnessVariable = RecursiveJaggedEvalProof>,
    SC::Recursive: RecursiveJaggedConfig<
        F = C::F,
        EF = C::EF,
        Circuit = C,
        BatchPcsProof = RecursiveStackedPcsProof,
        JaggedEvalProof = RecursiveJaggedEvalProof,
    >,
    C::EF: Witnessable<C, WitnessVariable = Ext<C::F, C::EF>>,
{
    type WitnessVariable = JaggedPcsProofVariable<SC::Recursive>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let params = self.params.read(builder);
        let sumcheck_proof = self.sumcheck_proof.read(builder);
        let jagged_eval_proof = self.jagged_eval_proof.read(builder);
        let stacked_pcs_proof = self.stacked_pcs_proof.read(builder);

        JaggedPcsProofVariable { stacked_pcs_proof, sumcheck_proof, jagged_eval_proof, params }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.params.write(witness);
        self.sumcheck_proof.write(witness);
        self.jagged_eval_proof.write(witness);
        self.stacked_pcs_proof.write(witness);
    }
}
