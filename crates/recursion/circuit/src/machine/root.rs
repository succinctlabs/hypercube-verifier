use std::marker::PhantomData;

use p3_air::Air;
use p3_field::AbstractField;

use super::SP1CompressWitnessVariable;
use crate::{
    basefold::{RecursiveBasefoldConfigImpl, RecursiveBasefoldProof, RecursiveBasefoldVerifier},
    jagged::RecursiveJaggedConfig,
    shard::RecursiveShardVerifier,
    zerocheck::RecursiveVerifierConstraintFolder,
    BabyBearFriConfigVariable, CircuitConfig,
};
use hypercube_recursion_compiler::ir::{Builder, Felt};
use hypercube_recursion_executor::DIGEST_SIZE;
use hypercube_stark::air::MachineAir;

/// A program to verify a single recursive proof representing a complete proof of program execution.
///
/// The root verifier is simply a `SP1CompressVerifier` with an assertion that the `is_complete`
/// flag is set to true.
#[derive(Debug, Clone, Copy)]
pub struct SP1CompressRootVerifier<C, SC, A, JC> {
    _phantom: PhantomData<(C, SC, A, JC)>,
}

/// A program to verify a single recursive proof representing a complete proof of program execution.
///
/// The root verifier is simply a `SP1CompressVerifier` with an assertion that the `is_complete`
/// flag is set to true.
#[derive(Debug, Clone, Copy)]
pub struct SP1CompressRootVerifierWithVKey<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

impl<C, SC, A, JC> SP1CompressRootVerifier<C, SC, A, JC>
where
    SC: BabyBearFriConfigVariable<C> + Send + Sync,
    C: CircuitConfig<F = SC::F, EF = SC::EF>,
    // <SC::ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>: Clone,
    A: MachineAir<SC::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    JC: RecursiveJaggedConfig<
        F = C::F,
        EF = C::EF,
        Circuit = C,
        Commitment = SC::DigestVariable,
        Challenger = SC::FriChallengerVariable,
        BatchPcsProof = RecursiveBasefoldProof<RecursiveBasefoldConfigImpl<C, SC>>,
        BatchPcsVerifier = RecursiveBasefoldVerifier<RecursiveBasefoldConfigImpl<C, SC>>,
    >,
{
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &RecursiveShardVerifier<A, SC, C, JC>,
        input: SP1CompressWitnessVariable<C, SC, JC>,
        _vk_root: [Felt<C::F>; DIGEST_SIZE],
    ) {
        // Assert that the program is complete.
        builder.assert_felt_eq(input.is_complete, C::F::one());
        // // Verify the proof, as a compress proof.
        for (vk, proof) in input.vks_and_proofs {
            let mut challenger = <SC as BabyBearFriConfigVariable<C>>::challenger_variable(builder);
            machine.verify_shard(builder, &vk, &proof, &mut challenger);
        }
    }
}
