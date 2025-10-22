use slop_jagged::Poseidon2Bn254JaggedCpuProverComponents;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{
    prover::{CpuMachineProverComponents, MachineProverComponents},
    MachineVerifier, SP1CpuJaggedProverComponents,
};
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext, SP1OuterGlobalContext};
use sp1_recursion_circuit::machine::InnerVal;

use crate::{
    core::CoreProverComponents,
    recursion::{RecursionProverComponents, WrapProverComponents},
    CompressAir, CoreSC, InnerSC, OuterSC, WrapAir,
};

pub struct SP1Config {}

pub type CoreProver<C> = <<C as SP1ProverComponents>::CoreComponents as MachineProverComponents<
    SP1GlobalContext,
>>::Prover;

pub type RecursionProver<C> =
    <<C as SP1ProverComponents>::RecursionComponents as MachineProverComponents<
        SP1GlobalContext,
    >>::Prover;

pub type WrapProver<C> = <<C as SP1ProverComponents>::WrapComponents as MachineProverComponents<
    SP1OuterGlobalContext,
>>::Prover;

pub trait SP1ProverComponents: Send + Sync + 'static {
    /// The prover for making SP1 core proofs.
    type CoreComponents: CoreProverComponents;
    /// The prover for making SP1 recursive proofs.
    type RecursionComponents: RecursionProverComponents;
    type WrapComponents: WrapProverComponents;

    fn core_verifier() -> MachineVerifier<SP1GlobalContext, CoreSC, RiscvAir<SP1Field>> {
        <Self::CoreComponents as CoreProverComponents>::verifier()
    }

    fn compress_verifier() -> MachineVerifier<SP1GlobalContext, InnerSC, CompressAir<InnerVal>> {
        <Self::RecursionComponents as RecursionProverComponents>::verifier()
    }

    fn shrink_verifier() -> MachineVerifier<SP1GlobalContext, InnerSC, CompressAir<InnerVal>> {
        <Self::RecursionComponents as RecursionProverComponents>::shrink_verifier()
    }

    fn wrap_verifier() -> MachineVerifier<SP1OuterGlobalContext, OuterSC, WrapAir<InnerVal>> {
        <Self::WrapComponents as WrapProverComponents>::wrap_verifier()
    }
}

pub struct CpuSP1ProverComponents;

impl SP1ProverComponents for CpuSP1ProverComponents {
    type CoreComponents = CpuMachineProverComponents<
        SP1GlobalContext,
        SP1CpuJaggedProverComponents,
        RiscvAir<SP1Field>,
    >;
    type RecursionComponents = CpuMachineProverComponents<
        SP1GlobalContext,
        SP1CpuJaggedProverComponents,
        CompressAir<SP1Field>,
    >;
    type WrapComponents = CpuMachineProverComponents<
        SP1OuterGlobalContext,
        Poseidon2Bn254JaggedCpuProverComponents<SP1Field, SP1ExtensionField>,
        WrapAir<SP1Field>,
    >;
}
