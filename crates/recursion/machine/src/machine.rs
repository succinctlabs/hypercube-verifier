use hypercube_recursion_executor::D;
use hypercube_stark::{Chip, Machine, PROOF_MAX_NUM_PVS};
use p3_field::{extension::BinomiallyExtendable, PrimeField32};

use strum_macros::EnumDiscriminants;

use crate::chips::{
    alu_base::BaseAluChip,
    alu_ext::ExtAluChip,
    mem::{MemoryConstChip, MemoryVarChip},
    // poseidon2_skinny::Poseidon2SkinnyChip,
    poseidon2_wide::Poseidon2WideChip,
    prefix_sum_checks::PrefixSumChecksChip,
    public_values::PublicValuesChip,
    select::SelectChip,
};

#[derive(sp1_derive::MachineAir, EnumDiscriminants)]
#[sp1_core_path = "hypercube_core_machine"]
#[builder_path = "crate::builder::SP1RecursionAirBuilder<F = F>"]
#[eval_trait_bound = "AB::Var: 'static"]
#[allow(dead_code)]
pub enum RecursionAir<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize> {
    MemoryConst(MemoryConstChip<F>),
    MemoryVar(MemoryVarChip<F>),
    BaseAlu(BaseAluChip),
    ExtAlu(ExtAluChip),
    Poseidon2Wide(Poseidon2WideChip<DEGREE>),
    Select(SelectChip),
    PrefixSumChecks(PrefixSumChecksChip),
    PublicValues(PublicValuesChip),
}

#[allow(dead_code)]
impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize> RecursionAir<F, DEGREE> {
    /// Get a machine with all chips, except the dummy chip.
    pub fn machine_wide_with_all_chips() -> Machine<F, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip),
            RecursionAir::ExtAlu(ExtAluChip),
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>),
            RecursionAir::PrefixSumChecks(PrefixSumChecksChip),
            RecursionAir::Select(SelectChip),
            RecursionAir::PublicValues(PublicValuesChip),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();

        Machine::new(chips, PROOF_MAX_NUM_PVS)
    }
}
