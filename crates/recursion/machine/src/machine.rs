use hypercube_recursion_executor::D;
use hypercube_stark::{Chip, Machine, MachineShape, PROOF_MAX_NUM_PVS};
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

        let shape = MachineShape::all(&chips);
        Machine::new(chips, PROOF_MAX_NUM_PVS, shape)
    }
}
//     /// Get a machine with all chips, except the dummy chip.
//     pub fn machine_skinny_with_all_chips() -> Machine<F, Self> {
//         panic!("Not implemented");
//         // let chips = [
//         //     RecursionAir::MemoryConst(MemoryConstChip::default()),
//         //     RecursionAir::MemoryVar(MemoryVarChip::default()),
//         //     RecursionAir::BaseAlu(BaseAluChip),
//         //     RecursionAir::ExtAlu(ExtAluChip),
//         //     RecursionAir::Poseidon2Skinny(Poseidon2SkinnyChip::<DEGREE>::default()),
//         //     // RecursionAir::BatchFRI(BatchFRIChip::<DEGREE>),
//         //     RecursionAir::PrefixSumChecks(PrefixSumChecksChip),
//         //     RecursionAir::Select(SelectChip),
//         //     RecursionAir::PublicValues(PublicValuesChip),
//         // ]
//         // .map(Chip::new)
//         // .into_iter()
//         // .collect::<Vec<_>>();
//         // let shape = MachineShape::all(&chips);
//         // Machine::new(chips, PROOF_MAX_NUM_PVS, shape)
//     }

//     /// A machine with dyunamic chip sizes that includes the wide variant of the Poseidon2 chip.
//     pub fn compress_machine() -> Machine<F, Self> {
//         let chips = [
//             RecursionAir::MemoryConst(MemoryConstChip::default()),
//             RecursionAir::MemoryVar(MemoryVarChip::default()),
//             RecursionAir::BaseAlu(BaseAluChip),
//             RecursionAir::ExtAlu(ExtAluChip),
//             RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>),
//             RecursionAir::PrefixSumChecks(PrefixSumChecksChip),
//             RecursionAir::Select(SelectChip),
//             RecursionAir::PublicValues(PublicValuesChip),
//         ]
//         .map(Chip::new)
//         .into_iter()
//         .collect::<Vec<_>>();
//         let shape = MachineShape::all(&chips);
//         Machine::new(chips, PROOF_MAX_NUM_PVS, shape)
//     }

//     pub fn shrink_machine() -> Machine<F, Self> {
//         Self::compress_machine()
//     }

//     /// A machine with dynamic chip sizes that includes the skinny variant of the Poseidon2 chip.
//     ///
//     /// This machine assumes that the `shrink` stage has a fixed shape, so there is no need to
//     /// fix the trace sizes.
//     pub fn wrap_machine() -> Machine<F, Self> {
//         let chips = [
//             RecursionAir::MemoryConst(MemoryConstChip::default()),
//             RecursionAir::MemoryVar(MemoryVarChip::default()),
//             RecursionAir::BaseAlu(BaseAluChip),
//             RecursionAir::ExtAlu(ExtAluChip),
//             RecursionAir::Poseidon2Skinny(Poseidon2SkinnyChip::<DEGREE>::default()),
//             RecursionAir::PrefixSumChecks(PrefixSumChecksChip),
//             RecursionAir::Select(SelectChip),
//             RecursionAir::PublicValues(PublicValuesChip),
//         ]
//         .map(Chip::new)
//         .into_iter()
//         .collect::<Vec<_>>();
//         let shape = MachineShape::all(&chips);
//         Machine::new(chips, PROOF_MAX_NUM_PVS, shape)
//     }

//     pub fn heights(program: &RecursionProgram<F>) -> Vec<(String, usize)> {
//         let heights =
//             program.inner.iter().fold(RecursionAirEventCount::default(), |heights, instruction| {
//                 heights + instruction.inner()
//             });

//         [
//             (
//                 Self::MemoryConst(MemoryConstChip::default()),
//                 heights.mem_const_events.div_ceil(NUM_CONST_MEM_ENTRIES_PER_ROW),
//             ),
//             (
//                 Self::MemoryVar(MemoryVarChip::default()),
//                 heights.mem_var_events.div_ceil(NUM_VAR_MEM_ENTRIES_PER_ROW),
//             ),
//             (
//                 Self::BaseAlu(BaseAluChip),
//                 heights.base_alu_events.div_ceil(NUM_BASE_ALU_ENTRIES_PER_ROW),
//             ),
//             (
//                 Self::ExtAlu(ExtAluChip),
//                 heights.ext_alu_events.div_ceil(NUM_EXT_ALU_ENTRIES_PER_ROW),
//             ),
//             (Self::Poseidon2Wide(Poseidon2WideChip::<DEGREE>), heights.poseidon2_wide_events),
//             (Self::PrefixSumChecks(PrefixSumChecksChip), heights.prefix_sum_checks_events),
//             (Self::Select(SelectChip), heights.select_events),
//             (Self::PublicValues(PublicValuesChip), PUB_VALUES_LOG_HEIGHT),
//         ]
//         .map(|(chip, log_height)| (chip.name(), log_height))
//         .to_vec()
//     }
// }
