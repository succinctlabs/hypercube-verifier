// use hypercube_recursion_executor::{
//     BaseAluInstr, BaseAluIo, Block, CommitPublicValuesEvent, CommitPublicValuesInstr, ExtAluInstr,
//     ExtAluIo, Poseidon2Event, Poseidon2Instr, SelectEvent, SelectInstr,
// };
// use p3_baby_bear::BabyBear;

// use crate::chips::{
//     alu_base::{BaseAluAccessCols, BaseAluValueCols},
//     alu_ext::{ExtAluAccessCols, ExtAluValueCols},
//     poseidon2_skinny::columns::{preprocessed::Poseidon2PreprocessedColsSkinny, Poseidon2},
//     poseidon2_wide::columns::preprocessed::Poseidon2PreprocessedColsWide,
//     public_values::{PublicValuesCols, PublicValuesPreprocessedCols},
//     select::{SelectCols, SelectPreprocessedCols},
// };

// #[link(name = "sp1-recursion-machine-sys", kind = "static")]
// extern "C-unwind" {
//     pub fn alu_base_event_to_row_babybear(
//         io: &BaseAluIo<BabyBear>,
//         cols: &mut BaseAluValueCols<BabyBear>,
//     );
//     pub fn alu_base_instr_to_row_babybear(
//         instr: &BaseAluInstr<BabyBear>,
//         cols: &mut BaseAluAccessCols<BabyBear>,
//     );

//     pub fn alu_ext_event_to_row_babybear(
//         io: &ExtAluIo<Block<BabyBear>>,
//         cols: &mut ExtAluValueCols<BabyBear>,
//     );
//     pub fn alu_ext_instr_to_row_babybear(
//         instr: &ExtAluInstr<BabyBear>,
//         cols: &mut ExtAluAccessCols<BabyBear>,
//     );

//     pub fn public_values_event_to_row_babybear(
//         io: &CommitPublicValuesEvent<BabyBear>,
//         digest_idx: usize,
//         cols: &mut PublicValuesCols<BabyBear>,
//     );
//     pub fn public_values_instr_to_row_babybear(
//         instr: &CommitPublicValuesInstr<BabyBear>,
//         digest_idx: usize,
//         cols: &mut PublicValuesPreprocessedCols<BabyBear>,
//     );

//     pub fn select_event_to_row_babybear(
//         io: &SelectEvent<BabyBear>,
//         cols: &mut SelectCols<BabyBear>,
//     );
//     pub fn select_instr_to_row_babybear(
//         instr: &SelectInstr<BabyBear>,
//         cols: &mut SelectPreprocessedCols<BabyBear>,
//     );

//     pub fn poseidon2_skinny_event_to_row_babybear(
//         io: &Poseidon2Event<BabyBear>,
//         cols: *mut Poseidon2<BabyBear>,
//     );
//     pub fn poseidon2_skinny_instr_to_row_babybear(
//         instr: &Poseidon2Instr<BabyBear>,
//         i: usize,
//         cols: &mut Poseidon2PreprocessedColsSkinny<BabyBear>,
//     );

//     pub fn poseidon2_wide_event_to_row_babybear(
//         input: *const BabyBear,
//         input_row: *mut BabyBear,
//         sbox_state: bool,
//     );
//     pub fn poseidon2_wide_instr_to_row_babybear(
//         instr: &Poseidon2Instr<BabyBear>,
//         cols: &mut Poseidon2PreprocessedColsWide<BabyBear>,
//     );
// }
