pub mod load;
pub mod store;

// #[cfg(test)]
// mod tests {
//     use std::borrow::BorrowMut;

//     use sp1_primitives::SP1Field;
//     use slop_algebra::AbstractField;
//     use slop_matrix::dense::RowMajorMatrix;
//     use sp1_core_executor::{
//         events::MemoryRecordEnum, ExecutionRecord, Instruction, Opcode, Program,
//     };
//     use sp1_hypercube::{
//         air::MachineAir, koala_bear_poseidon2::SP1CoreJaggedConfig, chip_name, CpuProver,
//         MachineProver, Val,
//     };

//     use crate::{
//         io::SP1Stdin,
//         memory::{columns::MemoryInstructionsColumns, MemoryInstructionsChip},
//         riscv::RiscvAir,
//         utils::run_malicious_test,
//     };

//     enum FailureType {
//         ConstraintsFailing,
//         // TODO: Re-enable when we LOGUP-GKR working.
//         // CumulativeSumFailing,
//     }

//     struct TestCase {
//         opcode: Opcode,
//         incorrect_value: u32,
//         failure_type: FailureType,
//     }

//     #[test]
//     fn test_malicious_stores() {
//         let test_cases = vec![
//             TestCase {
//                 opcode: Opcode::SW,
//                 incorrect_value: 8,
//                 failure_type: FailureType::ConstraintsFailing,
//             }, // The correct value is 0xDEADBEEF.
//             TestCase {
//                 opcode: Opcode::SH,
//                 incorrect_value: 0xDEADBEEF,
//                 failure_type: FailureType::ConstraintsFailing,
//             }, // The correct value is 0xBEEF.
//             TestCase {
//                 opcode: Opcode::SB,
//                 incorrect_value: 0xDEADBEEF,
//                 failure_type: FailureType::ConstraintsFailing,
//             }, // The correct value is 0xEF.
//         ];

//         for test_case in test_cases {
//             let instructions = vec![
//                 Instruction::new(Opcode::ADD, 29, 0, 0xDEADBEEF, false, true), // Set the stored
// value to 5.                 Instruction::new(Opcode::ADD, 30, 0, 100, false, true), // Set the
// address to 100.                 Instruction::new(test_case.opcode, 29, 30, 0, false, true),
//             ];
//             let program = Program::new(instructions, 0, 0);
//             let stdin = SP1Stdin::new();

//             type P = CpuProver<SP1CoreJaggedConfig, RiscvAir<SP1Field>>;

//             let malicious_trace_pv_generator =
//                 move |prover: &P,
//                       record: &mut ExecutionRecord|
//                       -> Vec<(String, RowMajorMatrix<Val<SP1CoreJaggedConfig>>)> {
//                     // Create a malicious record where the incorrect value is saved to memory.
//                     let mut malicious_record = record.clone();
//                     if let MemoryRecordEnum::Write(mem_write_record) =
//                         &mut malicious_record.memory_instr_events[0].mem_access
//                     {
//                         mem_write_record.value = test_case.incorrect_value;
//                     }
//                     prover.generate_traces(&malicious_record)
//                 };

//             let result =
//                 run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));

//             match test_case.failure_type {
//                 FailureType::ConstraintsFailing => {
//                     assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
//                 } // TODO: Re-enable when we LOGUP-GKR working.
//                   // FailureType::CumulativeSumFailing => {
//                   //     assert!(
//                   //         result.is_err() &&
// result.unwrap_err().is_local_cumulative_sum_failing()                   //     );
//                   // }
//             }
//         }
//     }

//     #[test]
//     fn test_malicious_loads() {
//         let test_cases = vec![
//             TestCase {
//                 opcode: Opcode::LW,
//                 incorrect_value: 8,
//                 failure_type: FailureType::ConstraintsFailing,
//             }, // The correct value is 0xDEADBEEF.
//             // TODO: Re-enable when we LOGUP-GKR working v6.
//             // TestCase {
//             //     opcode: Opcode::LH,
//             //     incorrect_value: 0xDEADBEEF,
//             //     failure_type: FailureType::CumulativeSumFailing,
//             // }, // The correct value is 0xFFFFBEEF.
//             TestCase {
//                 opcode: Opcode::LHU,
//                 incorrect_value: 0xDEADBEEF,
//                 failure_type: FailureType::ConstraintsFailing,
//             }, // The correct value is 0xBEEF.
//             // TODO: Re-enable when we LOGUP-GKR working v6.
//             // TestCase {
//             //     opcode: Opcode::LB,
//             //     incorrect_value: 0xDEADBEEF,
//             //     failure_type: FailureType::CumulativeSumFailing,
//             // }, // The correct value is 0xEF.
//             TestCase {
//                 opcode: Opcode::LBU,
//                 incorrect_value: 0xDEADBEEF,
//                 failure_type: FailureType::ConstraintsFailing,
//             }, // The correct value is 0xFFFFEF.
//         ];

//         for test_case in test_cases {
//             let instructions = vec![
//                 Instruction::new(Opcode::ADD, 29, 0, 0xDEADBEEF, false, true), // Set the stored
// value to 0xDEADBEEF.                 Instruction::new(Opcode::ADD, 30, 0, 100, false, true), //
// Set the address to 100.                 Instruction::new(Opcode::SW, 29, 30, 0, false, true), //
// Store the value to memory.                 Instruction::new(test_case.opcode, 25, 30, 0, false,
// true), // Load the value from memory.             ];
//             let program = Program::new(instructions, 0, 0);
//             let stdin = SP1Stdin::new();

//             type P = CpuProver<SP1CoreJaggedConfig, RiscvAir<SP1Field>>;

//             let malicious_trace_pv_generator =
//                 move |prover: &P,
//                       record: &mut ExecutionRecord|
//                       -> Vec<(String, RowMajorMatrix<Val<SP1CoreJaggedConfig>>)> {
//                     // Create a malicious record where the incorrect value is loaded from memory.
//                     let mut malicious_record = record.clone();
//                     malicious_record.cpu_events[3].a = test_case.incorrect_value;
//                     malicious_record.memory_instr_events[1].a = test_case.incorrect_value;
//                     prover.generate_traces(&malicious_record)
//                 };

//             let result =
//                 run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));

//             match test_case.failure_type {
//                 FailureType::ConstraintsFailing => {
//                     assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
//                 } // TODO: Re-enable when we LOGUP-GKR working.
//                   // FailureType::CumulativeSumFailing => {
//                   //     assert!(
//                   //         result.is_err() &&
// result.unwrap_err().is_local_cumulative_sum_failing()                   //     );
//                   // }
//             }
//         }
//     }

//     #[test]
//     fn test_malicious_multiple_opcode_flags() {
//         let instructions = vec![
//             Instruction::new(Opcode::ADD, 29, 0, 5, false, true), // Set the stored value to 5.
//             Instruction::new(Opcode::ADD, 30, 0, 100, false, true), // Set the address to 100.
//             Instruction::new(Opcode::SW, 29, 30, 0, false, true),
//         ];
//         let program = Program::new(instructions, 0, 0);
//         let stdin = SP1Stdin::new();

//         type P = CpuProver<SP1CoreJaggedConfig, RiscvAir<SP1Field>>;

//         let malicious_trace_pv_generator =
//             |prover: &P,
//              record: &mut ExecutionRecord|
//              -> Vec<(String, RowMajorMatrix<Val<SP1CoreJaggedConfig>>)> {
//                 // Modify the branch chip to have a row that has multiple opcode flags set.
//                 let mut traces = prover.generate_traces(record);
//                 let memory_instr_chip_name = chip_name!(MemoryInstructionsChip, SP1Field);
//                 for (chip_name, trace) in traces.iter_mut() {
//                     if *chip_name == memory_instr_chip_name {
//                         let first_row: &mut [SP1Field] = trace.row_mut(0);
//                         let first_row: &mut MemoryInstructionsColumns<SP1Field> =
//                             first_row.borrow_mut();
//                         assert!(first_row.is_sw == SP1Field::one());
//                         first_row.is_lw = SP1Field::one();
//                     }
//                 }
//                 traces
//             };

//         let result =
//             run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
//         assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
//     }
// }
