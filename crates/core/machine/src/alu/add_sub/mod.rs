pub mod add;
pub mod addi;
pub mod addw;
pub mod sub;
pub mod subw;
// #[cfg(test)]
// mod tests {
//     #![allow(clippy::print_stdout)]

//     use sp1_primitives::SP1Field;
//     use slop_matrix::dense::RowMajorMatrix;
//     use rand::{thread_rng, Rng};
//     use sp1_core_executor::{
//         events::{AluEvent, MemoryRecordEnum},
//         ExecutionRecord, Instruction, Opcode, DEFAULT_PC_INC,
//     };
//     use sp1_hypercube::{
//         air::{MachineAir, SP1_PROOF_NUM_PV_ELTS},
//         koala_bear_poseidon2::SP1CoreJaggedConfig,
//         chip_name, Chip, CpuProver, MachineProver, StarkMachine, Val,
//     };
//     use std::sync::LazyLock;

//     use super::*;
//     use crate::{
//         io::SP1Stdin,
//         riscv::RiscvAir,
//         utils::{run_malicious_test, run_test_machine, setup_test_machine},
//     };

//     /// Lazily initialized record for use across multiple tests.
//     /// Consists of random `ADD` and `SUB` instructions.
//     static SHARD: LazyLock<ExecutionRecord> = LazyLock::new(|| {
//         let add_events = (0..1)
//             .flat_map(|i| {
//                 [{
//                     let operand_1 = 1u32;
//                     let operand_2 = 2u32;
//                     let result = operand_1.wrapping_add(operand_2);
//                     AluEvent::new(i % 2, Opcode::ADD, result, operand_1, operand_2, false)
//                 }]
//             })
//             .collect::<Vec<_>>();
//         let _sub_events = (0..255)
//             .flat_map(|i| {
//                 [{
//                     let operand_1 = thread_rng().gen_range(0..u32::MAX);
//                     let operand_2 = thread_rng().gen_range(0..u32::MAX);
//                     let result = operand_1.wrapping_add(operand_2);
//                     AluEvent::new(i % 2, Opcode::SUB, result, operand_1, operand_2, false)
//                 }]
//             })
//             .collect::<Vec<_>>();
//         ExecutionRecord { add_events, ..Default::default() }
//     });

//     #[test]
//     fn generate_trace() {
//         let mut shard = ExecutionRecord::default();
//         shard.add_events = vec![AluEvent::new(0, Opcode::ADD, 14, 8, 6, false)];
//         let chip = AddSubChip::default();
//         let trace: RowMajorMatrix<SP1Field> =
//             chip.generate_trace(&shard, &mut ExecutionRecord::default());
//         println!("{:?}", trace.values)
//     }

//     #[test]
//     fn prove_koalabear() {
//         let mut shard = ExecutionRecord::default();
//         for i in 0..1 {
//             let operand_1 = thread_rng().gen_range(0..u32::MAX);
//             let operand_2 = thread_rng().gen_range(0..u32::MAX);
//             let result = operand_1.wrapping_add(operand_2);
//             shard.add_events.push(AluEvent::new(
//                 i * DEFAULT_PC_INC,
//                 Opcode::ADD,
//                 result,
//                 operand_1,
//                 operand_2,
//                 false,
//             ));
//         }
//         for i in 0..255 {
//             let operand_1 = thread_rng().gen_range(0..u32::MAX);
//             let operand_2 = thread_rng().gen_range(0..u32::MAX);
//             let result = operand_1.wrapping_sub(operand_2);
//             shard.add_events.push(AluEvent::new(
//                 i * DEFAULT_PC_INC,
//                 Opcode::SUB,
//                 result,
//                 operand_1,
//                 operand_2,
//                 false,
//             ));
//         }

//         // Run setup.
//         let air = AddSubChip::default();
//         let config = SP1CoreJaggedConfig::new();
//         let chip = Chip::new(air);
//         let (pk, vk) = setup_test_machine(StarkMachine::new(
//             config.clone(),
//             vec![chip],
//             SP1_PROOF_NUM_PV_ELTS,
//             true,
//         ));

//         // Run the test.
//         let air = AddSubChip::default();
//         let chip: Chip<SP1Field, AddSubChip> = Chip::new(air);
//         let machine = StarkMachine::new(config.clone(), vec![chip], SP1_PROOF_NUM_PV_ELTS, true);
//         run_test_machine::<SP1CoreJaggedConfig, AddSubChip>(vec![shard], machine, pk,
// vk).unwrap();     }

//     #[cfg(feature = "sys")]
//     #[test]
//     fn test_generate_trace_ffi_eq_rust() {
//         let shard = LazyLock::force(&SHARD);

//         let chip = AddSubChip::default();
//         let trace: RowMajorMatrix<SP1Field> =
//             chip.generate_trace(shard, &mut ExecutionRecord::default());
//         let trace_ffi = generate_trace_ffi(shard);

//         assert_eq!(trace_ffi, trace);
//     }

//     #[cfg(feature = "sys")]
//     fn generate_trace_ffi(input: &ExecutionRecord) -> RowMajorMatrix<SP1Field> {
//         use rayon::slice::ParallelSlice;

//         use crate::utils::pad_rows_fixed;

//         use sp1_primitives::SP1Field;
// type F = SP1Field;

//         let chunk_size =
//             std::cmp::max((input.add_events.len() + input.sub_events.len()) / num_cpus::get(),
// 1);

//         let events = input.add_events.iter().chain(input.sub_events.iter()).collect::<Vec<_>>();
//         let row_batches = events
//             .par_chunks(chunk_size)
//             .map(|events| {
//                 let rows = events
//                     .iter()
//                     .map(|event| {
//                         let mut row = [F::zero(); NUM_ADD_SUB_COLS];
//                         let cols: &mut AddSubCols<F> = row.as_mut_slice().borrow_mut();
//                         unsafe {
//                             crate::sys::add_sub_event_to_row_koalabear(event, cols);
//                         }
//                         row
//                     })
//                     .collect::<Vec<_>>();
//                 rows
//             })
//             .collect::<Vec<_>>();

//         let mut rows: Vec<[F; NUM_ADD_SUB_COLS]> = vec![];
//         for row_batch in row_batches {
//             rows.extend(row_batch);
//         }

//         pad_rows_fixed(&mut rows, || [F::zero(); NUM_ADD_SUB_COLS], None);

//         // Convert the trace to a row major matrix.
//         RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_ADD_SUB_COLS)
//     }

//     #[test]
//     fn test_malicious_add_sub() {
//         const NUM_TESTS: usize = 5;

//         for opcode in [Opcode::ADD, Opcode::SUB] {
//             for _ in 0..NUM_TESTS {
//                 let op_a = thread_rng().gen_range(0..u32::MAX);
//                 let op_b = thread_rng().gen_range(0..u32::MAX);
//                 let op_c = thread_rng().gen_range(0..u32::MAX);

//                 let correct_op_a = if opcode == Opcode::ADD {
//                     op_b.wrapping_add(op_c)
//                 } else {
//                     op_b.wrapping_sub(op_c)
//                 };

//                 assert!(op_a != correct_op_a);

//                 let instructions = vec![
//                     Instruction::new(opcode, 5, op_b, op_c, true, true),
//                     Instruction::new(Opcode::ADD, 10, 0, 0, false, false),
//                 ];
//                 let program = Program::new(instructions, 0, 0);
//                 let stdin = SP1Stdin::new();

//                 type P = CpuProver<SP1CoreJaggedConfig, RiscvAir<SP1Field>>;

//                 let malicious_trace_pv_generator = move |prover: &P,
//                                                          record: &mut ExecutionRecord|
//                       -> Vec<(
//                     String,
//                     RowMajorMatrix<Val<SP1CoreJaggedConfig>>,
//                 )> {
//                     let mut malicious_record = record.clone();
//                     malicious_record.cpu_events[0].a = op_a;
//                     if let Some(MemoryRecordEnum::Write(mut write_record)) =
//                         malicious_record.cpu_events[0].a_record
//                     {
//                         write_record.value = op_a;
//                     }
//                     if opcode == Opcode::ADD {
//                         malicious_record.add_events[0].a = op_a;
//                     } else if opcode == Opcode::SUB {
//                         malicious_record.sub_events[0].a = op_a;
//                     } else {
//                         unreachable!()
//                     }

//                     let mut traces = prover.generate_traces(&malicious_record);

//                     let add_sub_chip_name = chip_name!(AddSubChip, SP1Field);
//                     for (chip_name, trace) in traces.iter_mut() {
//                         if *chip_name == add_sub_chip_name {
//                             // Add the add instructions are added first to the trace, before the
// sub instructions.                             let index = if opcode == Opcode::ADD { 0 } else { 1
// };

//                             let first_row = trace.row_mut(index);
//                             let first_row: &mut AddSubCols<SP1Field> = first_row.borrow_mut();
//                             if opcode == Opcode::ADD {
//                                 first_row.add_operation.value = op_a.into();
//                             } else {
//                                 first_row.add_operation.value = op_b.into();
//                             }
//                         }
//                     }

//                     traces
//                 };

//                 let result =
//                     run_malicious_test::<P>(program, stdin,
// Box::new(malicious_trace_pv_generator));                 println!("Result for {opcode:?}:
// {result:?}");                 let add_sub_chip_name = chip_name!(AddSubChip, SP1Field);
//                 assert!(
//                     result.is_err() &&
//                         result.unwrap_err().is_constraints_failing(&add_sub_chip_name)
//                 );
//             }
//         }
//     }
// }
