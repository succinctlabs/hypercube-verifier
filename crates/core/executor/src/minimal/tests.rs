use std::sync::Arc;

use super::*;
use crate::{
    debug::{compare_states, render_current_instruction},
    Program, SP1CoreOpts,
};
use sp1_jit::{debug, debug::DebugState};
use sp1_primitives::Elf;
use std::fmt::Write;

#[allow(clippy::cast_precision_loss)]
fn run_program_and_compare_end_state(program: &Elf) {
    const DEBUG: bool = false;

    let program = Program::from(program).unwrap();
    let program = Arc::new(program);

    let mut interpreter =
        crate::executor::Executor::new(program.clone(), crate::SP1CoreOpts::default());
    let interpreter_time = {
        let start = std::time::Instant::now();
        interpreter.run_fast().expect("Interpreter failed");
        start.elapsed()
    };

    let mut executor = MinimalExecutor::new(program.clone(), DEBUG, None);
    let jit_time = {
        let start = std::time::Instant::now();
        executor.execute_chunk();
        start.elapsed()
    };

    // convert to mhz
    let cycles = executor.global_clk();
    let mhz = cycles as f64 / (jit_time.as_micros() as f64);
    eprintln!("cycles={cycles}");
    eprintln!("MinimalExecutor MHz={mhz} MHz");

    let interpreter_cycles = interpreter.state.global_clk;
    let interpreter_mhz = interpreter_cycles as f64 / (interpreter_time.as_micros() as f64);
    eprintln!("Interpreter MHz={interpreter_mhz} MHz");

    let (is_equal, report) =
        compare_states(&program, &executor.current_state(), &interpreter.current_state());
    assert!(is_equal, "state mismatch:\n{report}");
}

#[test]
fn test_run_keccak_with_input() {
    use bincode::serialize;
    use test_artifacts::KECCAK256_ELF;

    let program = Program::from(&KECCAK256_ELF).unwrap();
    let program = Arc::new(program);

    let mut executor = MinimalExecutor::new(program.clone(), false, None);
    // executor.debug();
    executor.with_input(&serialize(&5_usize).unwrap());
    for i in 0..5 {
        executor.with_input(&serialize(&vec![i; i]).unwrap());
    }
    executor.execute_chunk();

    let mut interpreter =
        crate::executor::Executor::new(program.clone(), crate::SP1CoreOpts::default());
    interpreter.write_stdin_slice(&serialize(&5_usize).unwrap());
    for i in 0..5 {
        interpreter.write_stdin_slice(&serialize(&vec![i; i]).unwrap());
    }
    interpreter.run_fast().expect("Interpreter failed");

    let (is_equal, report) =
        compare_states(&program, &executor.current_state(), &interpreter.current_state());
    assert!(is_equal, "state mismatch:\n{report}");
}

#[test]
fn test_chunk_stops_correctly() {
    use bincode::serialize;
    use sp1_jit::MinimalTrace;
    use test_artifacts::KECCAK256_ELF;

    let program = Program::from(&KECCAK256_ELF).unwrap();
    let program = Arc::new(program);

    let mut executor = MinimalExecutor::new(program.clone(), true, Some(10));
    // executor.debug();
    executor.with_input(&serialize(&5_usize).unwrap());
    for i in 0..5 {
        executor.with_input(&serialize(&vec![i; i]).unwrap());
    }

    let mut lask_clk = 1;
    let mut last_pc = program.pc_start_abs;
    let mut last_registers = executor.registers();
    let mut chunk_count = 0;
    while let Some(chunk) = executor.execute_chunk() {
        assert_eq!(chunk.clk_start(), lask_clk, "chunk {chunk_count} clk_start mismatch");
        assert_eq!(chunk.pc_start(), last_pc, "chunk {chunk_count} pc_start mismatch");
        assert_eq!(
            chunk.start_registers(),
            last_registers,
            "chunk {chunk_count} registers mismatch"
        );

        lask_clk = chunk.clk_end();
        last_pc = executor.pc();
        last_registers = executor.registers();
        chunk_count += 1;
    }

    assert!(chunk_count > 5, "no chunks were executed");
}

#[test]
fn test_run_fibonacci() {
    run_program_and_compare_end_state(&test_artifacts::FIBONACCI_ELF);
}

#[test]
fn test_run_sha256() {
    run_program_and_compare_end_state(&test_artifacts::SHA2_ELF);
}

#[test]
fn test_run_sha_extend() {
    run_program_and_compare_end_state(&test_artifacts::SHA_EXTEND_ELF);
}

#[test]
fn test_run_sha_compress() {
    run_program_and_compare_end_state(&test_artifacts::SHA_COMPRESS_ELF);
}

#[test]
fn test_run_keccak_permute() {
    run_program_and_compare_end_state(&test_artifacts::KECCAK_PERMUTE_ELF);
}

#[test]
fn test_run_secp256k1_add() {
    run_program_and_compare_end_state(&test_artifacts::SECP256K1_ADD_ELF);
}

#[test]
fn test_run_secp256k1_double() {
    run_program_and_compare_end_state(&test_artifacts::SECP256K1_DOUBLE_ELF);
}

#[test]
fn test_run_secp256r1_add() {
    run_program_and_compare_end_state(&test_artifacts::SECP256R1_ADD_ELF);
}

#[test]
fn test_run_secp256r1_double() {
    run_program_and_compare_end_state(&test_artifacts::SECP256R1_DOUBLE_ELF);
}

#[test]
fn test_run_bls12_381_add() {
    run_program_and_compare_end_state(&test_artifacts::BLS12381_ADD_ELF);
}

#[test]
fn test_ed_add() {
    run_program_and_compare_end_state(&test_artifacts::ED_ADD_ELF);
}

#[test]
fn test_bn254_add() {
    run_program_and_compare_end_state(&test_artifacts::BN254_ADD_ELF);
}

#[test]
fn test_bn254_double() {
    run_program_and_compare_end_state(&test_artifacts::BN254_DOUBLE_ELF);
}

#[test]
fn test_bn254_mul() {
    run_program_and_compare_end_state(&test_artifacts::BN254_MUL_ELF);
}

#[test]
fn test_uint256_mul() {
    run_program_and_compare_end_state(&test_artifacts::UINT256_MUL_ELF);
}

#[test]
fn test_bls12_381_fp() {
    run_program_and_compare_end_state(&test_artifacts::BLS12381_FP_ELF);
}

#[test]
fn test_bls12_381_fp2_mul() {
    run_program_and_compare_end_state(&test_artifacts::BLS12381_FP2_MUL_ELF);
}

#[test]
fn test_bls12_381_fp2_addsub() {
    run_program_and_compare_end_state(&test_artifacts::BLS12381_FP2_ADDSUB_ELF);
}

#[test]
fn test_bn254_fp() {
    run_program_and_compare_end_state(&test_artifacts::BN254_FP_ELF);
}

#[test]
fn test_bn254_fp2_addsub() {
    run_program_and_compare_end_state(&test_artifacts::BN254_FP2_ADDSUB_ELF);
}

#[test]
fn test_bn254_fp2_mul() {
    run_program_and_compare_end_state(&test_artifacts::BN254_FP2_MUL_ELF);
}

#[test]
fn test_ed_decompress() {
    run_program_and_compare_end_state(&test_artifacts::ED_DECOMPRESS_ELF);
}

#[test]
fn test_ed25519_verify() {
    run_program_and_compare_end_state(&test_artifacts::ED25519_ELF);
}

#[test]
fn test_ssz_withdrawls() {
    run_program_and_compare_end_state(&test_artifacts::SSZ_WITHDRAWALS_ELF);
}

#[test]
#[ignore = "Expensive test that is very useful for debugging"]
fn test_compare_registers_at_each_timestamp() {
    const ELF: Elf = test_artifacts::ED25519_ELF;

    let program = Program::from(&ELF).unwrap();
    let program = Arc::new(program);

    std::thread::scope(|s| {
        let mut minimal = MinimalExecutor::new(program.clone(), true, Some(50));
        let minimal_rx = minimal.new_debug_receiver().expect("Failed to create debug receiver");

        let mut oldexecutor =
            crate::executor::Executor::new(program.clone(), SP1CoreOpts::default());
        let oldexecutor_rx =
            oldexecutor.new_debug_receiver().expect("Failed to create debug receiver");

        s.spawn(move || while minimal.execute_chunk().is_some() {});
        s.spawn(move || oldexecutor.run_fast());
        s.spawn(move || {
            let mut got_prev: Option<debug::State> = None;
            let mut expected_prev: Option<debug::State> = None;

            for (cycle, (minimal_msg, oldexecutor_msg)) in
                minimal_rx.into_iter().zip(oldexecutor_rx.into_iter()).enumerate()
            {
                let (minimal_msg, oldexecutor_msg) = match (minimal_msg, oldexecutor_msg) {
                    (Some(minimal), Some(oldexecutor)) => (minimal, oldexecutor),
                    (Some(_), None) => {
                        eprintln!("minimal=    {minimal_msg:?}");
                        eprintln!("oldexecutor={oldexecutor_msg:?}");
                        panic!("😨 MinimalExecutor finished, but old Executor did not");
                    }
                    (None, Some(_)) => {
                        eprintln!("minimal=    {minimal_msg:?}");
                        eprintln!("oldexecutor={oldexecutor_msg:?}");
                        panic!("😨 Old Executor finished, but MinimalExecutor did not");
                    }
                    (None, None) => break,
                };

                let (is_equal, mut report) =
                    compare_states(&program, &minimal_msg, &oldexecutor_msg);
                if let (Some(got), Some(expected)) = (got_prev, expected_prev) {
                    let got = render_current_instruction(&program, &got);
                    let expected = render_current_instruction(&program, &expected);
                    writeln!(report).unwrap();
                    writeln!(report, "📄 PREVIOUS INSTRUCTION").unwrap();
                    writeln!(report, "       GOT: {got}").unwrap();
                    writeln!(report, "  EXPECTED: {expected}").unwrap();
                }
                if is_equal {
                    eprintln!("state matches at cycle {cycle}");
                } else {
                    eprintln!("{report}");
                    panic!("😨 state mismatch at cycle {cycle}");
                }
                got_prev = Some(minimal_msg);
                expected_prev = Some(oldexecutor_msg);
            }
        });
    });
}
