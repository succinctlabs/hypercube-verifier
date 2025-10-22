use std::time::{Duration, Instant};

// use clap::{command, Parser};
// use sp1_primitives::SP1Field;
// use sp1_core_executor::{Executor, ExecutorMode, Program, Trace};
// use sp1_core_machine::shape::CoreShapeConfig;
// use sp1_sdk::{self, SP1Stdin};
// use sp1_hypercube::SP1ProverOpts;
// use sp1_stark::SP1ProverOpts;
use clap::{command, Parser};
use sp1_core_executor::{
    CompressedMemory, CycleResult, Executor, ExecutorMode, MinimalExecutor, Program, SP1CoreOpts,
    Simple, SplicedMinimalTrace, SplicingVM, Trace, TracingVM,
};
use sp1_sdk::{self, SP1Stdin};
use std::sync::Arc;

#[derive(Parser, Clone)]
#[command(about = "Evaluate the performance of SP1 on programs.")]
struct PerfArgs {
    /// The program to evaluate.
    #[arg(short, long)]
    pub program: String,

    /// The input to the program being evaluated.
    #[arg(short, long)]
    pub stdin: String,

    /// The executor mode to use.
    #[arg(short, long)]
    pub executor_mode: ExecutorMode,
}

#[derive(Default, Debug, Clone)]
#[allow(dead_code)]
struct PerfResult {
    pub cycles: u64,
    pub execution_duration: Duration,
    pub prove_core_duration: Duration,
    pub verify_core_duration: Duration,
    pub compress_duration: Duration,
    pub verify_compressed_duration: Duration,
    pub shrink_duration: Duration,
    pub verify_shrink_duration: Duration,
    pub wrap_duration: Duration,
    pub verify_wrap_duration: Duration,
}

pub fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, std::time::Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}

#[tokio::main]
async fn main() {
    let args = PerfArgs::parse();

    let elf = std::fs::read(args.program).expect("failed to read program");
    let stdin = std::fs::read(args.stdin).expect("failed to read stdin");
    let stdin: SP1Stdin = bincode::deserialize(&stdin).expect("failed to deserialize stdin");

    let program = Program::from(&elf).expect("failed to parse program");
    let program = Arc::new(program);
    let mut executor = Executor::new(program.clone(), Default::default());
    executor.write_vecs(&stdin.buffer);
    for (proof, vkey) in stdin.proofs.iter() {
        executor.write_proof(proof.clone(), vkey.clone());
    }

    match args.executor_mode {
        ExecutorMode::Simple => {
            let (_, execution_duration) = time_operation(|| executor.run::<Simple>());
            println!("Simple mode:");
            println!("cycles: {}", executor.state.global_clk);
            println!(
                "MHZ: {}",
                executor.state.global_clk as f64 / 1_000_000.0 / execution_duration.as_secs_f64()
            );

            let mut minimal = MinimalExecutor::simple(program);
            for input in stdin.buffer.iter() {
                minimal.with_input(input);
            }

            let (_, execution_duration) = time_operation(|| minimal.execute_chunk());
            println!("Minimal executor:");
            println!("cycles: {}", minimal.global_clk());
            println!(
                "MHZ: {}",
                minimal.global_clk() as f64 / 1_000_000.0 / execution_duration.as_secs_f64()
            );

            assert_eq!(executor.state.global_clk, minimal.global_clk());

            minimal.reset();
            for input in stdin.buffer.iter() {
                minimal.with_input(input);
            }

            let (_, execution_duration) = time_operation(|| minimal.execute_chunk());
            println!("Minimal mode after reset:");
            println!("cycles: {}", minimal.global_clk());
            println!(
                "MHZ: {}",
                minimal.global_clk() as f64 / 1_000_000.0 / execution_duration.as_secs_f64()
            );
        }
        ExecutorMode::Trace => {
            let mut checkpoint_executor = Executor::new(program.clone(), Default::default());
            checkpoint_executor.write_vecs(&stdin.buffer);
            for (proof, vkey) in stdin.proofs.iter() {
                checkpoint_executor.write_proof(proof.clone(), vkey.clone());
            }

            let (_, checkpoint_execution_duration) = time_operation(|| loop {
                let (record, _, done) = checkpoint_executor.execute_state(true).unwrap();
                let _record = std::hint::black_box(record);
                if done {
                    break;
                }
            });
            println!("Checkpoint mode:");
            println!("checkpoint execution duration: {checkpoint_execution_duration:?}");
            println!("cycles: {}", checkpoint_executor.state.global_clk);
            println!(
                "MHZ: {}",
                checkpoint_executor.state.global_clk as f64
                    / 1_000_000.0
                    / checkpoint_execution_duration.as_secs_f64()
            );

            let mut execution_duration = Duration::ZERO;
            let mut old_shard_trace_durations = Vec::new();
            let mut execution_start = Instant::now();
            let mut shard_idx = 0;
            let mut last_global_clk = 0;
            while !executor.execute::<Trace>().unwrap() {
                let elapsed = execution_start.elapsed();
                println!("shard {shard_idx} took {:?} to trace", execution_start.elapsed());
                println!(
                    "shard {shard_idx} trace mhz: {}",
                    (executor.state.global_clk as f64 - last_global_clk as f64)
                        / 1_000_000.0
                        / elapsed.as_secs_f64()
                );

                shard_idx += 1;
                last_global_clk = executor.state.global_clk;
                old_shard_trace_durations.push(elapsed);

                execution_duration += execution_start.elapsed();
                execution_start = Instant::now();
            }
            // Ensure the last shard is included.
            execution_duration += execution_start.elapsed();
            old_shard_trace_durations.push(execution_start.elapsed());

            println!("Trace mode:");
            println!("trace execution duration: {execution_duration:?}");
            println!("cycles: {}", executor.state.global_clk);
            println!(
                "MHZ: {}",
                executor.state.global_clk as f64 / 1_000_000.0 / execution_duration.as_secs_f64()
            );

            let mut minimal = MinimalExecutor::tracing(program.clone(), None);
            for input in stdin.buffer.iter() {
                minimal.with_input(input);
            }

            let (minimal_trace, minimal_trace_duration) =
                time_operation(|| minimal.execute_chunk());
            let minimal_trace = minimal_trace.expect("failed to execute chunk");
            println!("Minimal trace duration: {minimal_trace_duration:?}");
            assert_eq!(minimal.global_clk(), executor.state.global_clk);
            println!(
                "minimal executor (trace) mhz: {}",
                minimal.global_clk() as f64 / 1_000_000.0 / minimal_trace_duration.as_secs_f64()
            );

            let mut touched_addresses = CompressedMemory::new();
            let mut splicing_vm = SplicingVM::new(
                &minimal_trace,
                program.clone(),
                &mut touched_addresses,
                SP1CoreOpts::default(),
            );

            let mut spliced_traces = Vec::new();
            let mut last_spliced_trace = SplicedMinimalTrace::new_full_trace(minimal_trace.clone());
            let mut splice_duration = Duration::ZERO;
            let mut splice_timer = Instant::now();
            while let CycleResult::ShardBoundry =
                splicing_vm.execute().expect("failed to execute chunk")
            {
                if let Some(spliced) = splicing_vm.splice(minimal_trace.clone()) {
                    splice_duration += splice_timer.elapsed();
                    splice_timer = Instant::now();

                    let mut last_spliced_trace =
                        std::mem::replace(&mut last_spliced_trace, spliced);

                    last_spliced_trace.set_last_clk(splicing_vm.core.clk());
                    last_spliced_trace.set_last_mem_reads_idx(splicing_vm.core.mem_reads.len());

                    spliced_traces.push(last_spliced_trace);
                } else {
                    unreachable!("This trace has no cycle limit, so we expect it always splice.");
                }
            }
            // Handle the last spliced trace correctly.
            splice_duration += splice_timer.elapsed();
            last_spliced_trace.set_last_clk(splicing_vm.core.clk());
            last_spliced_trace.set_last_mem_reads_idx(splicing_vm.core.mem_reads.len());
            spliced_traces.push(last_spliced_trace);
            assert_eq!(minimal.global_clk(), splicing_vm.core.global_clk());

            println!("Spliced traces: {}", spliced_traces.len());
            println!("Spliced traces duration: {splice_duration:?}");
            println!(
                "Spliced traces mhz: {}",
                minimal.global_clk() as f64 / 1_000_000.0 / splice_duration.as_secs_f64()
            );

            let mut total_execution_duration = Duration::ZERO;
            let mut shard_tracing_durations = Vec::new();
            for (i, spliced) in spliced_traces.iter().enumerate() {
                let mut tracing_vm =
                    TracingVM::new(spliced, program.clone(), SP1CoreOpts::default());
                let (result, execution_duration) = time_operation(|| tracing_vm.execute());
                let result = result.expect("failed to execute chunk");
                assert!(result.is_shard_boundry() || result.is_done());

                println!("shard {i} tracing vm duration: {execution_duration:?}");
                println!(
                    "shard {i} vm mhz: {}",
                    tracing_vm.core.global_clk() as f64
                        / 1_000_000.0
                        / execution_duration.as_secs_f64()
                );

                shard_tracing_durations.push(execution_duration);
                total_execution_duration += execution_duration;
            }

            println!(
                "total time spent checkpoint + trace: {:?}",
                execution_duration + checkpoint_execution_duration
            );
            println!("time to last shard old: {checkpoint_execution_duration:?}");
            println!(
                "total old mhz: {}",
                minimal.global_clk() as f64
                    / 1_000_000.0
                    / (execution_duration + checkpoint_execution_duration).as_secs_f64()
            );
            println!(
                "average shard tracing duration: {:?}",
                old_shard_trace_durations.iter().sum::<Duration>()
                    / old_shard_trace_durations.len() as u32
            );

            println!(
                "total time spent minimal trace + splicing + full tracing: {:?}",
                total_execution_duration + splice_duration + minimal_trace_duration
            );
            println!(
                "time to last shard minimal trace: {:?}",
                splice_duration + minimal_trace_duration
            );
            println!(
                "total new mhz: {}",
                minimal.global_clk() as f64 / 1_000_000.0 / total_execution_duration.as_secs_f64()
            );
            println!(
                "average shard trace duraiton new: {:?}",
                shard_tracing_durations.iter().sum::<Duration>()
                    / shard_tracing_durations.len() as u32
            );
        }
        ExecutorMode::ShapeCollection => unimplemented!(),
        _ => todo!(),
    }
}
