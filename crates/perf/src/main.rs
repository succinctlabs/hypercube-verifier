fn main() {}

// use std::{
//     future::Future,
//     sync::Arc,
//     time::{Duration, Instant},
// };

// use clap::{command, Parser};
// use sp1_core_executor::Program;
// use sp1_cuda::CudaProver;
// use sp1_hypercube::MachineProof;
// use sp1_prover::{
//     local::{LocalProver, LocalProverOpts},
//     CpuSP1ProverComponents, ProverMode, SP1ProverBuilder,
// };
// use sp1_sdk::{self, Elf, SP1Stdin};

// #[derive(Parser, Clone)]
// #[command(about = "Evaluate the performance of SP1 on programs.")]
// struct PerfArgs {
//     /// The program to evaluate.
//     #[arg(short, long)]
//     pub program: String,

//     /// The input to the program being evaluated.
//     #[arg(short, long)]
//     pub stdin: String,

//     /// The prover mode to use.
//     ///
//     /// Provide this only in prove mode.
//     #[arg(short, long)]
//     pub mode: ProverMode,
// }

// #[derive(Default, Debug, Clone)]
// #[allow(dead_code)]
// struct PerfResult {
//     pub cycles: u64,
//     pub execution_duration: Duration,
//     pub prove_core_duration: Duration,
//     pub verify_core_duration: Duration,
//     pub compress_duration: Duration,
//     pub verify_compressed_duration: Duration,
//     pub shrink_duration: Duration,
//     pub verify_shrink_duration: Duration,
//     pub wrap_duration: Duration,
//     pub verify_wrap_duration: Duration,
// }

// pub async fn time_operation_fut<Fut, T, F>(operation: F) -> (T, std::time::Duration)
// where
//     Fut: Future<Output = T>,
//     F: FnOnce() -> Fut,
// {
//     let start = Instant::now();
//     let result = operation().await;
//     let duration = start.elapsed();
//     (result, duration)
// }

// pub fn time_operation<T, F>(operation: F) -> (T, std::time::Duration)
// where
//     F: FnOnce() -> T,
// {
//     let start = Instant::now();
//     let result = operation();
//     let duration = start.elapsed();
//     (result, duration)
// }

// #[tokio::main]
// async fn main() {
//     sp1_sdk::utils::setup_logger();
//     let args = PerfArgs::parse();

//     let elf = std::fs::read(args.program).expect("failed to read program");
//     let elf: Elf = elf.into();
//     let stdin = std::fs::read(args.stdin).expect("failed to read stdin");
//     let stdin: SP1Stdin = bincode::deserialize(&stdin).expect("failed to deserialize stdin");
//     let prover =
//         SP1ProverBuilder::<CpuSP1ProverComponents>::new().without_vk_verification().build().
// await;

//     let opts = LocalProverOpts::default();
//     let prover = Arc::new(LocalProver::new(prover, opts));

//     let (pk, _, vk) = prover.prover().core().setup(&elf).await;
//     let pk = unsafe { pk.into_inner() };
//     match args.mode {
//         ProverMode::Cpu => {
//             let (report, execution_duration) = time_operation_fut(|| async {
//                 prover.clone().execute(&elf, &stdin, Default::default())
//             })
//             .await;

// let machine_proof: MachineProof<_, _> =
//     MachineProof { shard_proofs: core_proof.proof.0.clone() };
// let (_, verify_core_duration) =
//     time_operation(|| prover.prover().core().verifier().verify(&vk.vk, &machine_proof));

//             let machine_proof: MachineProof<_> =
//                 MachineProof { shard_proofs: core_proof.proof.0.clone() };
//             let (_, verify_core_duration) =
//                 time_operation(|| prover.prover().core().verifier().verify(&vk.vk,
// &machine_proof));

//             let proofs = stdin.proofs.into_iter().map(|(proof, _)| proof).collect::<Vec<_>>();
//             let (compress_proof, compress_duration) = time_operation_fut(|| async {
//                 prover.clone().compress(&vk, core_proof.clone(), proofs).await.unwrap()
//             })
//             .await;

//             let (_, verify_compressed_duration) =
//                 time_operation(|| prover.prover().verify_compressed(&compress_proof, &vk));

//             let (shrink_proof, shrink_duration) = time_operation_fut(|| async {
//                 prover.clone().shrink(compress_proof.clone()).await.unwrap()
//             })
//             .await;

//             let (_, verify_shrink_duration) =
//                 time_operation(|| prover.prover().verify_shrink(&shrink_proof, &vk));

//             let (wrapped_bn254_proof, wrap_duration) = time_operation_fut(|| async {
//                 prover.clone().wrap(shrink_proof.clone()).await.unwrap()
//             })
//             .await;

//             let (_, verify_wrap_duration) =
//                 time_operation(|| prover.prover().verify_wrap_bn254(&wrapped_bn254_proof, &vk));
//             // pub fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T,
// std::time::Duration) {             //     let start = Instant::now();
//             //     let result = operation();
//             //     let duration = start.elapsed();
//             //     (result, duration)
//             // }

//             // fn main() {
//             //     sp1_sdk::utils::setup_logger();
//             //     let args = PerfArgs::parse();

//             //     let elf = std::fs::read(args.program).expect("failed to read program");
//             //     let stdin = std::fs::read(args.stdin).expect("failed to read stdin");
//             //     let stdin: SP1Stdin = bincode::deserialize(&stdin).expect("failed to
// deserialize stdin");

//             //     let opts = SP1ProverOpts::auto();

//             //     let prover = SP1Prover::<CpuProverComponents>::new();
//             //     let (pk, pk_d, program, vk) = prover.setup(&elf);
//             //     match args.mode {
//             //         ProverMode::Cpu => {
//             //             let context = SP1Context::default();
//             //             let (report, execution_duration) =
//             //                 time_operation(|| prover.execute(&elf, &stdin, context.clone()));

// let machine_proof: MachineProof<_, _> =
//     MachineProof { shard_proofs: core_proof.proof.0.clone() };
// let (_, verify_core_duration) =
//     time_operation(|| prover.prover().core().verifier().verify(&vk.vk, &machine_proof));

//             //             let (_, verify_core_duration) =
//             //                 time_operation(|| prover.verify(&core_proof.proof, &vk));

//             //             let proofs = stdin.proofs.into_iter().map(|(proof, _)|
// proof).collect::<Vec<_>>();             //             let (compress_proof, compress_duration) =
//             //                 time_operation(|| prover.compress(&vk, core_proof.clone(), proofs,
// opts).unwrap());

//             //             let (_, verify_compressed_duration) =
//             //                 time_operation(|| prover.verify_compressed(&compress_proof, &vk));

//             //             let (shrink_proof, shrink_duration) =
//             //                 time_operation(|| prover.shrink(compress_proof.clone(),
// opts).unwrap());

//             //             let (_, verify_shrink_duration) =
//             //                 time_operation(|| prover.verify_shrink(&shrink_proof, &vk));

//             //             let (wrapped_bn254_proof, wrap_duration) =
//             //                 time_operation(|| prover.wrap_bn254(shrink_proof, opts).unwrap());

//             //             let (_, verify_wrap_duration) =
//             //                 time_operation(|| prover.verify_wrap_bn254(&wrapped_bn254_proof,
// &vk));

//             //             // Generate a proof that verifies two deferred proofs from the proof
// above.             //             let (_, pk_verify_proof_d, pk_verify_program, vk_verify_proof)
// =             //                 prover.setup(VERIFY_PROOF_ELF);
//             //             let pv = core_proof.public_values.to_vec();

//             //             let mut stdin = SP1Stdin::new();
//             //             let vk_u32 = vk.hash_u32();
//             //             stdin.write::<[u32; 8]>(&vk_u32);
//             //             stdin.write::<Vec<Vec<u8>>>(&vec![pv.clone(), pv.clone()]);
//             //             stdin.write_proof(compress_proof.clone(), vk.vk.clone());
//             //             stdin.write_proof(compress_proof.clone(), vk.vk.clone());

//             //             let context = SP1Context::default();
//             //             let (core_proof, _) = time_operation(|| {
//             //                 prover
//             //                     .prove_core(&pk_verify_proof_d, pk_verify_program, &stdin,
// opts, context)             //                     .unwrap()
//             //             });
//             //             let deferred_proofs =
//             //                 stdin.proofs.into_iter().map(|(proof, _)|
// proof).collect::<Vec<_>>();             //             let (compress_proof, _) =
// time_operation(|| {             //                 prover
//             //                     .compress(&vk_verify_proof, core_proof.clone(),
// deferred_proofs, opts)             //                     .unwrap()
//             //             });
//             //             prover.verify_compressed(&compress_proof, &vk_verify_proof).unwrap();

//             //             let result = PerfResult {
//             //                 cycles,
//             //                 execution_duration,
//             //                 prove_core_duration,
//             //                 verify_core_duration,
//             //                 compress_duration,
//             //                 verify_compressed_duration,
//             //                 shrink_duration,
//             //                 verify_shrink_duration,
//             //                 wrap_duration,
//             //                 verify_wrap_duration,
//             //             };

//             // println!("{result:?}");
//         }
//         ProverMode::Cuda => {
//             let server = CudaProver::new().await.unwrap();
//             let cuda_pk = server.setup(elf.clone()).await.unwrap();

//             let (report, execution_duration) =
//                 time_operation(|| prover.clone().execute(&elf, &stdin, Default::default()));
//             //             println!("{:?}", result);
//             //         }
//             //         ProverMode::Cuda => {
//             //             let server = SP1CudaProver::new(MoongateServer::default())
//             //                 .expect("failed to initialize CUDA prover");

//             //             let context = SP1Context::default();
//             //             let (report, execution_duration) =
//             //                 time_operation(|| prover.execute(&elf, &stdin, context.clone()));

//             //             let cycles = report.expect("execution
// failed").2.total_instruction_count();

//             let (core_proof, prove_core_duration) = time_operation_fut(|| async {
//                 server.core(&cuda_pk, stdin.clone()).await.unwrap()
//             })
//             .await;

//             let machine_proof: MachineProof<_> =
//                 MachineProof { shard_proofs: core_proof.proof.0.clone() };
//             let (_, verify_core_duration) =
//                 time_operation(|| prover.prover().core().verifier().verify(&vk.vk,
// &machine_proof));

//             let proofs = stdin.proofs.into_iter().map(|(proof, _)| proof).collect::<Vec<_>>();
//             let (compress_proof, compress_duration) = time_operation_fut(|| async {
//                 server.compress(&vk, core_proof, proofs).await.unwrap()
//             })
//             .await;

//             let (_, verify_compressed_duration) =
//                 time_operation(|| prover.prover().verify_compressed(&compress_proof, &vk));

//             // let (shrink_proof, shrink_duration) =
//             //     time_operation_fut(|| async { server.shrink(compress_proof).await.unwrap()
//             // }).await;

//             // let (_, verify_shrink_duration) =
//             //     time_operation(|| prover.prover().verify_shrink(&shrink_proof, &vk));

//             // let (wrap_proof, wrap_duration) =
//             //     time_operation_fut(|| async { server.wrap(shrink_proof).await.unwrap()
// }).await;

//             // let (_, verify_wrap_duration) =
//             //     time_operation(|| prover.prover().verify_wrap_bn254(&wrap_proof, &vk));

//             let result = PerfResult {
//                 cycles,
//                 execution_duration,
//                 prove_core_duration,
//                 verify_core_duration,
//                 compress_duration,
//                 verify_compressed_duration,
//                 ..Default::default() // todo: fix when unsound flag removed.
//             };

//             println!("{result:?}");
//         }
//         ProverMode::Network => {
//             // let prover = ProverClient::builder().network().build();
//             // let (_, _) = time_operation(|| prover.execute(&elf, &stdin));

//             // let prover = ProverClient::builder().network().build();

//             // let (_, _) = time_operation(|| prover.execute(&elf, &stdin));

//             // let use_groth16: bool = rand::thread_rng().gen();
//             // if use_groth16 {
//             //     let (proof, _) =
//             //         time_operation(|| prover.prove(&pk, &stdin).groth16().run().unwrap());

//             //     let (_, _) = time_operation(|| prover.verify(&proof, &vk));
//             // } else {
//             //     let (proof, _) =
//             //         time_operation(|| prover.prove(&pk, &stdin).plonk().run().unwrap());

//             //     let (_, _) = time_operation(|| prover.verify(&proof, &vk));
//             // }
//         }
//         ProverMode::Mock => unreachable!(),
//     };
// }
// //             let (_, _) = time_operation(|| server.setup(&elf).unwrap());

// //             let (core_proof, prove_core_duration) =
// //                 time_operation(|| server.prove_core(&stdin).unwrap());

// //             let (_, verify_core_duration) = time_operation(|| {
// //                 prover.verify(&core_proof.proof, &vk).expect("Proof verification failed")
// //             });

// //             let proofs = stdin.proofs.into_iter().map(|(proof, _)| proof).collect::<Vec<_>>();
// //             let (compress_proof, compress_duration) =
// //                 time_operation(|| server.compress(&vk, core_proof, proofs).unwrap());

// //             let (_, verify_compressed_duration) =
// //                 time_operation(|| prover.verify_compressed(&compress_proof, &vk));

// //             let (shrink_proof, shrink_duration) =
// //                 time_operation(|| server.shrink(compress_proof).unwrap());

// //             let (_, verify_shrink_duration) =
// //                 time_operation(|| prover.verify_shrink(&shrink_proof, &vk));

// //             let (_, wrap_duration) = time_operation(||
// server.wrap_bn254(shrink_proof).unwrap());

// //             // TODO: FIX
// //             //
// //             // let (_, verify_wrap_duration) =
// //             //     time_operation(|| prover.verify_wrap_bn254(&wrapped_bn254_proof, &vk));

// //             let result = PerfResult {
// //                 cycles,
// //                 execution_duration,
// //                 prove_core_duration,
// //                 verify_core_duration,
// //                 compress_duration,
// //                 verify_compressed_duration,
// //                 shrink_duration,
// //                 verify_shrink_duration,
// //                 wrap_duration,
// //                 ..Default::default()
// //             };

// //             println!("{:?}", result);
// //         }
// //         ProverMode::Network => {
// //             let prover = ProverClient::builder().network().build();
// //             let (_, _) = time_operation(|| prover.execute(&elf, &stdin));

// //             let prover = ProverClient::builder().network().build();

// //             let (_, _) = time_operation(|| prover.execute(&elf, &stdin));

// //             let use_groth16: bool = rand::thread_rng().gen();
// //             if use_groth16 {
// //                 let (proof, _) =
// //                     time_operation(|| prover.prove(&pk, &stdin).groth16().run().unwrap());

// //                 let (_, _) = time_operation(|| prover.verify(&proof, &vk));
// //             } else {
// //                 let (proof, _) =
// //                     time_operation(|| prover.prove(&pk, &stdin).plonk().run().unwrap());

// //                 let (_, _) = time_operation(|| prover.verify(&proof, &vk));
// //             }
// //         }
// //         ProverMode::Mock => unreachable!(),
// //     };
// // }
