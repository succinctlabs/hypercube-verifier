//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! Visit the [Getting Started](https://docs.succinct.xyz/docs/sp1/getting-started/install) section
//! in the official SP1 documentation for a quick start guide.

#![warn(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::should_panic_without_expect)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_assert)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::explicit_iter_loop)]
#![warn(missing_docs)]

pub mod artifacts;
pub mod client;
pub mod cpu;
pub use cpu::CpuProver;
pub mod mock;
pub use mock::MockProver;
pub mod cuda;
pub use cuda::CudaProver;
pub mod env;

pub mod install;
#[cfg(feature = "network")]
pub mod network;
#[cfg(feature = "network")]
pub use network::prover::NetworkProver;

#[cfg(feature = "blocking")]
pub mod blocking;

pub mod utils;

// Re-export the client.
pub use crate::client::ProverClient;

// Re-export the proof and prover traits.
pub mod proof;
pub use proof::*;
pub mod prover;

/// The traits that define how to interact with the prover.
pub use prover::{ProveRequest, Prover, ProvingKey, SP1VerificationError};

// Re-export the build utilities and executor primitives.
pub use sp1_build::include_elf;
pub use sp1_core_executor::{
    ExecutionReport, Executor, HookEnv, SP1Context, SP1ContextBuilder, StatusCode,
};

// Re-export the machine/prover primitives.
pub use sp1_core_machine::io::SP1Stdin;
pub use sp1_primitives::{io::SP1PublicValues, Elf};
pub use sp1_prover::{HashableKey, ProverMode, SP1Prover, SP1VerifyingKey, SP1_CIRCUIT_VERSION};

/// A prelude, including all the types and traits that are commonly used.
pub mod prelude {
    pub use super::{
        include_elf, Elf, HashableKey, ProveRequest, Prover, ProvingKey, SP1ProofWithPublicValues,
        SP1Stdin,
    };
}

// Re-export the utilities.
pub use utils::setup_logger;

#[cfg(test)]
mod tests {
    use sp1_primitives::io::SP1PublicValues;

    use crate::{utils, Prover, ProverClient, SP1Stdin};

    #[tokio::test]
    async fn test_execute() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build().await;
        let elf = test_artifacts::FIBONACCI_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let (_, _) = client.execute(elf, stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_execute_panic() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build().await;
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).await.unwrap();
        // TODO: once the exit code is exposed to the SDK, check its value, both here and elsewhere.
    }

    #[should_panic]
    #[tokio::test]
    async fn test_cycle_limit_fail() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build().await;
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).cycle_limit(1).await.unwrap();
    }

    #[tokio::test]
    async fn test_e2e_core() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build().await;
        let elf = test_artifacts::FIBONACCI_ELF;
        let pk = client.setup(elf).await.unwrap();
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, stdin).await.unwrap();
        client.verify(&proof, &pk.vk, None).unwrap();

        // Test invalid public values.
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &pk.vk, None).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    // TODO: reimplement the custom stdout/stderr and revive this test
    // #[tokio::test]
    // async fn test_e2e_io_override() {
    //     utils::setup_logger();
    //     let client = ProverClient::builder().cpu().build().await;
    //     let elf = test_artifacts::HELLO_WORLD_ELF;

    //     let mut stdout = Vec::new();

    //     // Generate proof & verify.
    //     let stdin = SP1Stdin::new();
    //     let _ = client.execute(elf, stdin).stdout(&mut stdout).run().unwrap();

    //     assert_eq!(stdout, b"Hello, world!\n");
    // }

    // TODO BEFORE RELEASE: remove use of unsound prover when vkey commitments are finally built.
    #[cfg(feature = "experimental")]
    #[tokio::test]
    async fn test_e2e_compressed() {
        use crate::{prover::ProveRequest, CpuProver};

        utils::setup_logger();
        let client = CpuProver::new_experimental().await;
        let elf = test_artifacts::FIBONACCI_ELF;
        let pk = client.setup(elf).await.unwrap();
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, stdin).compressed().await.unwrap();
        client.verify(&proof, &pk.vk, None).unwrap();

        // Test invalid public values.
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &pk.vk, None).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    // TODO BEFORE RELEASE: add this back when implemented as well as a similar groth16 test, and
    // remove use of unsound prover (see above).
    // #[cfg(feature = "experimental")]
    // #[tokio::test]
    // async fn test_e2e_prove_plonk() {
    //     use crate::CpuProver;

    //     utils::setup_logger();
    //     let client = CpuProver::new_experimental().await;
    //     let elf = test_artifacts::FIBONACCI_ELF;
    //     let pk = client.setup(elf).await.unwrap();
    //     let mut stdin = SP1Stdin::new();
    //     stdin.write(&10usize);

    //     // Generate proof & verify.
    //     let mut proof = client.prove(&pk, stdin).plonk().await.unwrap();
    //     client.verify(&proof, &pk.vk).unwrap();

    //     // Test invalid public values.
    //     proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
    //     if client.verify(&proof, &pk.vk).is_ok() {
    //         panic!("verified proof with invalid public values")
    //     }
    // }

    // TODO: reimplement the mock prover and revive this test
    // #[tokio::test]
    // async fn test_e2e_prove_plonk_mock() {
    //     utils::setup_logger();
    //     let client = ProverClient::builder().mock().build().await;
    //     let elf = test_artifacts::FIBONACCI_ELF;
    //     let pk = client.setup(elf).await.unwrap();
    //     let mut stdin = SP1Stdin::new();
    //     stdin.write(&10usize);

    //     // Generate proof & verify.
    //     let mut proof = client.prove(&pk, stdin).plonk().await.unwrap();
    //     client.verify(&proof, &pk.vk).unwrap();
    // }
}
