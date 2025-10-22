//! An end-to-end-prover implementation for the SP1 RISC-V zkVM.
//!
//! Separates the proof generation process into multiple stages:
//!
//! 1. Generate shard proofs which split up and prove the valid execution of a RISC-V program.
//! 2. Compress shard proofs into a single shard proof.
//! 3. Wrap the shard proof into a SNARK-friendly field.
//! 4. Wrap the last shard proof, proven over the SNARK-friendly field, into a PLONK proof.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::new_without_default)]
#![allow(clippy::collapsible_else_if)]

pub mod build;
pub mod components;
// pub mod gas; // TODO reimplement gas
pub mod core;
pub mod error;
pub mod local;
pub mod recursion;
pub mod shapes;
mod types;
pub mod utils;
pub mod verify;
pub mod worker;

use core::SP1CoreProver;
pub use recursion::SP1RecursionProver;
use shapes::{SP1NormalizeInputShape, DEFAULT_ARITY};
use sp1_core_executor::Program;
use std::{collections::BTreeMap, sync::Arc};

use sp1_hypercube::prover::{CpuShardProver, MachineProverBuilder, ProverSemaphore};
use sp1_recursion_executor::RecursionProgram;

use sp1_hypercube::{SP1CoreJaggedConfig, SP1OuterConfig};
use sp1_primitives::{SP1Field, SP1GlobalContext, SP1OuterGlobalContext};

pub use types::*;

pub use components::{CpuSP1ProverComponents, SP1ProverComponents};

/// The global version for all components of SP1.
///
/// This string should be updated whenever any step in verifying an SP1 proof changes, including
/// core, recursion, and plonk-bn254. This string is used to download SP1 artifacts and the gnark
/// docker image.
pub const SP1_CIRCUIT_VERSION: &str = include_str!("../SP1_VERSION");

/// The configuration for the core prover.
pub type CoreSC = SP1CoreJaggedConfig;
pub const CORE_LOG_BLOWUP: usize = 1;

/// The configuration for the inner prover.
pub type InnerSC = SP1CoreJaggedConfig;

/// The configuration for the outer prover.
pub type OuterSC = SP1OuterConfig;

// pub type DeviceProvingKey<C> = <<C as SP1ProverComponents>::CoreProver as MachineProver<
//     SP1CoreJaggedConfig,
//     RiscvAir<SP1Field>,
// >>::DeviceProvingKey;
use sp1_recursion_machine::RecursionAir;

use crate::{
    components::{CoreProver, RecursionProver, WrapProver},
    local::LocalProver,
};

const COMPRESS_DEGREE: usize = 3;
const SHRINK_DEGREE: usize = 3;
const WRAP_DEGREE: usize = 3;

// const CORE_CACHE_SIZE: usize = 5;
pub const COMPOSE_BATCH_SIZE: usize = 2;

pub type CompressAir<F> = RecursionAir<F, COMPRESS_DEGREE, 2>;
pub type ShrinkAir<F> = RecursionAir<F, SHRINK_DEGREE, 2>;
pub type WrapAir<F> = RecursionAir<F, WRAP_DEGREE, 1>;

pub struct SP1Prover<C: SP1ProverComponents> {
    core_prover: SP1CoreProver<C::CoreComponents>,
    recursion_prover: SP1RecursionProver<C>,
}

pub struct SP1ProverBuilder<C: SP1ProverComponents> {
    core_prover_builder: MachineProverBuilder<SP1GlobalContext, C::CoreComponents>,
    compress_prover_builder: MachineProverBuilder<SP1GlobalContext, C::RecursionComponents>,
    shrink_prover_builder: MachineProverBuilder<SP1GlobalContext, C::RecursionComponents>,
    wrap_prover_builder: MachineProverBuilder<SP1OuterGlobalContext, C::WrapComponents>,
    normalize_programs_cache_size: usize,
    maximum_compose_arity: usize,
    normalize_programs: BTreeMap<SP1NormalizeInputShape, Arc<RecursionProgram<SP1Field>>>,
    vk_verification: bool,
    compute_recursion_vks_at_initialization: bool,
    vk_map_path: Option<String>,
}

impl<C: SP1ProverComponents> SP1ProverBuilder<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new_multi_permits(
        base_core_provers: Vec<Arc<CoreProver<C>>>,
        core_prover_permits: Vec<ProverSemaphore>,
        nums_core_workers: Vec<usize>,
        base_compress_provers: Vec<Arc<RecursionProver<C>>>,
        compress_prover_permits: Vec<ProverSemaphore>,
        nums_compress_workers: Vec<usize>,
        base_shrink_provers: Vec<Arc<RecursionProver<C>>>,
        shrink_prover_permits: Vec<ProverSemaphore>,
        nums_shrink_workers: Vec<usize>,
        base_wrap_provers: Vec<Arc<WrapProver<C>>>,
        wrap_prover_permits: Vec<ProverSemaphore>,
        nums_wrap_workers: Vec<usize>,
        normalize_programs_cache_size: usize,
        max_compose_arity: usize,
    ) -> Self {
        let core_verifier = C::core_verifier();
        let core_prover_builder = MachineProverBuilder::new(
            core_verifier.shard_verifier().clone(),
            core_prover_permits,
            base_core_provers,
        );

        let compress_verifier = C::compress_verifier();
        let compress_prover_builder = MachineProverBuilder::new(
            compress_verifier.shard_verifier().clone(),
            compress_prover_permits,
            base_compress_provers,
        );

        let shrink_verifier = C::shrink_verifier();
        let shrink_prover_builder = MachineProverBuilder::new(
            shrink_verifier.shard_verifier().clone(),
            shrink_prover_permits,
            base_shrink_provers,
        );

        let wrap_verifier = C::wrap_verifier();
        let wrap_prover_builder = MachineProverBuilder::new(
            wrap_verifier.shard_verifier().clone(),
            wrap_prover_permits,
            base_wrap_provers,
        );

        let mut builder = Self {
            core_prover_builder,
            compress_prover_builder,
            shrink_prover_builder,
            wrap_prover_builder,
            normalize_programs_cache_size,
            normalize_programs: BTreeMap::new(),
            maximum_compose_arity: max_compose_arity,
            vk_verification: true,
            compute_recursion_vks_at_initialization: true,
            vk_map_path: None,
        };
        builder
            .num_core_workers_per_kind(nums_core_workers)
            .num_compress_workers_per_kind(nums_compress_workers)
            .num_shrink_workers_per_kind(nums_shrink_workers)
            .num_wrap_workers_per_kind(nums_wrap_workers);
        builder
    }

    pub fn new_single_permit(
        core_prover: CoreProver<C>,
        core_prover_permit: ProverSemaphore,
        num_core_workers: usize,
        compress_prover: RecursionProver<C>,
        compress_prover_permit: ProverSemaphore,
        num_compress_workers: usize,
        shrink_prover: RecursionProver<C>,
        shrink_prover_permit: ProverSemaphore,
        num_shrink_workers: usize,
        wrap_prover: WrapProver<C>,
        wrap_prover_permit: ProverSemaphore,
        num_wrap_workers: usize,
        normalize_programs_cache_size: usize,
        maximum_compose_arity: usize,
    ) -> Self {
        Self::new_multi_permits(
            vec![Arc::new(core_prover)],
            vec![core_prover_permit],
            vec![num_core_workers],
            vec![Arc::new(compress_prover)],
            vec![compress_prover_permit],
            vec![num_compress_workers],
            vec![Arc::new(shrink_prover)],
            vec![shrink_prover_permit],
            vec![num_shrink_workers],
            vec![Arc::new(wrap_prover)],
            vec![wrap_prover_permit],
            vec![num_wrap_workers],
            normalize_programs_cache_size,
            maximum_compose_arity,
        )
    }

    pub fn set_max_compose_arity(&mut self, max_compose_arity: usize) -> &mut Self {
        self.maximum_compose_arity = max_compose_arity;
        self
    }

    /// Set the number of workers for a given base kind.
    pub fn num_core_workers_for_base_kind(
        &mut self,
        base_kind: usize,
        num_workers: usize,
    ) -> &mut Self {
        self.core_prover_builder.num_workers_for_base_kind(base_kind, num_workers);
        self
    }

    /// Set the number of workers for each base kind.
    pub fn num_core_workers_per_kind(&mut self, num_workers_per_kind: Vec<usize>) -> &mut Self {
        self.core_prover_builder.num_workers_per_kind(num_workers_per_kind);
        self
    }

    /// Set the number of workers for all base kinds.
    pub fn num_core_workers(&mut self, num_workers: usize) -> &mut Self {
        self.core_prover_builder.num_workers(num_workers);
        self
    }

    pub fn num_compress_workers_for_base_kind(
        &mut self,
        base_kind: usize,
        num_workers: usize,
    ) -> &mut Self {
        self.compress_prover_builder.num_workers_for_base_kind(base_kind, num_workers);
        self
    }

    pub fn num_compress_workers_per_kind(&mut self, num_workers_per_kind: Vec<usize>) -> &mut Self {
        self.compress_prover_builder.num_workers_per_kind(num_workers_per_kind);
        self
    }

    pub fn num_shrink_workers_per_kind(&mut self, num_workers_per_kind: Vec<usize>) -> &mut Self {
        self.shrink_prover_builder.num_workers_per_kind(num_workers_per_kind);
        self
    }

    pub fn num_wrap_workers_per_kind(&mut self, num_workers_per_kind: Vec<usize>) -> &mut Self {
        self.wrap_prover_builder.num_workers_per_kind(num_workers_per_kind);
        self
    }

    pub fn num_compress_workers(&mut self, num_workers: usize) -> &mut Self {
        let _ = self.compress_prover_builder.num_workers(num_workers);
        self
    }

    pub fn normalize_cache_size(&mut self, normalize_programs_cache_size: usize) -> &mut Self {
        self.normalize_programs_cache_size = normalize_programs_cache_size;
        self
    }

    pub fn with_normalize_programs(
        &mut self,
        normalize_programs: BTreeMap<SP1NormalizeInputShape, Arc<RecursionProgram<SP1Field>>>,
    ) -> &mut Self {
        self.normalize_programs = normalize_programs;
        self
    }

    pub fn insert_normalize_program(
        &mut self,
        shape: SP1NormalizeInputShape,
        program: Arc<RecursionProgram<SP1Field>>,
    ) -> &mut Self {
        self.normalize_programs.insert(shape, program);
        self
    }

    #[cfg(feature = "experimental")]
    pub fn without_vk_verification(&mut self) -> &mut Self {
        self.vk_verification = false;
        self
    }

    pub fn with_vk_map_path(&mut self, vk_map_path: String) -> &mut Self {
        self.vk_map_path = Some(vk_map_path);
        self
    }

    pub fn without_recursion_vks(&mut self) -> &mut Self {
        self.compute_recursion_vks_at_initialization = false;
        self
    }

    pub async fn build(&mut self) -> SP1Prover<C> {
        let core_prover = self.core_prover_builder.build();
        let core_verifier = core_prover.verifier().shard_verifier().clone();
        let core_prover = SP1CoreProver::new(core_prover);
        let compress_prover = self.compress_prover_builder.build();
        let normalize_programs = std::mem::take(&mut self.normalize_programs);
        let shrink_prover = self.shrink_prover_builder.build();
        let wrap_prover = self.wrap_prover_builder.build();
        let recursion_prover = SP1RecursionProver::new(
            core_verifier,
            compress_prover,
            shrink_prover,
            wrap_prover,
            self.normalize_programs_cache_size,
            normalize_programs,
            self.maximum_compose_arity,
            self.vk_verification,
            self.compute_recursion_vks_at_initialization,
            self.vk_map_path.clone(),
        )
        .await;
        SP1Prover { core_prover, recursion_prover }
    }
}

impl<C: SP1ProverComponents> SP1Prover<C> {
    // TODO: hide behind builder pattern
    pub fn new(
        core_prover: SP1CoreProver<C::CoreComponents>,
        recursion_prover: SP1RecursionProver<C>,
    ) -> Self {
        // TODO: make as part of the input.
        Self { core_prover, recursion_prover }
    }

    pub fn core(&self) -> &SP1CoreProver<C::CoreComponents> {
        &self.core_prover
    }

    pub fn recursion(&self) -> &SP1RecursionProver<C> {
        &self.recursion_prover
    }

    /// Get the program from an elf.
    pub fn get_program(&self, elf: &[u8]) -> eyre::Result<Program> {
        let program = Program::from(elf)?;
        Ok(program)
    }
}

impl SP1ProverBuilder<CpuSP1ProverComponents> {
    pub fn new() -> Self {
        let cpu_ram_gb = sysinfo::System::new_all().total_memory() / (1024 * 1024 * 1024);
        let num_workers = match cpu_ram_gb {
            0..33 => 1,
            33..49 => 2,
            49..65 => 3,
            65..81 => 4,
            81.. => 4,
        };

        let prover_permits = ProverSemaphore::new(num_workers);

        let core_verifier = CpuSP1ProverComponents::core_verifier();
        let cpu_shard_prover = CpuShardProver::new(core_verifier.shard_verifier().clone());

        let compress_verifier = CpuSP1ProverComponents::compress_verifier();
        let compress_shard_prover = CpuShardProver::new(compress_verifier.shard_verifier().clone());

        let shrink_verifier = CpuSP1ProverComponents::shrink_verifier();
        let shrink_shard_prover = CpuShardProver::new(shrink_verifier.shard_verifier().clone());

        let wrap_verifier = CpuSP1ProverComponents::wrap_verifier();
        let wrap_shard_prover = CpuShardProver::new(wrap_verifier.shard_verifier().clone());

        let num_core_workers: usize = num_workers;
        let num_recursion_workers = num_workers;
        let num_shrink_workers = num_workers;
        let num_wrap_workers = num_workers;
        let normalize_programs_cache_size = 5;
        let max_compose_arity = DEFAULT_ARITY;

        SP1ProverBuilder::new_single_permit(
            cpu_shard_prover,
            prover_permits.clone(),
            num_core_workers,
            compress_shard_prover,
            prover_permits.clone(),
            num_recursion_workers,
            shrink_shard_prover,
            prover_permits.clone(),
            num_shrink_workers,
            wrap_shard_prover,
            prover_permits.clone(),
            num_wrap_workers,
            normalize_programs_cache_size,
            max_compose_arity,
        )
    }
}

pub async fn default_local_prover() -> LocalProver<CpuSP1ProverComponents> {
    let default_prover = SP1ProverBuilder::<CpuSP1ProverComponents>::new().build().await;
    LocalProver::new(default_prover, Default::default())
}

#[cfg(test)]
mod tests {
    use static_assertions::{assert_type_eq_all, const_assert_eq};

    use crate::{
        recursion::{
            RECURSION_LOG_BLOWUP, RECURSION_LOG_STACKING_HEIGHT, RECURSION_MAX_LOG_ROW_COUNT,
        },
        CompressAir,
    };
    use sp1_hypercube::SP1CoreJaggedConfig;
    use sp1_primitives::{SP1Field, SP1GlobalContext};
    /// Checks that the constants, types, etc. in sp1-verifier are valid.
    ///
    /// # How to obtain constants
    /// TODO: explain constants.
    #[test]
    fn sp1_verifier_valid() {
        use sp1_verifier::compressed::internal;

        assert_type_eq_all!(internal::F, SP1Field);
        assert_type_eq_all!(internal::GC, SP1GlobalContext);
        assert_type_eq_all!(internal::C, SP1CoreJaggedConfig);
        assert_type_eq_all!(internal::CompressAir<SP1Field>, CompressAir<SP1Field>);

        const_assert_eq!(internal::COMPRESS_DEGREE, crate::COMPRESS_DEGREE);
        const_assert_eq!(internal::RECURSION_LOG_BLOWUP, RECURSION_LOG_BLOWUP);
        const_assert_eq!(internal::RECURSION_LOG_STACKING_HEIGHT, RECURSION_LOG_STACKING_HEIGHT);
        const_assert_eq!(internal::RECURSION_MAX_LOG_ROW_COUNT, RECURSION_MAX_LOG_ROW_COUNT);

        // TODO: check vkey verification data is correct, if necessary.
    }
}
