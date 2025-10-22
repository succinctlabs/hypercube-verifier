use std::sync::Arc;

use sp1_core_executor::{ExecutionRecord, Program, HEIGHT_THRESHOLD};
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{
    prover::{
        CoreProofShape, MachineProver, MachineProverComponents, MachineProvingKey, PreprocessedData,
    },
    Machine, MachineVerifier, MachineVerifyingKey, ShardProof, ShardVerifier,
};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use static_assertions::const_assert;

use crate::{
    error::RecursionProgramError, shapes::SP1NormalizeInputShape, CoreSC, SP1VerifyingKey,
};

pub struct SP1CoreProver<C: CoreProverComponents> {
    prover: MachineProver<SP1GlobalContext, C>,
}

pub const CORE_LOG_BLOWUP: usize = 1;
pub const CORE_LOG_STACKING_HEIGHT: u32 = 21;
pub const CORE_MAX_LOG_ROW_COUNT: usize = 22;

const_assert!(HEIGHT_THRESHOLD <= (1 << CORE_MAX_LOG_ROW_COUNT));

pub trait CoreProverComponents:
    MachineProverComponents<SP1GlobalContext, Config = CoreSC, Air = RiscvAir<SP1Field>>
{
    /// The default verifier for the core prover.
    ///
    /// Thew verifier fixes the parameters of the underlying proof system.
    fn verifier() -> MachineVerifier<SP1GlobalContext, CoreSC, RiscvAir<SP1Field>> {
        let core_log_blowup = CORE_LOG_BLOWUP;
        let core_log_stacking_height = CORE_LOG_STACKING_HEIGHT;
        let core_max_log_row_count = CORE_MAX_LOG_ROW_COUNT;

        let machine = RiscvAir::machine();

        let core_verifier = ShardVerifier::from_basefold_parameters(
            core_log_blowup,
            core_log_stacking_height,
            core_max_log_row_count,
            machine.clone(),
        );

        MachineVerifier::new(core_verifier)
    }
}

impl<C> CoreProverComponents for C where
    C: MachineProverComponents<SP1GlobalContext, Config = CoreSC, Air = RiscvAir<SP1Field>>
{
}

impl<C: CoreProverComponents> SP1CoreProver<C> {
    #[inline]
    #[must_use]
    pub const fn new(prover: MachineProver<SP1GlobalContext, C>) -> Self {
        Self { prover }
    }

    /// Get the number of workers for the core prover
    #[must_use]
    #[inline]
    pub fn num_prover_workers(&self) -> usize {
        self.prover.num_workers()
    }

    pub fn machine(&self) -> &Machine<SP1Field, RiscvAir<SP1Field>> {
        self.prover.machine()
    }

    /// Setup the core prover
    #[must_use]
    pub async fn setup(
        &self,
        elf: &[u8],
    ) -> (PreprocessedData<MachineProvingKey<SP1GlobalContext, C>>, Arc<Program>, SP1VerifyingKey)
    {
        let program = Program::from(elf).unwrap();
        let (pk, vk) = self.prover.setup(Arc::new(program.clone()), None).await;
        (pk, Arc::new(program), SP1VerifyingKey { vk })
    }

    /// Setup the core prover with a vk already known.
    #[must_use]
    pub async fn setup_with_vk(
        &self,
        program: Arc<Program>,
        vk: SP1VerifyingKey,
    ) -> PreprocessedData<MachineProvingKey<SP1GlobalContext, C>> {
        let (pk, _) = self.prover.setup(program, Some(vk.vk)).await;

        pk
    }

    /// Prove a core shard
    #[inline]
    #[must_use]
    #[tracing::instrument(skip_all, name = "prove_core_shard")]
    pub async fn prove_shard(
        &self,
        pk: Arc<MachineProvingKey<SP1GlobalContext, C>>,
        record: ExecutionRecord,
    ) -> ShardProof<SP1GlobalContext, CoreSC> {
        self.prover.prove_shard(pk.clone(), record).await
    }

    pub fn verifier(&self) -> &MachineVerifier<SP1GlobalContext, C::Config, RiscvAir<SP1Field>> {
        self.prover.verifier()
    }

    /// Setup and prove a core shard
    ///
    /// The prover will compute the `pk` from the `vk` if exists, or will compute the setup and
    /// prove the shard in one step.
    #[inline]
    #[must_use]
    pub async fn setup_and_prove_shard(
        &self,
        program: Arc<Program>,
        vk: Option<SP1VerifyingKey>,
        record: ExecutionRecord,
    ) -> (MachineVerifyingKey<SP1GlobalContext, CoreSC>, ShardProof<SP1GlobalContext, CoreSC>) {
        self.prover.setup_and_prove_shard(program, vk.map(|vk| vk.vk), record).await
    }

    /// Get the shape of the core shard
    #[inline]
    pub fn core_shape_from_record(
        &self,
        record: &ExecutionRecord,
    ) -> Option<CoreProofShape<SP1Field, RiscvAir<SP1Field>>> {
        self.prover.shape_from_record(record)
    }

    /// Get the witness for a core shard
    pub fn normalize_input_shape(
        &self,
        record: &ExecutionRecord,
    ) -> Result<SP1NormalizeInputShape, RecursionProgramError> {
        let proof_shape = self
            .prover
            .shape_from_record(record)
            .ok_or(RecursionProgramError::InvalidRecordShape)?;

        Ok(SP1NormalizeInputShape {
            proof_shapes: vec![proof_shape],
            max_log_row_count: self.prover.max_log_row_count(),
            log_blowup: self.prover.verifier().fri_config().log_blowup,
            log_stacking_height: self.prover.log_stacking_height() as usize,
        })
    }
}
