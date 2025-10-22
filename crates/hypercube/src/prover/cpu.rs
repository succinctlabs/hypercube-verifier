use std::{
    collections::BTreeMap,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use slop_air::Air;
use slop_algebra::extension::BinomialExtensionField;
use slop_alloc::CpuBackend;
use slop_challenger::IopCtx;
use slop_jagged::{DefaultJaggedProver, JaggedConfig, JaggedProver, JaggedProverComponents};
use slop_uni_stark::SymbolicAirBuilder;
use sp1_primitives::{SP1Field, SP1GlobalContext};

use super::{
    DefaultTraceGenerator, MachineProver, MachineProverBuilder, ProverSemaphore, ShardProver,
    ShardProverComponents, ZerocheckAir, ZerocheckCpuProverData,
};
use crate::{
    air::MachineAir, debug::DebugConstraintBuilder, prover::MachineProverComponents,
    ConstraintSumcheckFolder, GkrProverImpl, LogupGkrCpuProverComponents, LogupGkrCpuRoundProver,
    LogupGkrCpuTraceGenerator, SP1CoreJaggedConfig, ShardVerifier,
};

/// The components of a CPU shard prover.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct CpuShardProverComponents<GC, PcsComponents, A>(PhantomData<(GC, A, PcsComponents)>);

/// The components of a CPU prover.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct CpuMachineProverComponents<GC, PcsComponents, A>(PhantomData<(GC, A, PcsComponents)>);

impl<GC, PcsComponents, A> MachineProverComponents<GC>
    for CpuMachineProverComponents<GC, PcsComponents, A>
where
    GC: IopCtx,
    PcsComponents: JaggedProverComponents<GC, A = CpuBackend>,
    A: std::fmt::Debug
        + MachineAir<GC::F>
        + Air<SymbolicAirBuilder<GC::F>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, GC::F, GC::F, GC::EF>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, GC::F, GC::EF, GC::EF>>
        + for<'b> Air<DebugConstraintBuilder<'b, GC::F, GC::EF>>
        + MachineAir<GC::F>,
{
    type Config = <PcsComponents as JaggedProverComponents<GC>>::Config;
    type Air = A;
    type Prover = ShardProver<GC, CpuShardProverComponents<GC, PcsComponents, A>>;

    async fn preprocessed_table_heights(
        pk: Arc<super::ProvingKey<GC, Self::Config, Self::Air, Self::Prover>>,
    ) -> BTreeMap<String, usize> {
        std::future::ready(
            pk.preprocessed_data
                .preprocessed_traces
                .iter()
                .map(|(name, trace)| (name.to_owned(), trace.num_real_entries()))
                .collect(),
        )
        .await
    }
}

/// A CPU prover.
pub type CpuProver<GC, PcsComponents, A> =
    MachineProver<GC, CpuShardProverComponents<GC, PcsComponents, A>>;
/// A CPU shard prover.
pub type CpuShardProver<GC, PcsComponents, A> =
    ShardProver<GC, CpuShardProverComponents<GC, PcsComponents, A>>;
/// A CPU prover builder.
pub struct CpuProverBuilder<GC, PcsComponents, A>
where
    GC: IopCtx,
    PcsComponents: JaggedProverComponents<GC, A = CpuBackend>,
    A: std::fmt::Debug
        + MachineAir<GC::F>
        + Air<SymbolicAirBuilder<GC::F>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, GC::F, GC::F, GC::EF>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, GC::F, GC::EF, GC::EF>>
        + for<'b> Air<DebugConstraintBuilder<'b, GC::F, GC::EF>>
        + MachineAir<GC::F>,
{
    inner: MachineProverBuilder<GC, CpuMachineProverComponents<GC, PcsComponents, A>>,
}

impl<GC, PcsComponents, A> Deref for CpuProverBuilder<GC, PcsComponents, A>
where
    GC: IopCtx,
    PcsComponents: JaggedProverComponents<GC, A = CpuBackend>,
    A: std::fmt::Debug
        + MachineAir<GC::F>
        + Air<SymbolicAirBuilder<GC::F>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, GC::F, GC::F, GC::EF>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, GC::F, GC::EF, GC::EF>>
        + for<'b> Air<DebugConstraintBuilder<'b, GC::F, GC::EF>>
        + MachineAir<GC::F>,
{
    type Target = MachineProverBuilder<GC, CpuMachineProverComponents<GC, PcsComponents, A>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<GC, PcsComponents, A> DerefMut for CpuProverBuilder<GC, PcsComponents, A>
where
    GC: IopCtx,
    PcsComponents: JaggedProverComponents<GC, A = CpuBackend>,
    A: std::fmt::Debug
        + MachineAir<GC::F>
        + Air<SymbolicAirBuilder<GC::F>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, GC::F, GC::F, GC::EF>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, GC::F, GC::EF, GC::EF>>
        + for<'b> Air<DebugConstraintBuilder<'b, GC::F, GC::EF>>
        + MachineAir<GC::F>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<GC, A, PcsComponents> ShardProverComponents<GC>
    for CpuShardProverComponents<GC, PcsComponents, A>
where
    GC: IopCtx,
    PcsComponents: JaggedProverComponents<GC, A = CpuBackend>,
    A: std::fmt::Debug
        + MachineAir<GC::F>
        + Air<SymbolicAirBuilder<GC::F>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, GC::F, GC::F, GC::EF>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, GC::F, GC::EF, GC::EF>>
        + for<'b> Air<DebugConstraintBuilder<'b, GC::F, GC::EF>>
        + MachineAir<GC::F>,
{
    type Program = <A as MachineAir<GC::F>>::Program;
    type Record = <A as MachineAir<GC::F>>::Record;
    type Air = A;
    type B = CpuBackend;

    type Config = <PcsComponents as JaggedProverComponents<GC>>::Config;

    type TraceGenerator = DefaultTraceGenerator<GC::F, A, CpuBackend>;

    type ZerocheckProverData = ZerocheckCpuProverData<A>;

    type GkrProver =
        GkrProverImpl<GC, LogupGkrCpuProverComponents<GC::F, GC::EF, A, GC::Challenger>>;

    type PcsProverComponents = PcsComponents;
}

impl<GC, Comp, A, Config> CpuShardProver<GC, Comp, A>
where
    GC: IopCtx,
    Config: JaggedConfig<GC> + Sync,
    Comp: JaggedProverComponents<GC, A = CpuBackend, Config = Config> + DefaultJaggedProver<GC>,
    A: ZerocheckAir<GC::F, GC::EF> + std::fmt::Debug,
{
    /// Create a new CPU prover.
    #[must_use]
    pub fn new(verifier: ShardVerifier<GC, Config, A>) -> Self {
        // Construct the shard prover.
        let ShardVerifier { jagged_pcs_verifier: pcs_verifier, machine } = verifier;
        let pcs_prover = JaggedProver::from_verifier(&pcs_verifier);
        let trace_generator = DefaultTraceGenerator::new(machine);
        let zerocheck_data = ZerocheckCpuProverData::default();
        let logup_gkr_trace_generator = LogupGkrCpuTraceGenerator::default();
        let logup_gkr_prover =
            GkrProverImpl::new(logup_gkr_trace_generator, LogupGkrCpuRoundProver);

        Self {
            trace_generator,
            logup_gkr_prover,
            zerocheck_prover_data: zerocheck_data,
            pcs_prover,
        }
    }
}

impl<A> CpuProverBuilder<SP1GlobalContext, crate::SP1CpuJaggedProverComponents, A>
where
    A: ZerocheckAir<SP1Field, BinomialExtensionField<SP1Field, 4>> + std::fmt::Debug,
{
    // /// Create a new CPU prover builder from a verifier and resource options.
    // #[must_use]
    // pub fn from_verifier(verifier: ShardVerifier<SP1CoreJaggedConfig, A>, opts: SP1CoreOpts) ->
    // Self {     let shard_prover = Arc::new(CpuShardProver::new(verifier.clone()));
    //     let prover_permits = Arc::new(Semaphore::new(opts.shard_batch_size));

    //     MachineProverBuilder::new(verifier, vec![prover_permits], vec![shard_prover])
    //         .num_workers(opts.trace_gen_workers)
    // }

    /// Create a new CPU prover builder from a verifier, having a single worker with a single
    /// permit.
    #[must_use]
    pub fn simple(verifier: ShardVerifier<SP1GlobalContext, SP1CoreJaggedConfig, A>) -> Self {
        let shard_prover = Arc::new(CpuShardProver::new(verifier.clone()));
        let prover_permits = ProverSemaphore::new(1);

        Self {
            inner: MachineProverBuilder::new(verifier, vec![prover_permits], vec![shard_prover]),
        }
    }

    /// Create a new CPU prover builder from a verifier.
    #[must_use]
    pub fn new(
        verifier: ShardVerifier<SP1GlobalContext, SP1CoreJaggedConfig, A>,
        prover_permits: ProverSemaphore,
    ) -> Self {
        let shard_prover = Arc::new(CpuShardProver::new(verifier.clone()));

        Self {
            inner: MachineProverBuilder::new(verifier, vec![prover_permits], vec![shard_prover]),
        }
    }
}
