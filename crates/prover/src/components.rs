use csl_air::{air_block::BlockAir, codegen_cuda_eval, SymbolicProverFolder};
use csl_cuda::{TaskScope, ToDevice};
use csl_jagged::{
    Poseidon2Bn254JaggedCudaProverComponents, Poseidon2KoalaBearJaggedCudaProverComponents,
};
use csl_logup_gkr::LogupGkrCudaProverComponents;
use csl_tracegen::{CudaTraceGenerator, CudaTracegenAir};
use csl_zerocheck::ZerocheckEvalProgramProverData;
use cslpc_merkle_tree::{Poseidon2Bn254CudaProver, Poseidon2KoalaBear16CudaProver, TcsProverClean};
use cslpc_prover::{
    CudaShardProver, Ext, Felt, ProverCleanMachineProverComponents, ProverCleanProverComponents,
};
use serde::{Deserialize, Serialize};
use slop_algebra::extension::BinomialExtensionField;
use slop_basefold::{Poseidon2Bn254FrBasefoldConfig, Poseidon2KoalaBear16BasefoldConfig};
use slop_challenger::IopCtx;
use slop_futures::queue::WorkerQueue;
use slop_jagged::{
    DefaultJaggedProver, JaggedBasefoldConfig, JaggedProver, JaggedProverComponents, SP1OuterConfig,
};
use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex};
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{
    air::MachineAir,
    prover::{
        MachineProverComponents, ProvingKey, ShardProver, ShardProverComponents, ZerocheckAir,
    },
    GkrProverImpl, MachineConfig, SP1CoreJaggedConfig, ShardVerifier,
};
use sp1_primitives::{SP1GlobalContext, SP1OuterGlobalContext};
use sp1_prover::{components::SP1ProverComponents, CompressAir, WrapAir};
use std::{collections::BTreeMap, marker::PhantomData, mem::MaybeUninit, sync::Arc};

pub struct CudaSP1ProverComponents;

impl SP1ProverComponents for CudaSP1ProverComponents {
    type CoreComponents = CudaMachineProverComponents<
        KoalaBearDegree4Duplex,
        Poseidon2KoalaBearJaggedCudaProverComponents,
        RiscvAir<KoalaBear>,
    >;
    type RecursionComponents = CudaMachineProverComponents<
        KoalaBearDegree4Duplex,
        Poseidon2KoalaBearJaggedCudaProverComponents,
        CompressAir<<SP1GlobalContext as IopCtx>::F>,
    >;
    type WrapComponents = CudaMachineProverComponents<
        SP1OuterGlobalContext,
        Poseidon2Bn254JaggedCudaProverComponents,
        WrapAir<<SP1OuterGlobalContext as IopCtx>::F>,
    >;
}

pub struct ProverCleanSP1ProverComponents;

impl SP1ProverComponents for ProverCleanSP1ProverComponents {
    type CoreComponents =
        ProverCleanMachineProverComponents<KoalaBearDegree4Duplex, ProverCleanCoreProverComponents>;
    type RecursionComponents = ProverCleanMachineProverComponents<
        KoalaBearDegree4Duplex,
        ProverCleanRecursionProverComponents,
    >;
    type WrapComponents =
        ProverCleanMachineProverComponents<SP1OuterGlobalContext, ProverCleanWrapProverComponents>;
}

/// Core prover components for prover-clean.
pub struct ProverCleanCoreProverComponents;

impl ProverCleanProverComponents<KoalaBearDegree4Duplex> for ProverCleanCoreProverComponents {
    type P = Poseidon2KoalaBear16CudaProver;
    type BC = Poseidon2KoalaBear16BasefoldConfig;
    type Air = RiscvAir<KoalaBear>;
    type C = SP1CoreJaggedConfig;
}

/// Recursion prover components for prover-clean.
pub struct ProverCleanRecursionProverComponents;

impl ProverCleanProverComponents<KoalaBearDegree4Duplex> for ProverCleanRecursionProverComponents {
    type P = Poseidon2KoalaBear16CudaProver;
    type BC = Poseidon2KoalaBear16BasefoldConfig;
    type Air = CompressAir<<SP1GlobalContext as IopCtx>::F>;
    type C = SP1CoreJaggedConfig;
}

/// Wrap prover comp    onents for prover-clean.
pub struct ProverCleanWrapProverComponents;

impl ProverCleanProverComponents<SP1OuterGlobalContext> for ProverCleanWrapProverComponents {
    type P = Poseidon2Bn254CudaProver;
    type BC = Poseidon2Bn254FrBasefoldConfig<Felt, Ext>;
    type Air = WrapAir<<SP1OuterGlobalContext as IopCtx>::F>;
    type C = SP1OuterConfig;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CudaShardProverComponents<GC, PcsComponents, A>(PhantomData<(GC, A, PcsComponents)>);

pub type CudaProver<GC, PcsComponents, A> =
    ShardProver<GC, CudaShardProverComponents<GC, PcsComponents, A>>;

impl<JC, A, GC> ShardProverComponents<GC> for CudaShardProverComponents<GC, JC, A>
where
    GC: IopCtx<F = KoalaBear, EF = BinomialExtensionField<KoalaBear, 4>>,
    JC: JaggedProverComponents<GC, A = TaskScope>,
    A: CudaTracegenAir<GC::F> + ZerocheckAir<GC::F, GC::EF> + std::fmt::Debug,
{
    type Program = <A as MachineAir<GC::F>>::Program;
    type Record = <A as MachineAir<GC::F>>::Record;
    type Air = A;
    type B = TaskScope;

    type Config = JC::Config;

    type TraceGenerator = CudaTraceGenerator<GC::F, A>;

    type ZerocheckProverData = ZerocheckEvalProgramProverData<GC::F, GC::EF, A>;

    type PcsProverComponents = JC;

    type GkrProver = GkrProverImpl<GC, LogupGkrCudaProverComponents<GC, A>>;
}

pub fn new_cuda_prover_sumcheck_eval<GC, C, Comp, A>(
    verifier: ShardVerifier<GC, C, A>,
    scope: TaskScope,
) -> CudaProver<GC, Comp, A>
where
    GC: IopCtx<F = KoalaBear, EF = BinomialExtensionField<KoalaBear, 4>>,
    C: MachineConfig<GC>,
    Comp: JaggedProverComponents<GC, A = TaskScope, Config = C> + DefaultJaggedProver<GC>,
    A: MachineAir<GC::F>
        + CudaTracegenAir<GC::F>
        + for<'a> BlockAir<SymbolicProverFolder<'a>>
        + ZerocheckAir<GC::F, GC::EF>
        + std::fmt::Debug,
{
    let ShardVerifier { jagged_pcs_verifier: pcs_verifier, machine } = verifier;
    let pcs_prover = JaggedProver::from_verifier(&pcs_verifier);
    let airs = machine.chips().iter().map(|chip| chip.air.clone()).collect::<Vec<_>>();
    let trace_generator = CudaTraceGenerator::new_in(machine, scope.clone());
    let zerocheck_data = ZerocheckEvalProgramProverData::new(&airs, scope);
    let logup_gkr_prover = LogupGkrCudaProverComponents::default_prover();
    CudaProver {
        trace_generator,
        logup_gkr_prover,
        zerocheck_prover_data: zerocheck_data,
        pcs_prover,
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CudaMachineProverComponents<GC, PcsComponents, A>(PhantomData<(GC, A, PcsComponents)>);

impl<GC, JC, A> MachineProverComponents<GC> for CudaMachineProverComponents<GC, JC, A>
where
    GC: IopCtx<F = KoalaBear, EF = BinomialExtensionField<KoalaBear, 4>>,
    JC: JaggedProverComponents<GC, A = TaskScope>,
    A: CudaTracegenAir<GC::F> + ZerocheckAir<GC::F, GC::EF> + std::fmt::Debug,
{
    type Config = JC::Config;
    type Prover = ShardProver<GC, CudaShardProverComponents<GC, JC, A>>;
    type Air = A;

    async fn preprocessed_table_heights(
        pk: Arc<ProvingKey<GC, Self::Config, Self::Air, Self::Prover>>,
    ) -> BTreeMap<String, usize> {
        pk.preprocessed_data
            .preprocessed_traces
            .iter()
            .map(|(k, v)| (k.clone(), v.num_real_entries()))
            .collect()
    }
}

pub async fn new_prover_clean_prover<GC, PC>(
    verifier: sp1_hypercube::MachineVerifier<GC, JaggedBasefoldConfig<GC>, PC::Air>,
    max_trace_size: usize,
    num_workers: usize,
    scope: TaskScope,
) -> CudaShardProver<GC, PC>
where
    GC: IopCtx<F = KoalaBear, EF = BinomialExtensionField<KoalaBear, 4>>,
    PC: ProverCleanProverComponents<GC>,
    PC::P: TcsProverClean<GC> + Default,
    PC::Air: CudaTracegenAir<GC::F>
        + for<'a> BlockAir<SymbolicProverFolder<'a>>
        + ZerocheckAir<GC::F, GC::EF>
        + std::fmt::Debug,
{
    use cslpc_basefold::ProverCleanFriCudaProver;
    use slop_basefold::BasefoldVerifier;

    let machine = verifier.machine().clone();

    let mut cache = BTreeMap::new();
    for chip in machine.chips() {
        let result = codegen_cuda_eval(chip.air.as_ref());
        cache.insert(chip.air.name(), result);
    }

    let log_stacking_height = verifier.log_stacking_height();
    let max_log_row_count = verifier.max_log_row_count();

    // Create the basefold prover from the verifier's PCS config
    // TODO: get this straight from the verifier.
    let basefold_verifier = BasefoldVerifier::<GC>::new(*verifier.fri_config(), 2);

    let basefold_prover = ProverCleanFriCudaProver::<GC, PC::P, GC::F>::new(
        PC::P::default(),
        basefold_verifier.fri_config,
        log_stacking_height,
    );

    let mut all_interactions = BTreeMap::new();

    for chip in machine.chips().iter() {
        let host_interactions = cslpc_logup_gkr::Interactions::new(chip.sends(), chip.receives());
        let device_interactions =
            cslpc_logup_gkr::Interactions::to_device_in(&host_interactions, &scope).await.unwrap();
        all_interactions.insert(chip.name().to_string(), Arc::new(device_interactions));
    }

    let mut trace_buffers = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let mut v: Vec<MaybeUninit<GC::F>> = Vec::with_capacity(max_trace_size);
        unsafe { v.set_len(max_trace_size) };
        let boxed: Box<[MaybeUninit<GC::F>]> = v.into_boxed_slice();
        let pinned = Box::into_pin(boxed);

        unsafe {
            let ptr = pinned.as_ptr() as *const std::ffi::c_void;
            let size = std::mem::size_of::<GC::F>() * max_trace_size;
            let result = csl_cuda::sys::runtime::cuda_host_register(ptr, size);
            if result != csl_cuda::sys::runtime::CUDA_SUCCESS_CSL {
                tracing::warn!(
                    "Failed to register buffer {} as pinned memory",
                    trace_buffers.len()
                );
            }
        }

        trace_buffers.push(pinned);
    }

    CudaShardProver {
        trace_buffers: Arc::new(WorkerQueue::new(trace_buffers)),
        all_interactions,
        all_zerocheck_programs: cache,
        max_log_row_count: max_log_row_count as u32,
        basefold_prover,
        max_trace_size,
        machine,
        backend: scope,
        _marker: PhantomData,
    }
}
