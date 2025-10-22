use std::{env, sync::Arc};

use sp1_hypercube::prover::ProverSemaphore;
use tokio::{sync::mpsc, task::JoinSet};

use crate::{
    components::{CoreProver, RecursionProver, WrapProver},
    worker::{
        ArtifactClient, InMemoryArtifactClient, LocalWorkerClient, RawTaskRequest, SP1Controller,
        SP1ControllerConfig, SP1CoreProverConfig, SP1LocalNode, SP1LocalNodeConfig,
        SP1ProverConfig, SP1ProverEngine, TaskKind, TaskMetadata, TaskStatus, WorkerClient,
    },
    SP1ProverComponents,
};

use super::config::*;

pub struct SP1LocalNodeBuilder<C: SP1ProverComponents> {
    config: SP1LocalNodeConfig,
    core_air_prover_and_permits: Option<(Arc<CoreProver<C>>, ProverSemaphore)>,
    compress_air_prover_and_permits: Option<(Arc<RecursionProver<C>>, ProverSemaphore)>,
    shrink_air_prover_and_permits: Option<(Arc<RecursionProver<C>>, ProverSemaphore)>,
    wrap_air_prover_and_permits: Option<(Arc<WrapProver<C>>, ProverSemaphore)>,
}

impl<C: SP1ProverComponents> SP1LocalNodeBuilder<C> {
    pub fn new() -> Self {
        // Build the core config using data from environment or default values.
        //
        // TODO: base default values on system information.

        // Build the controller config.
        let num_splicing_workers = env::var("SP1_LOCAL_NODE_NUM_SPLICING_WORKERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_NUM_SPLICING_WORKERS);
        let splicing_buffer_size = env::var("SP1_LOCAL_NODE_SPLICING_BUFFER_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_SPLICING_BUFFER_SIZE);
        let controller_config = SP1ControllerConfig { num_splicing_workers, splicing_buffer_size };

        // Build the core prover config.
        let num_trace_executor_workers = env::var("SP1_LOCAL_NODE_NUM_TRACE_EXECUTOR_WORKERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_NUM_TRACE_EXECUTOR_WORKERS);
        let trace_executor_buffer_size = env::var("SP1_LOCAL_NODE_TRACE_EXECUTOR_BUFFER_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_TRACE_EXECUTOR_BUFFER_SIZE);
        let num_core_prover_workers = env::var("SP1_LOCAL_NODE_NUM_CORE_PROVER_WORKERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_NUM_CORE_PROVER_WORKERS);
        let core_prover_buffer_size = env::var("SP1_LOCAL_NODE_CORE_PROVER_BUFFER_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_CORE_PROVER_BUFFER_SIZE);
        let num_setup_workers = env::var("SP1_LOCAL_NODE_NUM_SETUP_WORKERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_NUM_SETUP_WORKERS);
        let setup_buffer_size = env::var("SP1_LOCAL_NODE_SETUP_BUFFER_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_SETUP_BUFFER_SIZE);
        let core_prover_config = SP1CoreProverConfig {
            num_trace_executor_workers,
            trace_executor_buffer_size,
            num_core_prover_workers,
            core_prover_buffer_size,
            num_setup_workers,
            setup_buffer_size,
        };

        let prover_config = SP1ProverConfig { core_prover_config };

        // Get the local node config from parts above.
        let config = SP1LocalNodeConfig { controller_config, prover_config };

        Self {
            config,
            core_air_prover_and_permits: None,
            compress_air_prover_and_permits: None,
            shrink_air_prover_and_permits: None,
            wrap_air_prover_and_permits: None,
        }
    }

    pub fn with_core_air_prover(
        mut self,
        core_air_prover: Arc<CoreProver<C>>,
        permit: ProverSemaphore,
    ) -> Self {
        self.core_air_prover_and_permits = Some((core_air_prover, permit));
        self
    }

    pub fn with_compress_air_prover(
        mut self,
        compress_air_prover: Arc<RecursionProver<C>>,
        permit: ProverSemaphore,
    ) -> Self {
        self.compress_air_prover_and_permits = Some((compress_air_prover, permit));
        self
    }

    pub fn with_shrink_air_prover(
        mut self,
        shrink_air_prover: Arc<RecursionProver<C>>,
        permit: ProverSemaphore,
    ) -> Self {
        self.shrink_air_prover_and_permits = Some((shrink_air_prover, permit));
        self
    }

    pub fn with_wrap_air_prover(
        mut self,
        wrap_air_prover: Arc<WrapProver<C>>,
        permit: ProverSemaphore,
    ) -> Self {
        self.wrap_air_prover_and_permits = Some((wrap_air_prover, permit));
        self
    }

    pub fn build(self) -> anyhow::Result<SP1LocalNode> {
        // Destructure the builder.
        let Self {
            config,
            core_air_prover_and_permits,
            compress_air_prover_and_permits: _,
            shrink_air_prover_and_permits: _,
            wrap_air_prover_and_permits: _,
        } = self;

        let artifact_client = InMemoryArtifactClient::new();
        let (worker_client, mut channels) = LocalWorkerClient::init();

        // Spawn tasks to handle all the requests

        // Spawn the controller handler
        tokio::task::spawn({
            let mut controller_rx = channels.task_receivers.remove(&TaskKind::Controller).unwrap();
            let worker_client = worker_client.clone();
            let artifact_client = artifact_client.clone();
            let controller = SP1Controller::new(
                config.controller_config,
                artifact_client.clone(),
                worker_client.clone(),
            );
            async move {
                let worker_client = worker_client.clone();
                while let Some((task_id, request)) = controller_rx.recv().await {
                    // Run the controller task
                    controller.run(request.clone()).await.unwrap();

                    // Complete the task
                    worker_client
                        .complete_task(request.proof_id, task_id, TaskMetadata { gpu_time: None })
                        .await
                        .unwrap();

                    // Remove all the inputs from the task
                    for input in request.inputs {
                        artifact_client.delete(&input).await.unwrap();
                    }
                }
            }
        });

        // Create the prover engine
        let core_air_prover_and_permits = core_air_prover_and_permits
            .ok_or(anyhow::anyhow!("Core air prover and permit are required"))?;
        let prover_engine = SP1ProverEngine::<_, _, C>::new(
            config.prover_config,
            artifact_client.clone(),
            worker_client.clone(),
            core_air_prover_and_permits,
        );
        let prover_engine = Arc::new(prover_engine);

        // Spawn the setup handler
        tokio::task::spawn({
            let mut setup_rx = channels.task_receivers.remove(&TaskKind::SetupVkey).unwrap();
            let prover_engine = prover_engine.clone();
            let worker_client = worker_client.clone();
            async move {
                let mut task_set = JoinSet::new();
                let (task_tx, mut task_rx) = mpsc::unbounded_channel();
                loop {
                    tokio::select! {
                        Some((id, request)) = setup_rx.recv() => {
                            let RawTaskRequest { inputs, outputs, proof_id, .. } = request;
                            let elf = inputs[0].clone();
                            let output = outputs[0].clone();
                            // TODO: handle errors
                            let handle = prover_engine.submit_setup(id, elf, output).await.unwrap();
                            let proof_id = proof_id.clone();
                            let tx = task_tx.clone();
                            task_set.spawn(async move {
                                let task_id = handle.await.unwrap();
                                tx.send((proof_id, task_id, TaskStatus::Succeeded)).ok();
                            });

                        }

                        Some((proof_id, id, status)) = task_rx.recv() => {
                            assert_eq!(status, TaskStatus::Succeeded);
                            worker_client.complete_task(proof_id, id, TaskMetadata { gpu_time: None }).await.unwrap();
                        }
                        else => {
                            break;
                        }
                    }
                }
            }
        });

        // Spawn the prove shard handler
        tokio::task::spawn({
            let mut core_prover_rx = channels.task_receivers.remove(&TaskKind::ProveShard).unwrap();
            let worker_client = worker_client.clone();
            async move {
                let mut task_set = JoinSet::new();
                let (task_tx, mut task_rx) = mpsc::unbounded_channel();

                loop {
                    tokio::select! {
                        Some((id, request)) = core_prover_rx.recv() => {
                            let RawTaskRequest { inputs, outputs, proof_id, .. } = request;

                            let elf = inputs[0].clone();
                            let common_input = inputs[1].clone();
                            let record = inputs[2].clone();
                            let opts = inputs[3].clone();
                            let output = outputs[0].clone();

                            let handle = prover_engine.submit_prove_core_shard(id, elf, common_input, record, opts, output).await.unwrap();
                            let proof_id = proof_id.clone();
                            let tx = task_tx.clone();
                            task_set.spawn(async move {
                                let task_id = handle.await.unwrap();
                                tx.send((proof_id, task_id, TaskStatus::Succeeded)).ok();
                            });
                        }

                        Some((proof_id, task_id, status)) = task_rx.recv() => {
                            assert_eq!(status, TaskStatus::Succeeded);
                            worker_client.complete_task(proof_id, task_id, TaskMetadata { gpu_time: None }).await.unwrap();
                        }
                        else => {
                            break;
                        }
                    }
                }
            }
        });

        Ok(SP1LocalNode { artifact_client, worker_client })
    }
}
