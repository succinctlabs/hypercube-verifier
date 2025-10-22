use std::sync::Arc;

use slop_futures::pipeline::TaskHandle;
use sp1_hypercube::prover::ProverSemaphore;

use crate::{
    components::CoreProver,
    worker::{
        Artifact, ArtifactClient, SP1CoreProver, SP1CoreProverConfig, SetupTask, TaskId,
        TracingTask, WorkerClient,
    },
    SP1ProverComponents,
};

pub struct SP1ProverConfig {
    pub core_prover_config: SP1CoreProverConfig,
}

pub struct SP1ProverEngine<A: ArtifactClient, W: WorkerClient, C: SP1ProverComponents> {
    pub core_prover: SP1CoreProver<A, W, C>,
}

impl<A: ArtifactClient, W: WorkerClient, C: SP1ProverComponents> SP1ProverEngine<A, W, C> {
    pub fn new(
        config: SP1ProverConfig,
        artifact_client: A,
        worker_client: W,
        core_prover_and_permits: (Arc<CoreProver<C>>, ProverSemaphore),
    ) -> Self {
        let core_prover = SP1CoreProver::new(
            config.core_prover_config,
            artifact_client,
            worker_client,
            core_prover_and_permits.0,
            core_prover_and_permits.1,
        );
        Self { core_prover }
    }

    pub async fn submit_prove_core_shard(
        &self,
        id: TaskId,
        elf: Artifact,
        common_input: Artifact,
        record: Artifact,
        opts: Artifact,
        output: Artifact,
    ) -> anyhow::Result<TaskHandle<TaskId>> {
        let handle = self
            .core_prover
            .submit_prove_shard(TracingTask { id, elf, common_input, record, opts, output })
            .await?;
        Ok(handle)
    }

    pub async fn submit_setup(
        &self,
        id: TaskId,
        elf: Artifact,
        output: Artifact,
    ) -> anyhow::Result<TaskHandle<TaskId>> {
        let handle = self.core_prover.submit_setup(SetupTask { id, elf, output }).await?;
        Ok(handle)
    }
}
