mod compress;
mod core;
mod deferred;

pub use compress::*;
pub use core::*;
use opentelemetry::Context;
use sp1_core_machine::{executor::ExecutionOutput, io::SP1Stdin};
use sp1_hypercube::ShardProof;
use sp1_primitives::{io::SP1PublicValues, SP1GlobalContext};
use std::sync::Arc;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tracing::Instrument;

use crate::{
    worker::{
        Artifact, ArtifactClient, ArtifactType, ProofId, RawTaskRequest, RequesterId, TaskId,
        TaskKind, TaskStatus, WorkerClient,
    },
    CoreSC, SP1CoreProof, SP1CoreProofData, SP1VerifyingKey,
};

pub struct SP1ControllerConfig {
    pub num_splicing_workers: usize,
    pub splicing_buffer_size: usize,
}

pub struct SP1Controller<A, W> {
    splicing_engine: Arc<SplicingEngine<A, W>>,
    artifact_client: A,
    worker_client: W,
}

impl<A, W> SP1Controller<A, W>
where
    A: ArtifactClient,
    W: WorkerClient,
{
    pub fn new(config: SP1ControllerConfig, artifact_client: A, worker_client: W) -> Self {
        let splicing_workers = (0..config.num_splicing_workers)
            .map(|_| SplicingWorker::new(artifact_client.clone(), worker_client.clone()))
            .collect();
        let splicing_engine =
            Arc::new(SplicingEngine::new(splicing_workers, config.splicing_buffer_size));

        Self { splicing_engine, artifact_client, worker_client }
    }

    fn executor(
        &self,
        elf: Artifact,
        stdin: Artifact,
        common_input: Artifact,
        opts: Artifact,
        proof_id: ProofId,
        parent_id: Option<TaskId>,
        parent_context: Option<Context>,
        requester_id: RequesterId,
        sender: mpsc::UnboundedSender<ProofData>,
    ) -> SP1CoreExecutor<A, W> {
        SP1CoreExecutor::new(
            self.splicing_engine.clone(),
            elf,
            stdin,
            common_input,
            opts,
            proof_id,
            parent_id,
            parent_context,
            requester_id,
            sender,
            self.artifact_client.clone(),
            self.worker_client.clone(),
        )
    }

    pub async fn run(&self, request: RawTaskRequest) -> anyhow::Result<()> {
        let RawTaskRequest { inputs, outputs, proof_id, parent_id, parent_context, requester_id } =
            request;

        let elf = inputs[0].clone();
        let stdin_artifact = inputs[1].clone();
        let opts = inputs[2].clone();

        // For now, assume no deferred proofs
        let deferred_digest = [0; 8];
        let num_deffered_proofs = 0usize;

        // Create a setup task and wait for the vk
        let vk_artifact = self.artifact_client.create_artifact(ArtifactType::Unspecified);
        let setup_request = RawTaskRequest {
            inputs: vec![elf.clone()],
            outputs: vec![vk_artifact.clone()],
            proof_id: proof_id.clone(),
            parent_id: parent_id.clone(),
            parent_context: parent_context.clone(),
            requester_id: requester_id.clone(),
        };
        tracing::trace!("submitting setup task");
        let setup_id = self.worker_client.submit_task(TaskKind::SetupVkey, setup_request).await?;
        // Wait for the setup task to finish
        let subscriber = self.worker_client.subscriber().await.per_task();
        let status =
            subscriber.wait_task(setup_id).instrument(tracing::debug_span!("setup task")).await?;
        if status != TaskStatus::Succeeded {
            return Err(anyhow::anyhow!("setup task failed"));
        }
        tracing::trace!("setup task succeeded");
        // Download the vk
        let vk = self.artifact_client.download::<SP1VerifyingKey>(&vk_artifact).await?;
        // Create the common input
        let common_input = CommonProverInput { vk, deferred_digest, num_deffered_proofs };
        // Upload the common input
        let common_input_artifact = self.artifact_client.create_artifact(ArtifactType::Unspecified);
        self.artifact_client.upload(&common_input_artifact, common_input).await?;

        let (core_proof_tx, mut core_proof_rx) = mpsc::unbounded_channel();

        let executor = self.executor(
            elf,
            stdin_artifact.clone(),
            common_input_artifact,
            opts,
            proof_id.clone(),
            parent_id,
            parent_context,
            requester_id,
            core_proof_tx,
        );

        let mut join_set = JoinSet::<anyhow::Result<()>>::new();
        // Spawn a task to gather the proofs
        let (proofs_tx, proofs_rx) = oneshot::channel();
        join_set.spawn({
            let worker_client = self.worker_client.clone();
            let artifact_client = self.artifact_client.clone();
            async move {
                let subscriber = worker_client.subscriber().await.per_task();
                let mut shard_proofs = Vec::new();
                while let Some(proof_data) = core_proof_rx.recv().await {
                    let ProofData { task_id, proof } = proof_data;
                    // Wait for the task to finish
                    let status = subscriber.wait_task(task_id.clone()).await?;
                    assert_eq!(status, TaskStatus::Succeeded);
                    // Download the proof
                    let proof = artifact_client
                        .download::<ShardProof<SP1GlobalContext, CoreSC>>(&proof)
                        .await?;
                    shard_proofs.push(proof);
                }
                proofs_tx.send(shard_proofs).ok();
                Ok(())
            }
        });

        // Wait for the executor to finish
        let result = executor.execute().await?;
        tracing::trace!("executor finished");

        // Wait for the proofs to finish
        let shard_proofs = proofs_rx.await?;

        let stdin = self.artifact_client.download::<SP1Stdin>(&stdin_artifact).await?;

        let ExecutionOutput { public_value_stream, cycles } = result;
        let public_values = SP1PublicValues::from(&public_value_stream);
        let proof =
            SP1CoreProof { proof: SP1CoreProofData(shard_proofs), stdin, public_values, cycles };

        // Upload the proofs and output
        self.artifact_client.upload(&outputs[0], proof).await?;
        Ok(())
    }
}
