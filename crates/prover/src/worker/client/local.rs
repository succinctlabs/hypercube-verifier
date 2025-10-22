use std::{collections::BTreeMap, sync::Arc};

use dashmap::DashMap;
use enum_map::EnumMap;
use mti::prelude::{MagicTypeIdExt, V7};
use tokio::sync::{mpsc, watch};

use crate::worker::{
    ProofId, ProofRequestStatus, RawTaskRequest, SubscriberBuilder, TaskId, TaskKind, TaskMetadata,
    TaskStatus, WorkerClient,
};

type LocalDb = Arc<DashMap<TaskId, (watch::Sender<TaskStatus>, watch::Receiver<TaskStatus>)>>;

pub struct LocalWorkerClientChannels {
    pub task_receivers: BTreeMap<TaskKind, mpsc::Receiver<(TaskId, RawTaskRequest)>>,
}

pub struct LocalWorkerClientInner {
    db: LocalDb,
    input_task_queues: EnumMap<TaskKind, mpsc::Sender<(TaskId, RawTaskRequest)>>,
}

impl LocalWorkerClientInner {
    fn create_id() -> TaskId {
        TaskId::new("local_worker".create_type_id::<V7>().to_string())
    }

    fn init() -> (Self, LocalWorkerClientChannels) {
        let mut task_inputs = BTreeMap::new();
        let mut task_outputs = BTreeMap::new();

        let unspecified_channel = mpsc::channel(1);
        task_inputs.insert(TaskKind::Unspecified, unspecified_channel.0);
        task_outputs.insert(TaskKind::Unspecified, unspecified_channel.1);

        let controller_channel = mpsc::channel(1);
        task_inputs.insert(TaskKind::Controller, controller_channel.0);
        task_outputs.insert(TaskKind::Controller, controller_channel.1);

        let prove_shard_channel = mpsc::channel(1);
        task_inputs.insert(TaskKind::ProveShard, prove_shard_channel.0);
        task_outputs.insert(TaskKind::ProveShard, prove_shard_channel.1);

        let recursion_reduce_channel = mpsc::channel(1);
        task_inputs.insert(TaskKind::RecursionReduce, recursion_reduce_channel.0);
        task_outputs.insert(TaskKind::RecursionReduce, recursion_reduce_channel.1);

        let recursion_deferred_channel = mpsc::channel(1);
        task_inputs.insert(TaskKind::RecursionDeferred, recursion_deferred_channel.0);
        task_outputs.insert(TaskKind::RecursionDeferred, recursion_deferred_channel.1);

        let shrink_wrap_channel = mpsc::channel(1);
        task_inputs.insert(TaskKind::ShrinkWrap, shrink_wrap_channel.0);
        task_outputs.insert(TaskKind::ShrinkWrap, shrink_wrap_channel.1);

        let setup_vkey_channel = mpsc::channel(1);
        task_inputs.insert(TaskKind::SetupVkey, setup_vkey_channel.0);
        task_outputs.insert(TaskKind::SetupVkey, setup_vkey_channel.1);

        let marker_deferred_record_channel = mpsc::channel(1);
        task_inputs.insert(TaskKind::MarkerDeferredRecord, marker_deferred_record_channel.0);
        task_outputs.insert(TaskKind::MarkerDeferredRecord, marker_deferred_record_channel.1);

        let plonk_wrap_channel = mpsc::channel(1);
        task_inputs.insert(TaskKind::PlonkWrap, plonk_wrap_channel.0);
        task_outputs.insert(TaskKind::PlonkWrap, plonk_wrap_channel.1);

        let groth16_wrap_channel = mpsc::channel(1);
        task_inputs.insert(TaskKind::Groth16Wrap, groth16_wrap_channel.0);
        task_outputs.insert(TaskKind::Groth16Wrap, groth16_wrap_channel.1);

        let task_queues = EnumMap::from_fn(|kind| task_inputs.remove(&kind).unwrap());
        let inner = Self { db: Arc::new(DashMap::new()), input_task_queues: task_queues };
        (inner, LocalWorkerClientChannels { task_receivers: task_outputs })
    }
}

pub struct LocalWorkerClient {
    inner: Arc<LocalWorkerClientInner>,
}

impl LocalWorkerClient {
    /// Creates a new local worker client.
    #[must_use]
    pub fn init() -> (Self, LocalWorkerClientChannels) {
        let (inner, channels) = LocalWorkerClientInner::init();
        (Self { inner: Arc::new(inner) }, channels)
    }
}

impl Clone for LocalWorkerClient {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl WorkerClient for LocalWorkerClient {
    async fn submit_task(&self, kind: TaskKind, task: RawTaskRequest) -> anyhow::Result<TaskId> {
        tracing::info!("submitting task of kind {kind:?}");
        let task_id = LocalWorkerClientInner::create_id();
        // Create a db entry for the task.
        let (tx, rx) = watch::channel(TaskStatus::Pending);
        self.inner.db.insert(task_id.clone(), (tx, rx));
        // Send the task to the input queue.
        self.inner.input_task_queues[kind]
            .send((task_id.clone(), task))
            .await
            .map_err(|_| anyhow::anyhow!("failed to send task of kind {:?} to queue", kind))?;
        Ok(task_id)
    }

    async fn complete_task(
        &self,
        _proof_id: ProofId,
        task_id: TaskId,
        _metadata: TaskMetadata,
    ) -> anyhow::Result<()> {
        // Get the sender for this task
        let (status_tx, _) = self
            .inner
            .db
            .get(&task_id)
            .as_deref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("task does not exist"))?;

        status_tx
            .send(TaskStatus::Succeeded)
            .map_err(|_| anyhow::anyhow!("failed to send status to task"))?;
        Ok(())
    }

    async fn complete_proof(
        &self,
        _proof_id: ProofId,
        _task_id: Option<TaskId>,
        _status: ProofRequestStatus,
    ) -> anyhow::Result<()> {
        unimplemented!("Not used for local worker client");
    }

    async fn subscriber(&self) -> SubscriberBuilder<Self> {
        let (subscriber_input_tx, mut subscriber_input_rx) = mpsc::unbounded_channel();
        let (subscriber_output_tx, subscriber_output_rx) = mpsc::unbounded_channel();

        tokio::task::spawn({
            let db = self.inner.db.clone();
            let output_tx = subscriber_output_tx.clone();
            async move {
                while let Some(id) = subscriber_input_rx.recv().await {
                    // Spawn a task to send the status to the output channel.
                    let db = db.clone();
                    let output_tx = output_tx.clone();
                    tokio::task::spawn(async move {
                        let (_, mut rx) =
                            db.get(&id).as_deref().cloned().expect("task does not exist");
                        rx.mark_changed();
                        while let Ok(()) = rx.changed().await {
                            let value = *rx.borrow();
                            if matches!(value, TaskStatus::FailedFatal | TaskStatus::Succeeded) {
                                output_tx.send((id, value)).ok();
                                return;
                            }
                        }
                    });
                }
            }
        });
        SubscriberBuilder::new(self.clone(), subscriber_input_tx, subscriber_output_rx)
    }
}
