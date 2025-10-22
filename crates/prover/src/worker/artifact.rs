use core::fmt;
use std::{future::Future, sync::Arc};

use hashbrown::HashMap;
use mti::prelude::{MagicTypeIdExt, V7};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::sync::Mutex;

use anyhow::anyhow;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArtifactId(String);

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ArtifactType {
    Unspecified,
    Program,
    Stdin,
    Proof,
}

impl fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => write!(f, "Unspecified"),
            Self::Program => write!(f, "Program"),
            Self::Stdin => write!(f, "Stdin"),
            Self::Proof => write!(f, "Proof"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Artifact {
    id: ArtifactId,
    artifact_type: ArtifactType,
}

impl Artifact {
    #[inline]
    pub fn id(&self) -> &ArtifactId {
        &self.id
    }

    #[inline]
    pub fn artifact_type(&self) -> &ArtifactType {
        &self.artifact_type
    }
}

impl fmt::Display for Artifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Artifact::{}({})", self.artifact_type, self.id)
    }
}

pub trait ArtifactClient: Send + Sync + Clone + 'static {
    fn upload_raw(
        &self,
        id: &Artifact,
        raw: Vec<u8>,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn download_raw(&self, id: &Artifact) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    fn exists(&self, id: &Artifact) -> impl Future<Output = anyhow::Result<bool>> + Send;

    fn delete(&self, id: &Artifact) -> impl Future<Output = anyhow::Result<()>> + Send;

    #[inline]
    fn create_artifact(&self, artifact_type: ArtifactType) -> Artifact {
        let id = ArtifactId("artifact".create_type_id::<V7>().to_string());
        Artifact { id, artifact_type }
    }

    fn upload<T: Serialize + Send + 'static>(
        &self,
        artifact: &Artifact,
        data: T,
    ) -> impl Future<Output = anyhow::Result<()>> + Send {
        async move {
            let raw_data = tokio::task::spawn_blocking(move || bincode::serialize(&data))
                .await
                .expect("serialization function panicked")?;
            self.upload_raw(artifact, raw_data).await
        }
    }

    fn download<T: DeserializeOwned + Send + 'static>(
        &self,
        artifact: &Artifact,
    ) -> impl Future<Output = anyhow::Result<T>> + Send {
        async move {
            let raw_data = self.download_raw(artifact).await?;
            let data = tokio::task::spawn_blocking(move || bincode::deserialize(&raw_data))
                .await
                .expect("deserialization function panicked")?;
            Ok(data)
        }
    }

    fn try_delete(&self, artifact: &Artifact) -> impl Future<Output = ()> + Send {
        async move {
            if let Err(e) = self.delete(artifact).await {
                tracing::warn!("Failed to delete artifact {}: {:?}", artifact, e);
            }
        }
    }
}

#[derive(Clone)]
pub struct InMemoryArtifactClient {
    artifacts: Arc<Mutex<HashMap<Artifact, Vec<u8>>>>,
}

impl fmt::Debug for InMemoryArtifactClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InMemoryArtifactClient")
    }
}

impl ArtifactClient for InMemoryArtifactClient {
    async fn upload_raw(&self, id: &Artifact, raw: Vec<u8>) -> anyhow::Result<()> {
        let mut artifacts = self.artifacts.lock().await;
        artifacts.insert(id.clone(), raw);
        Ok(())
    }

    async fn download_raw(&self, id: &Artifact) -> anyhow::Result<Vec<u8>> {
        let artifacts = self.artifacts.lock().await;
        artifacts.get(id).cloned().ok_or_else(|| anyhow!("artifact not found: {}", id))
    }

    async fn exists(&self, id: &Artifact) -> anyhow::Result<bool> {
        let artifacts = self.artifacts.lock().await;
        let exists = artifacts.contains_key(id);
        Ok(exists)
    }

    async fn delete(&self, id: &Artifact) -> anyhow::Result<()> {
        let mut artifacts = self.artifacts.lock().await;
        artifacts.remove(id);
        Ok(())
    }
}

impl InMemoryArtifactClient {
    pub fn new() -> Self {
        Self { artifacts: Arc::new(Mutex::new(HashMap::new())) }
    }
}
