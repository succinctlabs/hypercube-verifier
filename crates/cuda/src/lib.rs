/// The shared API between the client and server.
pub mod api;

/// The client that interacts with the CUDA server.
pub mod client;

/// The proving key type, which is a "remote" reference to a key held by the CUDA server.
pub mod pk;

/// The server startup logic.
mod server;

mod error;
pub use error::CudaClientError;

use std::path::PathBuf;

pub use pk::CudaProvingKey;
use semver::Version;
use sp1_core_machine::{io::SP1Stdin, recursion::SP1RecursionProof};
use sp1_primitives::{Elf, SP1GlobalContext, SP1OuterGlobalContext};
use sp1_prover::{InnerSC, OuterSC, SP1CoreProof, SP1VerifyingKey};

use crate::client::CudaClient;

const MIN_CUDA_VERSION: Version = Version::new(12, 6, 0);

#[derive(Clone)]
pub struct CudaProver {
    client: CudaClient,
}

impl CudaProver {
    /// Create a new prover, using the 0th CUDA device.
    pub async fn new() -> Result<Self, CudaClientError> {
        Ok(Self { client: CudaClient::connect(0).await? })
    }

    /// Create a new prover, using the given CUDA device.
    pub async fn new_with_id(cuda_id: u32) -> Result<Self, CudaClientError> {
        Ok(Self { client: CudaClient::connect(cuda_id).await? })
    }

    pub async fn setup(&self, elf: Elf) -> Result<CudaProvingKey, CudaClientError> {
        self.client.setup(elf).await
    }

    pub async fn core(
        &self,
        key: &CudaProvingKey,
        stdin: SP1Stdin,
        proof_nonce: [u32; 4],
    ) -> Result<SP1CoreProof, CudaClientError> {
        self.client.core(key, stdin, proof_nonce).await
    }

    pub async fn compress(
        &self,
        vk: &SP1VerifyingKey,
        proof: SP1CoreProof,
        deferred: Vec<SP1RecursionProof<SP1GlobalContext, InnerSC>>,
    ) -> Result<SP1RecursionProof<SP1GlobalContext, InnerSC>, CudaClientError> {
        self.client.compress(vk, proof, deferred).await
    }

    pub async fn shrink(
        &self,
        proof: SP1RecursionProof<SP1GlobalContext, InnerSC>,
    ) -> Result<SP1RecursionProof<SP1GlobalContext, InnerSC>, CudaClientError> {
        self.client.shrink(proof).await
    }

    pub async fn wrap(
        &self,
        proof: SP1RecursionProof<SP1GlobalContext, InnerSC>,
    ) -> Result<SP1RecursionProof<SP1OuterGlobalContext, OuterSC>, CudaClientError> {
        self.client.wrap(proof).await
    }
}

/// Panics if we detect an incompatible CUDA installation.
///
/// Note: This method is a noop if no cuda `version.json` can be found.
async fn check_cuda_version() {
    #[derive(serde::Deserialize, Debug)]
    struct CudaVersions {
        cuda_cudart: CudaVersion,
    }

    #[derive(serde::Deserialize, Debug)]
    struct CudaVersion {
        version: semver::Version,
    }

    let cuda_paths: Vec<PathBuf> = match std::env::var("CUDA_PATH").ok() {
        Some(path) => vec![path.into()],
        // todo: Check is there more than one CUDA installation.
        None => vec![PathBuf::from("/usr/local/cuda")],
    };

    for cuda_path in &cuda_paths {
        let version_file = cuda_path.join("version.json");
        if !version_file.exists() {
            continue;
        }

        let Ok(version_file) = tokio::fs::read_to_string(&version_file).await else {
            tracing::error!("Failed to read version.json for CUDA path: {:?}", cuda_path);
            continue;
        };

        let Ok(versions): Result<CudaVersions, _> = serde_json::from_str(&version_file) else {
            tracing::error!("Failed to parse version.json for CUDA path: {:?}", cuda_path);
            continue;
        };

        // If weve successfully parsed the version file, and the version is greater than or equal to
        // the minimum version, we can return Ok.
        if versions.cuda_cudart.version >= MIN_CUDA_VERSION {
            return;
        } else {
            panic!("CUDA version is too old. Please upgrade to at least {MIN_CUDA_VERSION} or set the CUDA_PATH env var.");
        }
    }

    tracing::error!(
        "Failed to find a compatible CUDA installation, locations checked: {:?}",
        cuda_paths
    );
}
