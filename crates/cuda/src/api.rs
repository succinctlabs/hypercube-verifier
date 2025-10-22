use serde::{Deserialize, Serialize};
use sp1_primitives::{SP1GlobalContext, SP1OuterGlobalContext};
use sp1_prover::{InnerSC, OuterSC, SP1CoreProof, SP1VerifyingKey};

use crate::CudaClientError;
use sp1_core_machine::{io::SP1Stdin, recursion::SP1RecursionProof};

#[derive(Serialize, Deserialize)]
pub enum Request {
    /// Tell the server to create a new proving key.
    Setup { elf: Vec<u8> },
    /// Tell the server to create a core proof.
    Core { key: [u8; 32], stdin: SP1Stdin, proof_nonce: [u32; 4] },
    /// Tell the server to create a compress proof.
    Compress {
        vk: SP1VerifyingKey,
        proof: SP1CoreProof,
        deferred: Vec<SP1RecursionProof<SP1GlobalContext, InnerSC>>,
    },
    /// Tell the server to create a shrink proof.
    Shrink { proof: SP1RecursionProof<SP1GlobalContext, InnerSC> },
    /// Tell the server to create a wrap proof.
    Wrap { proof: SP1RecursionProof<SP1GlobalContext, InnerSC> },
    /// Tell the server to destroy a proving key.
    Destroy { key: [u8; 32] },
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    /// The server has initialized.
    Ok,
    /// The setup response, containing the vkey and key id.
    Setup { id: [u8; 32], vk: SP1VerifyingKey },
    /// The core response, containing the core proof.
    Core { proof: SP1CoreProof },
    /// The compress response, containing the compress proof.
    Compress { proof: SP1RecursionProof<SP1GlobalContext, InnerSC> },
    /// The shrink response, containing the shrink proof.
    Shrink { proof: SP1RecursionProof<SP1GlobalContext, InnerSC> },
    /// The wrap response, containing the wrap proof.
    Wrap { proof: SP1RecursionProof<SP1OuterGlobalContext, OuterSC> },
    /// The server returned a prover error.
    ProverError(String),
    /// The error response, containing the error message.
    InternalError(String),
    /// The server has disconnected the client.
    ///
    /// This is really only useful for debugging purposes,
    /// if for some reason we dont send enoug bytes.
    ConnectionClosed,
}

impl Response {
    /// Get the type of the response.
    pub(crate) const fn type_of(&self) -> &'static str {
        match self {
            Response::Ok => "Ok",
            Response::Setup { .. } => "Setup",
            Response::Core { .. } => "Core",
            Response::Compress { .. } => "Compress",
            Response::Shrink { .. } => "Shrink",
            Response::Wrap { .. } => "Wrap",
            Response::InternalError(_) => "InternalError",
            Response::ProverError(_) => "ProverError",
            Response::ConnectionClosed => "ConnectionClosed",
        }
    }

    /// Capture any expected errors and convert them to a [`CudaClientError`].
    pub(crate) fn into_result(self) -> Result<Self, CudaClientError> {
        match self {
            Self::InternalError(e) => Err(CudaClientError::ServerError(e)),
            Self::ProverError(e) => {
                // todo!(n): can we make the [`SP1ProverError`] serde compatible?
                Err(CudaClientError::ServerError(e))
            }
            _ => Ok(self),
        }
    }
}
