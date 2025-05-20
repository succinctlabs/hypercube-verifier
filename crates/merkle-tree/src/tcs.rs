use std::fmt::Debug;

use hypercube_commit::{TensorCs, TensorCsOpening};
use hypercube_tensor::Tensor;
use itertools::Itertools;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

/// An interfacr defining a Merkle tree.
pub trait MerkleTreeConfig: 'static + Clone + Send + Sync {
    type Data: 'static + Clone + Send + Sync + Serialize + DeserializeOwned;
    type Digest: 'static
        + Debug
        + Clone
        + Send
        + Sync
        + PartialEq
        + Eq
        + Serialize
        + DeserializeOwned;
    type Hasher: CryptographicHasher<Self::Data, Self::Digest> + Send + Sync + Clone;
    type Compressor: PseudoCompressionFunction<Self::Digest, 2> + Send + Sync + Clone;
}

pub trait DefaultMerkleTreeConfig: MerkleTreeConfig {
    fn default_hasher_and_compressor() -> (Self::Hasher, Self::Compressor);
}

/// A merkle tree Tensor commitment scheme.
///
/// A tensor commitment scheme based on merkleizing the committed tensors at a given dimension,
/// which the prover is free to choose.
#[derive(Debug, Clone, Copy)]
pub struct MerkleTreeTcs<M: MerkleTreeConfig> {
    pub hasher: M::Hasher,
    pub compressor: M::Compressor,
}

#[derive(Debug, Clone, Copy, Error)]
pub enum MerkleTreeTcsError {
    #[error("Merkle tree root mismatch: expected {expected} but got {actual}")]
    RootMismatch { expected: String, actual: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeTcsProof<T> {
    pub paths: Tensor<T>,
}

impl<M: DefaultMerkleTreeConfig> Default for MerkleTreeTcs<M> {
    #[inline]
    fn default() -> Self {
        let (hasher, compressor) = M::default_hasher_and_compressor();
        Self { hasher, compressor }
    }
}

impl<M: MerkleTreeConfig> TensorCs for MerkleTreeTcs<M> {
    type Data = M::Data;
    type Commitment = M::Digest;
    type Proof = MerkleTreeTcsProof<M::Digest>;
    type VerifierError = MerkleTreeTcsError;

    fn verify_tensor_openings(
        &self,
        commit: &Self::Commitment,
        indices: &[usize],
        opening: &TensorCsOpening<Self>,
    ) -> Result<(), Self::VerifierError> {
        for (i, (index, path)) in indices.iter().zip_eq(opening.proof.paths.split()).enumerate() {
            // Collect the lead slices of the claimed values.
            let claimed_values_slices = opening.values.get(i).unwrap().as_slice();

            let path = path.as_slice();

            // Iterate the path and compute the root.
            let digest = self.hasher.hash_iter_slices(vec![claimed_values_slices]);

            let mut root = digest;
            let mut index = *index;
            for sibling in path.iter().cloned() {
                let (left, right) = if index & 1 == 0 { (root, sibling) } else { (sibling, root) };
                root = self.compressor.compress([left, right]);
                index >>= 1;
            }

            if root != *commit {
                return Err(Self::VerifierError::RootMismatch);
            }
        }

        Ok(())
    }
}
