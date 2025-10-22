#![allow(clippy::disallowed_types)]
mod synchronize;

use std::fmt::Debug;

use futures::prelude::*;
pub use p3_challenger::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use slop_algebra::{ExtensionField, PrimeField32};
use slop_symmetric::{CryptographicHasher, PseudoCompressionFunction};
pub use synchronize::*;

pub trait FromChallenger<Challenger: Send + Sync, A: Send + Sync>: Send + Sync + Sized {
    fn from_challenger(
        challenger: &Challenger,
        backend: A,
    ) -> impl Future<Output = Self> + Send + Sync;
}

impl<Challenger: Clone + Send + Sync, A: Send + Sync> FromChallenger<Challenger, A> for Challenger {
    async fn from_challenger(challenger: &Challenger, _backend: A) -> Self {
        challenger.clone()
    }
}

/// A trait packaging together the types that usually appear in interactive oracle proofs in the
/// context of SP1: a field and a its cryptographically secure extension, a Fiat-Shamir challenger,
/// and a succinct commitment to data.
pub trait IopCtx:
    Clone + 'static + Send + Sync + Serialize + for<'de> Deserialize<'de> + Debug + Default
{
    type F: PrimeField32 + Ord;
    type EF: ExtensionField<Self::F>;
    type Digest: 'static
        + Copy
        + Send
        + Sync
        + Serialize
        + DeserializeOwned
        + Debug
        + PartialEq
        + Eq;
    type Challenger: FieldChallenger<Self::F>
        + GrindingChallenger
        + CanObserve<Self::Digest>
        + 'static
        + Send
        + Sync
        + Clone;

    type Hasher: CryptographicHasher<Self::F, Self::Digest> + Send + Sync + Clone;
    type Compressor: PseudoCompressionFunction<Self::Digest, 2> + Send + Sync + Clone;

    fn default_hasher_and_compressor() -> (Self::Hasher, Self::Compressor);

    fn default_challenger() -> Self::Challenger;
}
