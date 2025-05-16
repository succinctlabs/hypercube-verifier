use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{ExtensionField, Field};
use serde::{de::DeserializeOwned, Serialize};
use hypercube_multilinear::MultilinearPcsVerifier;
use std::fmt::Debug;

use crate::JaggedEvalConfig;

pub trait JaggedConfig: 'static + Clone + Send + Clone + Serialize + DeserializeOwned {
    type F: Field;
    type EF: ExtensionField<Self::F>;

    type Commitment: 'static + Clone + Send + Sync + Serialize + DeserializeOwned + Debug;

    /// The challenger type that creates the random challenges via Fiat-Shamir.
    ///
    /// The challenger is observing all the messages sent throughout the protocol and uses this
    /// to create the verifier messages of the IOP.
    type Challenger: FieldChallenger<Self::F>
        + CanObserve<Self::Commitment>
        + 'static
        + Send
        + Sync
        + Clone;

    type BatchPcsProof: 'static + Clone + Send + Sync + Serialize + DeserializeOwned;

    type BatchPcsVerifier: MultilinearPcsVerifier<
        F = Self::F,
        EF = Self::EF,
        Challenger = Self::Challenger,
        Proof = Self::BatchPcsProof,
        Commitment = Self::Commitment,
    >;

    type JaggedEvaluator: JaggedEvalConfig<Self::F, Self::EF, Self::Challenger>
        + 'static
        + Clone
        + Send
        + Sync
        + Serialize
        + DeserializeOwned;
}
