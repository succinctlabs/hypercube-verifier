use serde::{de::DeserializeOwned, Serialize};
use slop_challenger::IopCtx;
use slop_multilinear::MultilinearPcsVerifier;

pub trait JaggedConfig<GC: IopCtx>:
    'static + Clone + Send + Clone + Serialize + DeserializeOwned
{
    type PcsVerifier: MultilinearPcsVerifier<GC>;

    /// The jagged verifier will assume that the underlying PCS will pad commitments to a multiple
    /// of `1<<log.stacking_height(verifier)`.
    fn log_stacking_height(verifier: &Self::PcsVerifier) -> u32;

    fn round_multiples(
        proof: &<Self::PcsVerifier as MultilinearPcsVerifier<GC>>::Proof,
    ) -> Vec<usize>;
}

pub type JaggedProof<GC, JC> =
    <<JC as JaggedConfig<GC>>::PcsVerifier as MultilinearPcsVerifier<GC>>::Proof;

pub type JaggedError<GC, JC> =
    <<JC as JaggedConfig<GC>>::PcsVerifier as MultilinearPcsVerifier<GC>>::VerifierError;
