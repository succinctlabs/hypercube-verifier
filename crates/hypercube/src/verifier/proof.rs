use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use slop_challenger::IopCtx;
use slop_jagged::JaggedPcsProof;
use slop_matrix::dense::RowMajorMatrixView;
use slop_multilinear::Point;
use slop_sumcheck::PartialSumcheckProof;

use crate::{LogupGkrProof, MachineVerifyingKey};

use super::MachineConfig;

/// The maximum number of elements that can be stored in the public values vec.  Both SP1 and
/// recursive proofs need to pad their public values vec to this length.  This is required since the
/// recursion verification program expects the public values vec to be fixed length.
pub const PROOF_MAX_NUM_PVS: usize = 187;

/// Data required for testing.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "GC: IopCtx, GC::Challenger: Serialize",
    deserialize = "GC: IopCtx, GC::Challenger: Deserialize<'de>"
))]
// #[cfg(any(test, feature = "test-proof"))]
pub struct TestingData<GC: IopCtx> {
    /// The gkr points.
    pub gkr_points: Vec<Point<GC::EF>>,
    /// The challenger state just before the zerocheck.
    pub challenger_state: GC::Challenger,
}

/// A proof for a shard.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: MachineConfig<GC>, GC::Challenger: Serialize",
    deserialize = "C: MachineConfig<GC>, GC::Challenger: Deserialize<'de>"
))]
pub struct ShardProof<GC: IopCtx, C: MachineConfig<GC>> {
    /// The public values
    pub public_values: Vec<GC::F>,
    /// The commitments to main traces.
    pub main_commitment: GC::Digest,
    /// The Logup GKR IOP proof.
    pub logup_gkr_proof: LogupGkrProof<GC::EF>,
    /// TH zerocheck IOP proof.
    pub zerocheck_proof: PartialSumcheckProof<GC::EF>,
    /// The values of the traces at the final random point.
    pub opened_values: ShardOpenedValues<GC::F, GC::EF>,
    /// The evaluation proof.
    pub evaluation_proof: JaggedPcsProof<GC, C>,
}

/// The values of the chips in the shard at a random point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardOpenedValues<F, EF> {
    /// For each chip with respect to the canonical ordering, the values of the chip at the random
    /// point.
    pub chips: BTreeMap<String, ChipOpenedValues<F, EF>>,
}

/// The opening values for a given chip at a random point.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize, EF: Serialize"))]
#[serde(bound(deserialize = "F: Deserialize<'de>, EF: Deserialize<'de>"))]
pub struct ChipOpenedValues<F, EF> {
    /// The opening of the preprocessed trace.
    pub preprocessed: AirOpenedValues<EF>,
    /// The opening of the main trace.
    pub main: AirOpenedValues<EF>,
    /// The big-endian bit representation of the degree of the chip.
    pub degree: Point<F>,
}

/// The opening values for a given table section at a random point.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize"))]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct AirOpenedValues<T> {
    /// The opening of the local trace
    pub local: Vec<T>,
}

impl<T> AirOpenedValues<T> {
    /// Organize the opening values into a vertical pair.
    #[must_use]
    pub fn view(&self) -> RowMajorMatrixView<'_, T>
    where
        T: Clone + Send + Sync,
    {
        RowMajorMatrixView::new_row(&self.local)
    }
}

/// An intermediate proof which proves the execution of a Hypercube verifier.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(
    serialize = "GC: IopCtx, GC::Challenger: Serialize",
    deserialize = "GC: IopCtx, GC::Challenger: Deserialize<'de>"
))]
pub struct SP1RecursionProof<GC: IopCtx, C: MachineConfig<GC>> {
    /// The verifying key associated with the proof.
    pub vk: MachineVerifyingKey<GC, C>,
    /// The shard proof representing the shard proof.
    pub proof: ShardProof<GC, C>,
}

impl<GC: IopCtx, C: MachineConfig<GC>> std::fmt::Debug for SP1RecursionProof<GC, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("SP1ReduceProof");
        // TODO: comment back after debug enabled.
        // debug_struct.field("vk", &self.vk);
        // debug_struct.field("proof", &self.proof);
        debug_struct.finish()
    }
}
