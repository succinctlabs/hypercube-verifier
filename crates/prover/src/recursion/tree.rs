use std::{
    borrow::Borrow,
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

use slop_futures::queue::WorkerQueue;
use sp1_core_executor::SP1RecursionProof;
use sp1_hypercube::air::{ShardBoundary, ShardRange};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_recursion_circuit::machine::SP1ShapedWitnessValues;
use sp1_recursion_executor::RecursionPublicValues;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::{error::SP1ProverError, InnerSC, SP1CircuitWitness};

#[derive(Debug, Clone)]
pub struct RecursionProof {
    pub shard_range: ShardRange,
    pub proof: SP1RecursionProof<SP1GlobalContext, InnerSC>,
}

pub struct ExecuteTask {
    pub range: ShardRange,
    pub input: SP1CircuitWitness,
}

/// An enum marking which sibling was found.
enum Sibling {
    Left(RangeProofs),
    Right(RangeProofs),
    Both(RangeProofs, RangeProofs),
}

#[derive(Clone, Debug)]
struct RangeProofs {
    shard_range: ShardRange,
    proofs: VecDeque<SP1RecursionProof<SP1GlobalContext, InnerSC>>,
}

impl RangeProofs {
    pub fn new(
        shard_range: ShardRange,
        proofs: VecDeque<SP1RecursionProof<SP1GlobalContext, InnerSC>>,
    ) -> Self {
        Self { shard_range, proofs }
    }

    pub fn push_right(&mut self, proof: RecursionProof) {
        assert_eq!(proof.shard_range.end(), self.shard_range.start());
        self.shard_range = (proof.shard_range.start()..self.shard_range.end()).into();
        self.proofs.push_front(proof.proof);
    }

    pub fn push_left(&mut self, proof: RecursionProof) {
        assert_eq!(proof.shard_range.start(), self.shard_range.end());
        self.shard_range = (self.shard_range.start()..proof.shard_range.end()).into();
        self.proofs.push_back(proof.proof);
    }

    pub fn split_off(&mut self, at: usize) -> Option<Self> {
        if at >= self.proofs.len() {
            return None;
        }

        let proofs = self.proofs.split_off(at);

        let range = {
            let start_proof_pv: &RecursionPublicValues<SP1Field> =
                proofs.front().unwrap().proof.public_values.as_slice().borrow();
            let at_start_range = start_proof_pv.range().start();
            let end_proof_pv: &RecursionPublicValues<SP1Field> =
                proofs.iter().last().unwrap().proof.public_values.as_slice().borrow();
            let at_end_range = end_proof_pv.range().end();
            at_start_range..at_end_range
        }
        .into();

        let new_self_range = {
            let start_proof_pv: &RecursionPublicValues<SP1Field> =
                self.proofs.front().unwrap().proof.public_values.as_slice().borrow();
            let at_start_range = start_proof_pv.range().start();
            let end_proof_pv: &RecursionPublicValues<SP1Field> =
                self.proofs.iter().last().unwrap().proof.public_values.as_slice().borrow();
            let at_end_range = end_proof_pv.range().end();
            at_start_range..at_end_range
        };
        self.shard_range = new_self_range.into();

        Some(Self { shard_range: range, proofs })
    }

    pub fn push_both(&mut self, middle: RecursionProof, right: Self) {
        assert_eq!(middle.shard_range.start(), self.shard_range.end());
        assert_eq!(right.shard_range.start(), middle.shard_range.end());
        // Push the middle to the queue.
        self.proofs.push_back(middle.proof);
        // Append the right proofs to the queue.
        for proof in right.proofs {
            self.proofs.push_back(proof);
        }
        // Update the shard range.
        self.shard_range = (self.shard_range.start()..right.shard_range.end()).into();
    }

    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn into_witness(
        self,
        is_complete: bool,
    ) -> (ShardRange, SP1ShapedWitnessValues<SP1GlobalContext, InnerSC>) {
        let vks_and_proofs =
            self.proofs.into_iter().map(|proof| (proof.vk, proof.proof)).collect::<Vec<_>>();
        (self.shard_range, SP1ShapedWitnessValues { vks_and_proofs, is_complete })
    }
}

pub struct CompressTree {
    map: BTreeMap<ShardBoundary, RangeProofs>,
    batch_size: usize,
}

impl CompressTree {
    /// Create a new recursion tree.
    pub fn new(batch_size: usize) -> Self {
        Self { map: BTreeMap::new(), batch_size }
    }

    /// Insert a new range of proofs into the tree.
    fn insert(&mut self, proofs: RangeProofs) {
        self.map.insert(proofs.shard_range.start(), proofs);
    }

    /// Get the sibling of a proof.
    fn sibling(&mut self, proof: &RecursionProof) -> Option<Sibling> {
        // Check for a left sibling
        if let Some(previous) =
            self.map.range(ShardBoundary::initial()..=proof.shard_range.start()).next_back()
        {
            let (start, proofs) = previous;
            let start = *start;
            let proofs = proofs.clone();

            if proofs.shard_range.end() == proof.shard_range.start() {
                let left = self.map.remove(&start).unwrap();
                // Check for a right sibling.
                if let Some(right) = self.map.remove(&proof.shard_range.end()) {
                    return Some(Sibling::Both(left, right));
                } else {
                    return Some(Sibling::Left(left));
                }
            }
        }
        // If there is no left sibling, check for a right sibling.
        if let Some(right) = self.map.remove(&proof.shard_range.end()) {
            return Some(Sibling::Right(right));
        }

        // No sibling found.
        None
    }

    fn is_complete(
        &self,
        range: &ShardRange,
        pending_tasks: usize,
        full_range: &Option<ShardRange>,
    ) -> bool {
        (pending_tasks == 0)
            && self.map.is_empty()
            && full_range.as_ref().is_some_and(|full| range == full)
    }

    /// Reduce the proofs into the tree until the batch size is reached.
    ///
    /// ### Inputs
    ///
    /// - `full_range_rx`: A receiver for the full range of proofs.
    /// - `proofs_rx`: A receiver for the proofs to reduce.
    /// - `recursion_executors`: A queue of executors to use to execute the proofs.
    /// - `pending_tasks`: The number of pending tasks that are already running.
    ///
    /// **Remark**: it's important to keep track of the number of pending tasks because the shard
    /// ranges only cover timestamp ranges but do not cover how many precomputed proofs are in the
    /// tree.
    ///
    /// ### Outputs
    ///
    /// - A vector of proofs that have been reduced.
    ///
    /// ### Notes
    ///
    /// This function will terminate when the batch size is reached or when the full range is
    /// reached.
    pub async fn reduce_proofs(
        &mut self,
        mut full_range_rx: oneshot::Receiver<ShardRange>,
        proofs_rx: &mut UnboundedReceiver<RecursionProof>,
        recursion_executors: Arc<WorkerQueue<UnboundedSender<ExecuteTask>>>,
        mut pending_tasks: usize,
    ) -> Result<SP1RecursionProof<SP1GlobalContext, InnerSC>, SP1ProverError> {
        // Populate the recursion proofs into the tree until we reach the reduce batch size.
        let mut full_range = None;
        while let Some(proof) = proofs_rx.recv().await {
            // Mark that this is a completed task.
            pending_tasks -= 1;

            if let Ok(range) = full_range_rx.try_recv() {
                full_range = Some(range);
            }
            if self.is_complete(&proof.shard_range, pending_tasks, &full_range) {
                return Ok(proof.proof);
            }

            // Check if there is a neighboring range.
            if let Some(sibling) = self.sibling(&proof) {
                let mut proofs = match sibling {
                    Sibling::Left(mut proofs) => {
                        proofs.push_left(proof);
                        proofs
                    }
                    Sibling::Right(mut proofs) => {
                        proofs.push_right(proof);
                        proofs
                    }
                    Sibling::Both(mut proofs, right) => {
                        proofs.push_both(proof, right);
                        proofs
                    }
                };

                // Check for proofs to split and put back the reminder.
                let split = proofs.split_off(self.batch_size);
                if let Some(split) = split {
                    self.insert(split);
                }

                if proofs.len() > self.batch_size {
                    tracing::error!("Proofs are larger than the batch size: {:?}", proofs.len());
                    panic!("Proofs are larger than the batch size: {:?}", proofs.len());
                }

                let is_complete = self.is_complete(&proofs.shard_range, pending_tasks, &full_range);

                if proofs.len() == self.batch_size || is_complete {
                    // Compress all the proofs into a single proof.
                    let (range, input) = proofs.into_witness(is_complete);
                    let input = SP1CircuitWitness::Compress(input);
                    // Wait for an executor to be available.
                    let executor = recursion_executors.clone().pop().await.unwrap();
                    pending_tasks += 1;
                    executor.send(ExecuteTask { input, range }).ok();
                } else {
                    self.insert(proofs);
                }
            } else {
                // If there is no neighboring range, add the proof to the tree.
                let RecursionProof { shard_range, proof } = proof;
                let mut queue = VecDeque::with_capacity(self.batch_size);
                queue.push_back(proof);
                let proofs = RangeProofs::new(shard_range, queue);
                self.insert(proofs);
            }
        }

        unreachable!("todo explain this")
    }
}
