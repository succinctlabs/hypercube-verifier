use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent, PageProtLocalEvent, PageProtRecord,
};

pub(crate) const STATE_SIZE: usize = 25;

/// Keccak-256 Permutation Page Prot Records.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct KeccakPermutePageProtRecords {
    /// The page prot records for reading the pre-state address.
    pub read_pre_state_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for writing the post-state address.
    pub write_post_state_page_prot_records: Vec<PageProtRecord>,
}

/// Keccak-256 Permutation Event.
///
/// This event is emitted when a keccak-256 permutation operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct KeccakPermuteEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pre-state as a list of u64 words.
    pub pre_state: [u64; STATE_SIZE],
    /// The post-state as a list of u64 words.
    pub post_state: [u64; STATE_SIZE],
    /// The memory records for the pre-state.
    pub state_read_records: Vec<MemoryReadRecord>,
    /// The memory records for the post-state.
    pub state_write_records: Vec<MemoryWriteRecord>,
    /// The address of the state.
    pub state_addr: u64,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot records.
    pub page_prot_records: KeccakPermutePageProtRecords,
    /// The local page prot access events.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}
