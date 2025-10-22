use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::{
    MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord, PageProtLocalEvent, PageProtRecord,
};

/// SHA-256 Extend Memory Records.
///
/// This struct contains the memory records for a single step of the SHA-256 extend operation.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct ShaExtendMemoryRecords {
    /// The memory read record for `w_i_minus_15`.
    pub w_i_minus_15_reads: MemoryReadRecord,
    /// The memory read record for `w_i_minus_2`.
    pub w_i_minus_2_reads: MemoryReadRecord,
    /// The memory read record for `w_i_minus_16`.
    pub w_i_minus_16_reads: MemoryReadRecord,
    /// The memory read record for `w_i_minus_7`.
    pub w_i_minus_7_reads: MemoryReadRecord,
    /// The memory write record for `w_i`.
    pub w_i_write: MemoryWriteRecord,
}

/// SHA-256 Extend Page Prot Records.
///
/// This struct contains the page prot records for a single step of the SHA-256 extend operation.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct ShaExtendPageProtRecords {
    /// The page prot records for the initial 16 words.
    pub initial_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for the extensions.
    pub extension_page_prot_records: Vec<PageProtRecord>,
}

/// SHA-256 Extend Event.
///
/// This event is emitted when a SHA-256 extend operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct ShaExtendEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer to the word.
    pub w_ptr: u64,
    /// The memory records.
    pub memory_records: Vec<ShaExtendMemoryRecords>,
    /// The page prot records.
    pub page_prot_records: ShaExtendPageProtRecords,
    /// The local memory accesses.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The local page prot accesses.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}
