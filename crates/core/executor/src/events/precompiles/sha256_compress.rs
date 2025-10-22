use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent, PageProtLocalEvent, PageProtRecord,
};

/// SHA-256 Compress Page Prot Access.
///
/// This struct is used to track the page prot access for the SHA-256 compress operation.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct ShaCompressPageProtAccess {
    /// Reading initial h state prot record
    pub h_read_page_prot_records: Vec<PageProtRecord>,
    /// Reading w state to feed into compress prot record
    pub w_read_page_prot_records: Vec<PageProtRecord>,
    /// Writing final h after compress completed prot record
    pub h_write_page_prot_records: Vec<PageProtRecord>,
}

/// SHA-256 Compress Event.
///
/// This event is emitted when a SHA-256 compress operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct ShaCompressEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer to the word.
    pub w_ptr: u64,
    /// The word as a list of words.
    pub h_ptr: u64,
    /// The word as a list of words.
    pub w: Vec<u32>,
    /// The word as a list of words.
    pub h: [u32; 8],
    /// The memory records for the word.
    pub h_read_records: [MemoryReadRecord; 8],
    /// The memory records for the word.
    pub w_i_read_records: Vec<MemoryReadRecord>,
    /// The memory records for the word.
    pub h_write_records: [MemoryWriteRecord; 8],
    /// The local memory accesses.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot accesses.
    pub page_prot_access: ShaCompressPageProtAccess,
    /// The local page prot accesses.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}
