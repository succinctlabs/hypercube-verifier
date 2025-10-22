use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
    PageProtLocalEvent, PageProtRecord,
};

/// `U256xU2048` Mul Page Prot Records.
///
/// This struct contains the page prot records for the `U256xU2048` mul operation.
/// Each vector will have at least length 1, length 2 if the operation is split across two pages.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct U256xU2048MulPageProtRecords {
    /// The page prot records for reading the a address.
    pub read_a_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for reading the b address.
    pub read_b_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for writing the lo address.
    pub write_lo_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for writing the hi address.
    pub write_hi_page_prot_records: Vec<PageProtRecord>,
}

/// `U256xU2048` Mul Event.
///
/// This event is emitted when a `U256xU2048` mul operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct U256xU2048MulEvent {
    /// The channel number.
    pub clk: u64,
    /// The pointer to the a value.
    pub a_ptr: u64,
    /// The a value as a list of words.
    pub a: Vec<u64>,
    /// The pointer to the b value.
    pub b_ptr: u64,
    /// The b value as a list of words.
    pub b: Vec<u64>,
    /// The pointer to the lo value.
    pub lo_ptr: u64,
    /// The memory record for the pointer to the lo value.
    pub lo_ptr_memory: MemoryReadRecord,
    /// The lo value as a list of words.
    pub lo: Vec<u64>,
    /// The pointer to the hi value.
    pub hi_ptr: u64,
    /// The memory record for the pointer to the hi value.
    pub hi_ptr_memory: MemoryReadRecord,
    /// The hi value as a list of words.
    pub hi: Vec<u64>,
    /// The memory records for the a value.
    pub a_memory_records: Vec<MemoryReadRecord>,
    /// The memory records for the b value.
    pub b_memory_records: Vec<MemoryReadRecord>,
    /// The memory records for lo.
    pub lo_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for hi.
    pub hi_memory_records: Vec<MemoryWriteRecord>,
    /// The local memory access events.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot records.
    pub page_prot_records: U256xU2048MulPageProtRecords,
    /// The local page prot access events.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}
