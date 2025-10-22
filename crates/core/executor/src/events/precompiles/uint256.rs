use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent, PageProtLocalEvent, PageProtRecord,
};

/// Uint256 Mul Page Prot Records.
///
/// This struct contains the page prot records for the uint256 mul operation.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct Uint256MulPageProtRecords {
    /// The page prot records for writing the x address.
    pub write_x_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for reading the y||modulus address.
    pub read_y_modulus_page_prot_records: Vec<PageProtRecord>,
}

/// Uint256 Mul Event.
///
/// This event is emitted when a uint256 mul operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct Uint256MulEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer to the x value.
    pub x_ptr: u64,
    /// The x value as a list of words.
    pub x: Vec<u64>,
    /// The pointer to the y value.
    pub y_ptr: u64,
    /// The y value as a list of words.
    pub y: Vec<u64>,
    /// The modulus as a list of words.
    pub modulus: Vec<u64>,
    /// The memory records for the x value.
    pub x_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the y value.
    pub y_memory_records: Vec<MemoryReadRecord>,
    /// The memory records for the modulus.
    pub modulus_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot records.
    pub page_prot_records: Uint256MulPageProtRecords,
    /// The local page prot access events.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}
