use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent, PageProtLocalEvent, PageProtRecord,
};

/// Uint256 operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, DeepSizeOf)]
pub enum Uint256Operation {
    /// Addition operation.
    #[default]
    Add,
    /// Multiplication operation.
    Mul,
}

/// Uint256 Ops Page Prot Records.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct Uint256OpsPageProtRecords {
    /// The page prot records for reading the a address.
    pub read_a_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for reading the b address.
    pub read_b_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for reading the c address.
    pub read_c_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for writing the d address.
    pub write_d_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for writing the e address.
    pub write_e_page_prot_records: Vec<PageProtRecord>,
}

/// Uint256 operations event.
#[derive(Debug, Clone, Serialize, Deserialize, Default, DeepSizeOf)]
pub struct Uint256OpsEvent {
    /// The clock cycle that this event occurred in.
    pub clk: u64,
    /// The operation performed.
    pub op: Uint256Operation,
    /// The pointer to the a value.
    pub a_ptr: u64,
    /// The a value.
    pub a: [u64; 4],
    /// The pointer to the b value.
    pub b_ptr: u64,
    /// The b value.
    pub b: [u64; 4],
    /// The pointer to the c value.
    pub c_ptr: u64,
    /// The c value.
    pub c: [u64; 4],
    /// The pointer to the d value (result low).
    pub d_ptr: u64,
    /// The d value (result low).
    pub d: [u64; 4],
    /// The pointer to the e value (result high).
    pub e_ptr: u64,
    /// The e value (result high).
    pub e: [u64; 4],
    /// The memory record for reading ``c_ptr`` from register.
    pub c_ptr_memory: MemoryReadRecord,
    /// The memory record for reading ``d_ptr`` from register.
    pub d_ptr_memory: MemoryReadRecord,
    /// The memory record for reading ``e_ptr`` from register.
    pub e_ptr_memory: MemoryReadRecord,
    /// The memory records for reading a.
    pub a_memory_records: Vec<MemoryReadRecord>,
    /// The memory records for reading b.
    pub b_memory_records: Vec<MemoryReadRecord>,
    /// The memory records for reading c.
    pub c_memory_records: Vec<MemoryReadRecord>,
    /// The memory records for writing d.
    pub d_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for writing e.
    pub e_memory_records: Vec<MemoryWriteRecord>,
    /// The local memory access events.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot records.
    pub page_prot_records: Uint256OpsPageProtRecords,
    /// The local page prot access events.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}
