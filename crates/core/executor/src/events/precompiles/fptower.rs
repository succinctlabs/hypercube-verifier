use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::{
    MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord, PageProtLocalEvent, PageProtRecord,
};

/// This is an arithmetic operation for emulating modular arithmetic.
#[derive(Default, PartialEq, Copy, Clone, Debug, Serialize, Deserialize, DeepSizeOf)]
pub enum FieldOperation {
    /// Addition.
    #[default]
    Add,
    /// Multiplication.
    Mul,
    /// Subtraction.
    Sub,
    /// Division.
    Div,
}

/// Each fp op has one read slice and one write slice operation that require page prot checks.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct FpPageProtRecords {
    /// The page prot records for reading the address.
    pub read_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for writing the address.
    pub write_page_prot_records: Vec<PageProtRecord>,
}

/// Emulated Field Operation Events.
///
/// This event is emitted when an emulated field operation is performed on the input operands.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct FpOpEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer to the x operand.
    pub x_ptr: u64,
    /// The x operand.
    pub x: Vec<u64>,
    /// The pointer to the y operand.
    pub y_ptr: u64,
    /// The y operand.
    pub y: Vec<u64>,
    /// The operation to perform.
    pub op: FieldOperation,
    /// The memory records for the x operand.
    pub x_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the y operand.
    pub y_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot records.
    pub page_prot_records: FpPageProtRecords,
    /// The local page prot access records.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}

/// Emulated Degree 2 Field Addition/Subtraction Events.
///
/// This event is emitted when an emulated degree 2 field operation is performed on the input
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct Fp2AddSubEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The operation to perform.
    pub op: FieldOperation,
    /// The pointer to the x operand.
    pub x_ptr: u64,
    /// The x operand.
    pub x: Vec<u64>,
    /// The pointer to the y operand.
    pub y_ptr: u64,
    /// The y operand.
    pub y: Vec<u64>,
    /// The memory records for the x operand.
    pub x_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the y operand.
    pub y_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot records.
    pub page_prot_records: FpPageProtRecords,
    /// The local page prot access records.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}

/// Emulated Degree 2 Field Multiplication Events.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct Fp2MulEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer to the x operand.
    pub x_ptr: u64,
    /// The x operand.
    pub x: Vec<u64>,
    /// The pointer to the y operand.
    pub y_ptr: u64,
    /// The y operand.
    pub y: Vec<u64>,
    /// The memory records for the x operand.
    pub x_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the y operand.
    pub y_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot records.
    pub page_prot_records: FpPageProtRecords,
    /// The local page prot access records.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}
