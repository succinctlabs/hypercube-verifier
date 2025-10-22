use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};
use sp1_curves::{edwards::WORDS_FIELD_ELEMENT, COMPRESSED_POINT_BYTES, NUM_BYTES_FIELD_ELEMENT};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent, PageProtLocalEvent, PageProtRecord,
};

/// Edwards Page Prot Records
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct EdwardsPageProtRecords {
    /// The page prot records for reading the address.
    pub read_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for writing the address.
    pub write_page_prot_records: Vec<PageProtRecord>,
}

/// Edwards Decompress Event.
///
/// This event is emitted when an edwards decompression operation is performed.
#[derive(Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct EdDecompressEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer to the point.
    pub ptr: u64,
    /// The sign bit of the point.
    pub sign: bool,
    /// The comprssed y coordinate as a list of bytes.
    pub y_bytes: [u8; COMPRESSED_POINT_BYTES],
    #[serde(with = "serde_arrays")]
    /// The decompressed x coordinate as a list of bytes.
    pub decompressed_x_bytes: [u8; NUM_BYTES_FIELD_ELEMENT],
    /// The memory records for the x coordinate.
    pub x_memory_records: [MemoryWriteRecord; WORDS_FIELD_ELEMENT],
    /// The memory records for the y coordinate.
    pub y_memory_records: [MemoryReadRecord; WORDS_FIELD_ELEMENT],
    /// The local memory access events.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot records.
    pub page_prot_records: EdwardsPageProtRecords,
    /// The local page prot access records.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}

impl Default for EdDecompressEvent {
    fn default() -> Self {
        Self {
            clk: 0,
            ptr: 0,
            sign: false,
            y_bytes: [0; COMPRESSED_POINT_BYTES],
            decompressed_x_bytes: [0; NUM_BYTES_FIELD_ELEMENT],
            x_memory_records: [MemoryWriteRecord::default(); WORDS_FIELD_ELEMENT],
            y_memory_records: [MemoryReadRecord::default(); WORDS_FIELD_ELEMENT],
            local_mem_access: Vec::new(),
            page_prot_records: EdwardsPageProtRecords::default(),
            local_page_prot_access: Vec::new(),
        }
    }
}
