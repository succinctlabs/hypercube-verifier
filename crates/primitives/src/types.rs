use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
pub enum RecursionProgramType {
    Core,
    Deferred,
    Compress,
    Shrink,
    Wrap,
}

/// A buffer of serializable/deserializable objects.                                              
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Buffer {
    pub data: Vec<u8>,
    #[serde(skip)]
    pub ptr: usize,
}

impl Buffer {
    pub const fn new() -> Self {
        Self { data: Vec::new(), ptr: 0 }
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}
