use crate::types::Buffer;
use serde::{Deserialize, Serialize};

/// Public values for the prover.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SP1PublicValues {
    buffer: Buffer,
}
