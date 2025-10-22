use sp1_primitives::SP1Field;

use crate::{ir::Builder, prelude::Config};

/// An assembly code configuration given a field and an extension field.
#[derive(Debug, Clone, Default)]
pub struct AsmConfig;

pub type AsmBuilder = Builder<AsmConfig>;

impl Config for AsmConfig {
    type N = SP1Field;
}
