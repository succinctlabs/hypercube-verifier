use slop_bn254::Bn254Fr;

use crate::{circuit::AsmConfig, prelude::Config};

pub type InnerConfig = AsmConfig;

#[derive(Clone, Default, Debug)]
pub struct OuterConfig;

impl Config for OuterConfig {
    type N = Bn254Fr;
}
