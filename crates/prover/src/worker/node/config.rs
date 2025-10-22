use crate::worker::{SP1ControllerConfig, SP1ProverConfig};

pub struct SP1LocalNodeConfig {
    pub controller_config: SP1ControllerConfig,
    pub prover_config: SP1ProverConfig,
}

// Default values for the controller config.
pub(crate) const DEFAULT_NUM_SPLICING_WORKERS: usize = 2;
pub(crate) const DEFAULT_SPLICING_BUFFER_SIZE: usize = 2;

// Default values for the core prover config.
pub(crate) const DEFAULT_NUM_TRACE_EXECUTOR_WORKERS: usize = 4;
pub(crate) const DEFAULT_TRACE_EXECUTOR_BUFFER_SIZE: usize = 4;
pub(crate) const DEFAULT_NUM_CORE_PROVER_WORKERS: usize = 4;
pub(crate) const DEFAULT_CORE_PROVER_BUFFER_SIZE: usize = 4;
pub(crate) const DEFAULT_NUM_SETUP_WORKERS: usize = 2;
pub(crate) const DEFAULT_SETUP_BUFFER_SIZE: usize = 2;
