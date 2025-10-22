use sp1_core_machine::executor::MachineExecutorError;
use thiserror::Error;
use tokio::sync::oneshot;

#[derive(Debug, Error)]
pub enum SP1ProverError {
    #[error("Compilation error")]
    CompilationError,
    // Core executor error.
    #[error("Core executor error: {0}")]
    CoreExecutorError(#[from] MachineExecutorError),
    /// Recursion program error.
    #[error("Recursion program error: {0}")]
    RecursionProgramError(#[from] RecursionProgramError),
    /// Other error.
    #[error("Unexpected error: {0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum RecursionProgramError {
    #[error("Compilation error: {0}")]
    CompilationError(#[from] oneshot::error::RecvError),
    // Recursion witness error.
    #[error("Invalid record shape for shard chips")]
    InvalidRecordShape,
    #[error("Task was aborted")]
    TaskAborted,
}
