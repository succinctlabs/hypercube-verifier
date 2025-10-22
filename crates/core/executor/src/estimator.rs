//! Data that may be collected during execution and used to estimate trace area.

use enum_map::EnumMap;

use crate::RiscvAirId;

/// Data accumulated during execution to estimate the core trace area used to prove the execution.
#[derive(Clone, Debug, Default)]
pub struct RecordEstimator {
    /// Core shards, represented by the number of events per AIR.
    pub core_records: Vec<EnumMap<RiscvAirId, u64>>,
    /// For each precompile AIR, a list of estimated records in the form
    /// `(<number of precompile events>, <number of local memory events>)`.
    pub precompile_records: EnumMap<RiscvAirId, Vec<(u64, u64)>>,
    /// Number of memory global init events for the whole program.
    pub memory_global_init_events: u64,
    /// Number of memory global finalize events for the whole program.
    pub memory_global_finalize_events: u64,
}
