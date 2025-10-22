use crate::{
    events::MemoryRecord, syscalls::SyscallCode, vm::shapes::riscv_air_id_from_opcode,
    CompressedMemory, ExecutionReport, Instruction, Opcode, RiscvAirId,
};
use enum_map::EnumMap;
use hashbrown::{HashMap, HashSet};
use std::str::FromStr;

// Trusted gas estimation calculator
// For a given executor, calculate the total complexity and trace area
// Based off of ShapeChecker
pub struct ReportGenerator {
    pub opcode_counts: EnumMap<Opcode, u64>,
    pub syscall_counts: EnumMap<SyscallCode, u64>,
    pub deferred_syscall_counts: EnumMap<SyscallCode, u64>,
    pub system_chips_counts: EnumMap<RiscvAirId, u64>,

    pub(crate) syscall_sent: bool,
    pub(crate) local_mem_counts: u64,
    is_last_read_external: CompressedMemory,

    trace_cost_lookup: EnumMap<RiscvAirId, u64>,

    shard_start_clk: u64,
}

impl ReportGenerator {
    pub fn new(shard_start_clk: u64) -> Self {
        let costs: HashMap<String, usize> =
            serde_json::from_str(include_str!("../artifacts/rv64im_costs.json")).unwrap();
        let costs: EnumMap<RiscvAirId, u64> =
            costs.into_iter().map(|(k, v)| (RiscvAirId::from_str(&k).unwrap(), v as u64)).collect();

        Self {
            trace_cost_lookup: costs,
            opcode_counts: EnumMap::default(),
            syscall_counts: EnumMap::default(),
            deferred_syscall_counts: EnumMap::default(),
            system_chips_counts: EnumMap::default(),
            syscall_sent: false,
            local_mem_counts: 0,
            is_last_read_external: CompressedMemory::new(),
            shard_start_clk,
        }
    }

    /// Set the start clock of the shard.
    #[inline]
    pub fn reset(&mut self, clk: u64) {
        *self = Self::new(clk);
    }

    pub fn get_costs(&self) -> (u64, u64) {
        (self.sum_total_complexity(), self.sum_total_trace_area())
    }

    /// Generate an `ExecutionReport` from the current state of the `ReportGenerator`
    pub fn generate_report(&self) -> ExecutionReport {
        // Combine syscall_counts and deferred_syscall_counts
        let mut total_syscall_counts = self.syscall_counts;
        for (syscall_code, &count) in self.deferred_syscall_counts.iter() {
            if count > 0 {
                total_syscall_counts[syscall_code] += count;
            }
        }

        let (complexity, trace_area) = self.get_costs();
        // Use integer arithmetic to avoid f64 precision warnings
        // 0.3 * trace_area + 0.1 * complexity ≈ (3 * trace_area + complexity) / 10
        let gas = (3 * trace_area + complexity) / 10;

        ExecutionReport {
            opcode_counts: Box::new(self.opcode_counts),
            syscall_counts: Box::new(total_syscall_counts),
            cycle_tracker: HashMap::new(), // TODO: Fill out
            invocation_tracker: HashMap::new(),
            touched_memory_addresses: 0,
            gas: Some(gas),
        }
    }

    /// Helper method to filter out opcode counts with zero values
    fn filtered_opcode_counts(&self) -> impl Iterator<Item = (Opcode, u64)> + '_ {
        self.opcode_counts
            .iter()
            .filter(|(_, &count)| count > 0)
            .map(|(opcode, &count)| (opcode, count))
    }

    fn sum_total_complexity(&self) -> u64 {
        self.filtered_opcode_counts()
            .map(|(opcode, count)| {
                get_complexity_mapping()[riscv_air_id_from_opcode(opcode)] * count
            })
            .sum::<u64>()
            + self
                .syscall_counts
                .iter()
                .map(|(syscall_code, count)| {
                    if let Some(syscall_air_id) = syscall_code.as_air_id() {
                        get_complexity_mapping()[syscall_air_id] * count
                    } else {
                        tracing::warn!("Syscall with no air id: {:?}", syscall_code);
                        0
                    }
                })
                .sum::<u64>()
            + self
                .deferred_syscall_counts
                .iter()
                .map(|(syscall_code, count)| {
                    if let Some(syscall_air_id) = syscall_code.as_air_id() {
                        get_complexity_mapping()[syscall_air_id] * count
                    } else {
                        tracing::warn!("Syscall with no air id: {:?}", syscall_code);
                        0
                    }
                })
                .sum::<u64>()
            + self
                .system_chips_counts
                .iter()
                .map(|(riscv_air_id, count)| get_complexity_mapping()[riscv_air_id] * count)
                .sum::<u64>()
    }

    fn sum_total_trace_area(&self) -> u64 {
        self.filtered_opcode_counts()
            .map(|(opcode, count)| self.trace_cost_lookup[riscv_air_id_from_opcode(opcode)] * count)
            .sum::<u64>()
            + self
                .syscall_counts
                .iter()
                .map(|(syscall_code, count)| {
                    if let Some(syscall_air_id) = syscall_code.as_air_id() {
                        self.trace_cost_lookup[syscall_air_id] * count
                    } else {
                        tracing::warn!("Syscall with no air id: {:?}", syscall_code);
                        0
                    }
                })
                .sum::<u64>()
            + self
                .deferred_syscall_counts
                .iter()
                .map(|(syscall_code, count)| {
                    if let Some(syscall_air_id) = syscall_code.as_air_id() {
                        self.trace_cost_lookup[syscall_air_id] * count
                    } else {
                        tracing::warn!("Syscall with no air id: {:?}", syscall_code);
                        0
                    }
                })
                .sum::<u64>()
            + self
                .system_chips_counts
                .iter()
                .map(|(riscv_air_id, count)| self.trace_cost_lookup[riscv_air_id] * count)
                .sum::<u64>()
    }

    #[inline]
    pub fn handle_mem_event(&mut self, addr: u64, clk: u64) {
        // Round down to the nearest 8-byte aligned address.
        let addr = if addr > 31 { addr & !0b111 } else { addr };

        let is_external = self.syscall_sent;

        let is_first_read_this_shard = self.shard_start_clk > clk;

        let is_last_read_external = self.is_last_read_external.insert(addr, is_external);

        self.local_mem_counts +=
            (is_first_read_this_shard || (is_last_read_external && !is_external)) as u64;
    }

    #[inline]
    pub fn handle_retained_syscall(&mut self, syscall_code: SyscallCode) {
        if let Some(syscall_air_id) = syscall_code.as_air_id() {
            let rows_per_event = syscall_air_id.rows_per_event() as u64;

            self.syscall_counts[syscall_code] += rows_per_event;
        }
    }

    #[inline]
    pub fn add_global_init_and_finalize_counts(
        &mut self,
        final_registers: &[MemoryRecord; 32],
        mut touched_addresses: HashSet<u64>,
        hint_init_events_addrs: &HashSet<u64>,
        memory_image_addrs: &[u64],
    ) {
        touched_addresses.extend(memory_image_addrs);

        // Add init for registers
        self.system_chips_counts[RiscvAirId::MemoryGlobalInit] += 32;

        // Add finalize for registers
        self.system_chips_counts[RiscvAirId::MemoryGlobalFinalize] +=
            final_registers.iter().enumerate().filter(|(_, e)| e.timestamp != 0).count() as u64;

        // Add memory init events
        self.system_chips_counts[RiscvAirId::MemoryGlobalInit] +=
            hint_init_events_addrs.len() as u64;

        let memory_init_events = touched_addresses
            .iter()
            .filter(|addr| !memory_image_addrs.contains(*addr))
            .filter(|addr| !hint_init_events_addrs.contains(*addr));
        self.system_chips_counts[RiscvAirId::MemoryGlobalInit] += memory_init_events.count() as u64;

        touched_addresses.extend(hint_init_events_addrs.clone());
        self.system_chips_counts[RiscvAirId::MemoryGlobalFinalize] +=
            touched_addresses.len() as u64;
    }

    /// Increment the trace area for the given instruction.
    ///
    /// # Arguments
    ///
    /// * `instruction`: The instruction that is being handled.
    /// * `syscall_sent`: Whether a syscall was sent during this cycle.
    /// * `bump_clk_high`: Whether the clk's top 24 bits incremented during this cycle.
    /// * `is_load_x0`: Whether the instruction is a load of x0, if so the riscv air id is `LoadX0`.
    ///
    /// # Returns
    ///
    /// Whether the shard limit has been reached.
    #[inline]
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn handle_instruction(
        &mut self,
        instruction: &Instruction,
        bump_clk_high: bool,
        _is_load_x0: bool,
        needs_state_bump: bool,
    ) {
        let touched_addresses: u64 = std::mem::take(&mut self.local_mem_counts);
        let syscall_sent = std::mem::take(&mut self.syscall_sent);

        // Increment for opcode
        self.opcode_counts[instruction.opcode] += 1;

        // Increment system chips
        // Increment by if bump_clk_high is needed
        let bump_clk_high_num_events = 32 * bump_clk_high as u64;
        self.system_chips_counts[RiscvAirId::MemoryBump] += bump_clk_high_num_events;
        self.system_chips_counts[RiscvAirId::MemoryLocal] += touched_addresses;
        self.system_chips_counts[RiscvAirId::StateBump] += needs_state_bump as u64;
        self.system_chips_counts[RiscvAirId::Global] += 2 * touched_addresses + syscall_sent as u64;

        // Increment if the syscall is retained
        self.system_chips_counts[RiscvAirId::SyscallCore] += syscall_sent as u64;
    }

    #[inline]
    pub fn syscall_sent(&mut self, syscall_code: SyscallCode) {
        self.syscall_sent = true;
        if let Some(syscall_air_id) = syscall_code.as_air_id() {
            let rows_per_event = syscall_air_id.rows_per_event() as u64;

            self.deferred_syscall_counts[syscall_code] += rows_per_event;
        }
    }
}

/// Returns a mapping of `RiscvAirId` to their associated complexity codes.
/// This provides the complexity cost for each AIR component in the system.
pub fn get_complexity_mapping() -> EnumMap<RiscvAirId, u64> {
    let mut mapping = EnumMap::<RiscvAirId, u64>::default();

    // Core program and system components
    mapping[RiscvAirId::Program] = 0;
    mapping[RiscvAirId::SyscallCore] = 2;
    mapping[RiscvAirId::SyscallPrecompile] = 2;

    // SHA components
    mapping[RiscvAirId::ShaExtend] = 80;
    mapping[RiscvAirId::ShaExtendControl] = 73;
    mapping[RiscvAirId::ShaCompress] = 300;
    mapping[RiscvAirId::ShaCompressControl] = 99;

    // Elliptic curve operations
    mapping[RiscvAirId::EdAddAssign] = 844;
    mapping[RiscvAirId::EdDecompress] = 807;

    // Secp256k1 operations
    mapping[RiscvAirId::Secp256k1Decompress] = 743;
    mapping[RiscvAirId::Secp256k1AddAssign] = 970;
    mapping[RiscvAirId::Secp256k1DoubleAssign] = 930;

    // Secp256r1 operations
    mapping[RiscvAirId::Secp256r1Decompress] = 743;
    mapping[RiscvAirId::Secp256r1AddAssign] = 970;
    mapping[RiscvAirId::Secp256r1DoubleAssign] = 930;

    // Keccak operations
    mapping[RiscvAirId::KeccakPermute] = 2859;
    mapping[RiscvAirId::KeccakPermuteControl] = 383;

    // Bn254 operations
    mapping[RiscvAirId::Bn254AddAssign] = 970;
    mapping[RiscvAirId::Bn254DoubleAssign] = 930;

    // BLS12-381 operations
    mapping[RiscvAirId::Bls12381AddAssign] = 1426;
    mapping[RiscvAirId::Bls12381DoubleAssign] = 1382;
    mapping[RiscvAirId::Bls12381Decompress] = 1289;

    // Uint256 operations
    mapping[RiscvAirId::Uint256MulMod] = 305;
    mapping[RiscvAirId::Uint256Ops] = 427;
    mapping[RiscvAirId::U256XU2048Mul] = 1301;

    // Field operations
    mapping[RiscvAirId::Bls12381FpOpAssign] = 369;
    mapping[RiscvAirId::Bls12381Fp2AddSubAssign] = 667;
    mapping[RiscvAirId::Bls12381Fp2MulAssign] = 1046;
    mapping[RiscvAirId::Bn254FpOpAssign] = 269;
    mapping[RiscvAirId::Bn254Fp2AddSubAssign] = 467;
    mapping[RiscvAirId::Bn254Fp2MulAssign] = 718;

    // System operations
    mapping[RiscvAirId::Mprotect] = 11;
    mapping[RiscvAirId::Poseidon2] = 523;

    // RISC-V instruction costs
    mapping[RiscvAirId::DivRem] = 351;
    mapping[RiscvAirId::Add] = 19;
    mapping[RiscvAirId::Addi] = 18;
    mapping[RiscvAirId::Addw] = 24;
    mapping[RiscvAirId::Sub] = 19;
    mapping[RiscvAirId::Subw] = 19;
    mapping[RiscvAirId::Bitwise] = 23;
    mapping[RiscvAirId::Mul] = 64;
    mapping[RiscvAirId::ShiftRight] = 81;
    mapping[RiscvAirId::ShiftLeft] = 72;
    mapping[RiscvAirId::Lt] = 45;

    // Memory operations
    mapping[RiscvAirId::LoadByte] = 37;
    mapping[RiscvAirId::LoadHalf] = 38;
    mapping[RiscvAirId::LoadWord] = 38;
    mapping[RiscvAirId::LoadDouble] = 29;
    mapping[RiscvAirId::LoadX0] = 39;
    mapping[RiscvAirId::StoreByte] = 37;
    mapping[RiscvAirId::StoreHalf] = 32;
    mapping[RiscvAirId::StoreWord] = 32;
    mapping[RiscvAirId::StoreDouble] = 28;

    // Control flow
    mapping[RiscvAirId::UType] = 23;
    mapping[RiscvAirId::Branch] = 53;
    mapping[RiscvAirId::Jal] = 28;
    mapping[RiscvAirId::Jalr] = 29;

    // System components
    mapping[RiscvAirId::InstructionDecode] = 160;
    mapping[RiscvAirId::InstructionFetch] = 11;
    mapping[RiscvAirId::SyscallInstrs] = 102;
    mapping[RiscvAirId::MemoryBump] = 5;
    mapping[RiscvAirId::PageProt] = 32;
    mapping[RiscvAirId::PageProtLocal] = 1;
    mapping[RiscvAirId::StateBump] = 8;
    mapping[RiscvAirId::MemoryGlobalInit] = 31;
    mapping[RiscvAirId::MemoryGlobalFinalize] = 31;
    mapping[RiscvAirId::PageProtGlobalInit] = 26;
    mapping[RiscvAirId::PageProtGlobalFinalize] = 25;
    mapping[RiscvAirId::MemoryLocal] = 4;
    mapping[RiscvAirId::Global] = 276;

    // Memory types
    mapping[RiscvAirId::Byte] = 0;
    mapping[RiscvAirId::Range] = 0;

    mapping
}
