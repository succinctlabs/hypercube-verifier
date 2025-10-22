use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::syscalls::SyscallCode;

/// Syscall Event.
///
/// This object encapsulated the information needed to prove a syscall invocation from the CPU
/// table. This includes its shard, clk, syscall id, arguments, other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, DeepSizeOf)]
#[repr(C)]
pub struct SyscallEvent {
    /// The program counter.
    pub pc: u64,
    /// The next program counter.
    pub next_pc: u64,
    /// The clock cycle.
    pub clk: u64,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
    /// Whether this syscall should be sent.
    pub should_send: bool,
    /// The syscall code.
    pub syscall_code: SyscallCode,
    /// The syscall id.
    pub syscall_id: u32,
    /// The first operand value (`op_b`).
    pub arg1: u64,
    /// The second operand value (`op_c`).
    pub arg2: u64,
    /// The exit code.
    pub exit_code: u32,
}
