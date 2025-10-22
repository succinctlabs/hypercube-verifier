use crate::{ExecutorConfig, HALT_PC};

use super::{context::SyscallContext, SyscallCode};

pub fn halt_syscall<E: ExecutorConfig>(
    ctx: &mut SyscallContext<E>,
    _: SyscallCode,
    exit_code: u64,
    _: u64,
) -> Option<u64> {
    ctx.set_next_pc(HALT_PC);
    ctx.set_exit_code(exit_code as u32);
    None
}
