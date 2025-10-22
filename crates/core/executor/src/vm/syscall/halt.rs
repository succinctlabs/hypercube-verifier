use crate::{syscalls::SyscallCode, vm::syscall::SyscallRuntime, HALT_PC};

pub(crate) fn halt_syscall<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    _: SyscallCode,
    exit_code: u64,
    _: u64,
) -> Option<u64> {
    let core_mut = rt.core_mut();

    core_mut.set_next_pc(HALT_PC);
    core_mut.set_exit_code(exit_code as u32);
    None
}
