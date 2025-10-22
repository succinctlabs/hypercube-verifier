use super::SyscallRuntime;
use crate::syscalls::SyscallCode;

pub(crate) fn hint_len_syscall<'a, RT: SyscallRuntime<'a>>(
    ctx: &mut RT,
    _: SyscallCode,
    _: u64,
    _: u64,
) -> Option<u64> {
    let core_mut = ctx.core_mut();
    core_mut.hint_lens.next().map_or(Some(u64::MAX), |len| Some(*len as u64))
}
