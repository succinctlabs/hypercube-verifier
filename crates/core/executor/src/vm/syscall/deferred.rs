use crate::{syscalls::SyscallCode, vm::syscall::SyscallRuntime};

pub(crate) fn commit_deferred_proofs_syscall<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    _: SyscallCode,
    word_idx: u64,
    word: u64,
) -> Option<u64> {
    if RT::TRACING {
        let record = rt.record_mut();

        record.public_values.deferred_proofs_digest[word_idx as usize] = word as u32;
        record.public_values.commit_deferred_syscall = 1;
    }

    None
}
