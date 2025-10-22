use crate::ExecutorConfig;

use super::{SyscallCode, SyscallContext};

#[allow(clippy::mut_mut)]
pub fn commit_deferred_proofs_syscall<E: ExecutorConfig>(
    ctx: &mut SyscallContext<E>,
    _: SyscallCode,
    word_idx: u64,
    word: u64,
) -> Option<u64> {
    ctx.rt.record.public_values.deferred_proofs_digest[word_idx as usize] = word as u32;
    ctx.rt.record.public_values.commit_deferred_syscall = 1;
    None
}
