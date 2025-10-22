use crate::{
    events::{KeccakPermuteEvent, KeccakPermutePageProtRecords, PrecompileEvent},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
};

use tiny_keccak::keccakf;

pub(crate) const STATE_SIZE: usize = 25;

// The permutation state is 25 u64's.  Our word size is 64 bits, so it is 25 words.
pub const STATE_NUM_WORDS: usize = STATE_SIZE;

pub(crate) fn keccak256_permute_syscall<E: ExecutorConfig>(
    rt: &mut SyscallContext<E>,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let start_clk = rt.clk;
    let state_ptr = arg1;
    if arg2 != 0 {
        panic!("Expected arg2 to be 0, got {arg2}");
    }

    let mut state_read_records = Vec::new();
    let mut state_write_records = Vec::new();

    let (state_records, state, read_pre_state_page_prot_records) =
        rt.mr_slice(state_ptr, STATE_NUM_WORDS);
    state_read_records.extend_from_slice(&state_records);

    let saved_state = state.clone();

    let mut state = state.try_into().unwrap();
    keccakf(&mut state);

    // Increment the clk by 1 before writing because we read from memory at start_clk.
    rt.clk += 1;

    let (write_records, write_post_state_page_prot_records) =
        rt.mw_slice(state_ptr, state.as_slice(), false);
    state_write_records.extend_from_slice(&write_records);

    // Push the Keccak permute event.
    let (local_mem_access, local_page_prot_access) = rt.postprocess();

    let event = PrecompileEvent::KeccakPermute(KeccakPermuteEvent {
        clk: start_clk,
        pre_state: saved_state.as_slice().try_into().unwrap(),
        post_state: state.as_slice().try_into().unwrap(),
        state_read_records,
        state_write_records,
        state_addr: state_ptr,
        local_mem_access,
        page_prot_records: KeccakPermutePageProtRecords {
            read_pre_state_page_prot_records,
            write_post_state_page_prot_records,
        },
        local_page_prot_access,
    });
    let syscall_event =
        rt.rt.syscall_event(start_clk, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
    rt.add_precompile_event(syscall_code, syscall_event, event);

    None
}
