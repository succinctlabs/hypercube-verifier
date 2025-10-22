use crate::{
    events::{KeccakPermuteEvent, PrecompileEvent},
    syscalls::SyscallCode,
    vm::syscall::SyscallRuntime,
};

pub(crate) const STATE_SIZE: usize = 25;
pub const STATE_NUM_WORDS: usize = STATE_SIZE;

pub fn keccak256_permute<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let state_ptr = arg1;
    if arg2 != 0 {
        panic!("Expected arg2 to be 0, got {arg2}");
    }

    let start_clk = rt.core().clk();

    // Read the current state (will be overwritten)
    let state_read_records = rt.mr_slice(state_ptr, STATE_NUM_WORDS);

    rt.increment_clk();

    // Write the new state (we don't compute the actual result in tracing mode)
    let state_write_records = rt.mw_slice(state_ptr, STATE_NUM_WORDS);

    if RT::TRACING {
        let post_state: Vec<u64> = state_write_records.iter().map(|record| record.value).collect();
        let pre_state: Vec<u64> = state_read_records.iter().map(|record| record.value).collect();

        let event = KeccakPermuteEvent {
            clk: start_clk,
            pre_state: pre_state.as_slice().try_into().unwrap(),
            post_state: post_state.as_slice().try_into().unwrap(),
            state_read_records,
            state_write_records,
            state_addr: state_ptr,
            local_mem_access: rt.postprocess_precompile(),
            ..Default::default()
        };

        let syscall_event = rt.syscall_event(
            start_clk,
            syscall_code,
            arg1,
            arg2,
            false,
            rt.core().next_pc(),
            rt.core().exit_code(),
        );
        rt.add_precompile_event(syscall_code, syscall_event, PrecompileEvent::KeccakPermute(event));
    }

    None
}
