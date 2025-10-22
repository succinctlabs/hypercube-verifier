use sp1_curves::edwards::WORDS_FIELD_ELEMENT;
use sp1_primitives::consts::WORD_BYTE_SIZE;

use crate::{
    events::{PrecompileEvent, Uint256MulEvent},
    syscalls::SyscallCode,
    vm::syscall::SyscallRuntime,
};

pub(crate) fn uint256_mul<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let x_ptr = arg1;
    if !x_ptr.is_multiple_of(4) {
        panic!();
    }
    let y_ptr = arg2;
    if !y_ptr.is_multiple_of(4) {
        panic!();
    }

    let clk = rt.core().clk();

    // First read the words for the x value. We can read a slice_unsafe here because we write
    // the computed result to x later.
    let x = rt.mr_slice_unsafe(WORDS_FIELD_ELEMENT);

    // Read the y value.
    let y_memory_records = rt.mr_slice(y_ptr, WORDS_FIELD_ELEMENT);
    let y = y_memory_records.iter().map(|record| record.value).collect();

    // The modulus is stored after the y value. We increment the pointer by the number of words.
    let modulus_ptr = y_ptr + WORDS_FIELD_ELEMENT as u64 * WORD_BYTE_SIZE as u64;
    let modulus_memory_records = rt.mr_slice(modulus_ptr, WORDS_FIELD_ELEMENT);
    let modulus = modulus_memory_records.iter().map(|record| record.value).collect();

    rt.increment_clk();

    // Write the result to x and keep track of the memory records.
    let x_memory_records = rt.mw_slice(x_ptr, 4);

    if RT::TRACING {
        let event = PrecompileEvent::Uint256Mul(Uint256MulEvent {
            clk,
            x_ptr,
            x,
            y_ptr,
            y,
            modulus,
            x_memory_records,
            y_memory_records,
            modulus_memory_records,
            local_mem_access: rt.postprocess_precompile(),
            ..Default::default()
        });
        let syscall_event = rt.syscall_event(
            clk,
            syscall_code,
            arg1,
            arg2,
            false,
            rt.core().next_pc(),
            rt.core().exit_code(),
        );
        rt.add_precompile_event(syscall_code, syscall_event, event);
    }

    None
}
