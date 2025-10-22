use crate::{
    events::{Poseidon2PrecompileEvent, PrecompileEvent},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
};
use slop_algebra::{AbstractField, PrimeField32};
use slop_symmetric::Permutation;
use sp1_hypercube::inner_perm;
use sp1_primitives::SP1Field;

pub(crate) fn poseidon2_syscall<E: ExecutorConfig>(
    rt: &mut SyscallContext<E>,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let clk_init = rt.clk;
    let ptr = arg1;
    assert!(arg2 == 0, "arg2 must be 0");
    assert!(arg1.is_multiple_of(8));

    let mut input = rt.slice_unsafe(ptr, 8);
    let perm = inner_perm();

    let input_arr: &[u32; 16] = unsafe { &*(input.as_mut_ptr().cast::<[u32; 16]>()) };

    let output_hash =
        perm.permute(input_arr.map(SP1Field::from_canonical_u32)).map(|x| x.as_canonical_u32());

    let u64_result: Vec<u64> = output_hash
        .chunks_exact(2)
        .map(|pair| (u64::from(pair[1]) << 32) | u64::from(pair[0]))
        .collect();

    assert!(u64_result.len() == 8);

    let (output_memory_records, page_prot_records) = rt.mw_slice(ptr, &u64_result, true);

    // Push the Poseidon2 event.
    let (local_mem_access, page_prot_local_events) = rt.postprocess();
    let event = PrecompileEvent::POSEIDON2(Poseidon2PrecompileEvent {
        clk: clk_init,
        ptr,
        memory_records: output_memory_records,
        local_mem_access,
        page_prot_records,
        local_page_prot_access: page_prot_local_events,
    });
    let syscall_event =
        rt.rt.syscall_event(clk_init, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
    rt.add_precompile_event(syscall_code, syscall_event, event);

    None
}
