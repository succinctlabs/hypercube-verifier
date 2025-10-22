use crate::{
    events::{PrecompileEvent, ShaExtendEvent, ShaExtendMemoryRecords},
    syscalls::SyscallCode,
    vm::syscall::SyscallRuntime,
};

pub(crate) fn sha256_extend<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let w_ptr = arg1;
    assert!(arg2 == 0, "arg2 must be 0");
    assert!(arg1.is_multiple_of(8));

    let clk = rt.core_mut().clk();

    rt.increment_clk();
    let mut sha_extend_memory_records = Vec::with_capacity(48);
    for i in 16..64 {
        // Read w[i-15].
        let w_i_minus_15_reads = rt.mr(w_ptr + (i - 15) * 8);

        // Read w[i-2].
        let w_i_minus_2_reads = rt.mr(w_ptr + (i - 2) * 8);

        // Read w[i-16].
        let w_i_minus_16_reads = rt.mr(w_ptr + (i - 16) * 8);

        // Read w[i-7].
        let w_i_minus_7_reads = rt.mr(w_ptr + (i - 7) * 8);
        // Write w[i].
        let w_i_write = rt.mw(w_ptr + i * 8);

        rt.increment_clk();

        sha_extend_memory_records.push(ShaExtendMemoryRecords {
            w_i_minus_15_reads,
            w_i_minus_2_reads,
            w_i_minus_16_reads,
            w_i_minus_7_reads,
            w_i_write,
        });
    }

    if RT::TRACING {
        // Push the SHA extend event.
        #[allow(clippy::default_trait_access)]
        let event = PrecompileEvent::ShaExtend(ShaExtendEvent {
            clk,
            w_ptr,
            local_mem_access: rt.postprocess_precompile(),
            memory_records: sha_extend_memory_records,
            page_prot_records: Default::default(),
            local_page_prot_access: Default::default(),
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
