use sp1_primitives::consts::{PROT_READ, PROT_WRITE};

use crate::{
    events::{PrecompileEvent, ShaExtendEvent, ShaExtendMemoryRecords, ShaExtendPageProtRecords},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
};

pub(crate) fn sha256_extend_syscall<E: ExecutorConfig>(
    rt: &mut SyscallContext<E>,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let clk_init = rt.clk;
    let w_ptr = arg1;
    assert!(arg2 == 0, "arg2 must be 0");
    assert!(arg1.is_multiple_of(8));

    let w_ptr_init = w_ptr;
    let mut event_memory_records = Vec::with_capacity(48);

    // Given the architecture, for extend we check page prot access on initialize instead of per
    // read or write. The first sixteen bytes are read only, and the next 48 bytes are read and
    // written to.
    let page_prot_records_initial = rt.page_prot_range_access(w_ptr, w_ptr + 15 * 8, PROT_READ);
    rt.clk += 1;
    let page_prot_records_extensions =
        rt.page_prot_range_access(w_ptr + 16 * 8, w_ptr + 63 * 8, PROT_READ | PROT_WRITE);

    for i in 16..64 {
        // Read w[i-15].
        let w_ptr_i_minus_15 = w_ptr + (i - 15) * 8;
        let w_i_minus_15_record = rt.rt.mr::<E>(
            w_ptr_i_minus_15,
            rt.external_flag,
            rt.clk,
            rt.local_memory_access.as_mut(),
        );
        let w_i_minus_15 = w_i_minus_15_record.value;

        // Compute `s0`.
        let s0 = (w_i_minus_15 as u32).rotate_right(7)
            ^ (w_i_minus_15 as u32).rotate_right(18)
            ^ ((w_i_minus_15 as u32) >> 3);

        // Read w[i-2].
        let w_ptr_i_minus_2 = w_ptr + (i - 2) * 8;
        let w_i_minus_2_record = rt.rt.mr::<E>(
            w_ptr_i_minus_2,
            rt.external_flag,
            rt.clk,
            rt.local_memory_access.as_mut(),
        );
        let w_i_minus_2 = w_i_minus_2_record.value;

        // Compute `s1`.
        let s1 = (w_i_minus_2 as u32).rotate_right(17)
            ^ (w_i_minus_2 as u32).rotate_right(19)
            ^ ((w_i_minus_2 as u32) >> 10);

        // Read w[i-16].
        let w_ptr_i_minus_16 = w_ptr + (i - 16) * 8;
        let w_i_minus_16_record = rt.rt.mr::<E>(
            w_ptr_i_minus_16,
            rt.external_flag,
            rt.clk,
            rt.local_memory_access.as_mut(),
        );
        let w_i_minus_16 = w_i_minus_16_record.value;

        // Read w[i-7].
        let w_ptr_i_minus_7 = w_ptr + (i - 7) * 8;
        let w_i_minus_7_record = rt.rt.mr::<E>(
            w_ptr_i_minus_7,
            rt.external_flag,
            rt.clk,
            rt.local_memory_access.as_mut(),
        );
        let w_i_minus_7 = w_i_minus_7_record.value;

        // Compute `w_i`.
        let w_i =
            s1.wrapping_add(w_i_minus_16 as u32).wrapping_add(s0).wrapping_add(w_i_minus_7 as u32);

        // Write w[i].
        let w_ptr_i = w_ptr + i * 8;
        let w_i_record = rt.rt.mw::<E>(
            w_ptr_i,
            w_i as u64,
            rt.external_flag,
            rt.clk,
            rt.local_memory_access.as_mut(),
        );

        event_memory_records.push(ShaExtendMemoryRecords {
            w_i_minus_15_reads: w_i_minus_15_record,
            w_i_minus_2_reads: w_i_minus_2_record,
            w_i_minus_16_reads: w_i_minus_16_record,
            w_i_minus_7_reads: w_i_minus_7_record,
            w_i_write: w_i_record,
        });

        rt.clk += 1;
    }

    // Push the SHA extend event.
    let (local_mem_access, local_page_prot_access) = rt.postprocess();

    let event = PrecompileEvent::ShaExtend(ShaExtendEvent {
        clk: clk_init,
        w_ptr: w_ptr_init,
        memory_records: event_memory_records,
        page_prot_records: ShaExtendPageProtRecords {
            initial_page_prot_records: page_prot_records_initial,
            extension_page_prot_records: page_prot_records_extensions,
        },
        local_mem_access,
        local_page_prot_access,
    });
    let syscall_event =
        rt.rt.syscall_event(clk_init, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
    rt.add_precompile_event(syscall_code, syscall_event, event);

    None
}
