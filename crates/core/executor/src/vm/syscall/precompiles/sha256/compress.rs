use crate::{
    events::{PrecompileEvent, ShaCompressEvent},
    syscalls::SyscallCode,
    vm::syscall::SyscallRuntime,
};

pub(crate) fn sha256_compress<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let w_ptr = arg1;
    let h_ptr = arg2;
    assert_ne!(w_ptr, h_ptr);

    let clk = rt.core().clk();

    // Execute the "initialize" phase where we read in the h values.
    let mut hx = [0u32; 8];
    let mut h_read_records = Vec::new();
    for i in 0..8 {
        let record = rt.mr(h_ptr + i as u64 * 8);
        h_read_records.push(record);
        hx[i] = record.value as u32;
    }

    rt.increment_clk();
    let mut original_w = Vec::new();
    let mut w_i_read_records = Vec::new();
    for i in 0..64 {
        let w_i_record = rt.mr(w_ptr + i as u64 * 8);
        w_i_read_records.push(w_i_record);
        let w_i = w_i_record.value as u32;
        original_w.push(w_i);
    }

    rt.increment_clk();
    let mut h_write_records = Vec::new();
    for i in 0..8 {
        let record = rt.mw(h_ptr + i as u64 * 8);
        h_write_records.push(record);
    }

    if RT::TRACING {
        // Push the SHA extend event.
        let event = PrecompileEvent::ShaCompress(ShaCompressEvent {
            clk,
            w_ptr,
            h_ptr,
            w: original_w,
            h: hx,
            h_read_records: h_read_records.try_into().unwrap(),
            w_i_read_records,
            h_write_records: h_write_records.try_into().unwrap(),
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
