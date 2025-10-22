use crate::{
    events::{PrecompileEvent, ShaCompressEvent, ShaCompressPageProtAccess},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
};

pub const SHA_COMPRESS_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[allow(clippy::pedantic)]
pub(crate) fn sha256_compress_syscall<E: ExecutorConfig>(
    rt: &mut SyscallContext<E>,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let w_ptr = arg1;
    let h_ptr = arg2;
    assert_ne!(w_ptr, h_ptr);
    assert!(arg1.is_multiple_of(8));
    assert!(arg2.is_multiple_of(8));

    let start_clk = rt.clk;
    let mut h_read_records = Vec::new();
    let mut w_i_read_records = Vec::new();
    let mut h_write_records = Vec::new();

    // Execute the "initialize" phase where we read in the h values.
    let mut hx = [0u32; 8];
    let (records, values, h_read_page_prot_records) = rt.mr_slice(h_ptr, 8);
    h_read_records.extend(records);
    for i in 0..8 {
        hx[i] = values[i] as u32;
    }

    // Need to increment the clk because h and w could be on the same page
    rt.clk += 1;

    let mut original_w = Vec::new();
    // Read all w values at once
    let (w_records, w_values, w_read_page_prot_records) = rt.mr_slice(w_ptr, 64);
    w_i_read_records.extend(w_records);
    for i in 0..64 {
        original_w.push(w_values[i] as u32);
    }

    // Execute the "compress" phase.
    let mut a = hx[0];
    let mut b = hx[1];
    let mut c = hx[2];
    let mut d = hx[3];
    let mut e = hx[4];
    let mut f = hx[5];
    let mut g = hx[6];
    let mut h = hx[7];
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let w_i = original_w[i];
        let temp1 =
            h.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA_COMPRESS_K[i]).wrapping_add(w_i);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    // Execute the "finalize" phase.
    rt.clk += 1;
    let v = [a, b, c, d, e, f, g, h];
    let final_values: Vec<u64> = (0..8).map(|i| hx[i].wrapping_add(v[i]) as u64).collect();
    let (records, h_write_page_prot_records) = rt.mw_slice(h_ptr, &final_values, true);
    h_write_records.extend(records);

    // Push the SHA extend event.
    let (local_mem_access, local_page_prot_access) = rt.postprocess();

    let event = PrecompileEvent::ShaCompress(ShaCompressEvent {
        clk: start_clk,
        w_ptr,
        h_ptr,
        w: original_w,
        h: hx,
        h_read_records: h_read_records.try_into().unwrap(),
        w_i_read_records,
        h_write_records: h_write_records.try_into().unwrap(),
        local_mem_access,
        page_prot_access: ShaCompressPageProtAccess {
            h_read_page_prot_records,
            w_read_page_prot_records,
            h_write_page_prot_records,
        },
        local_page_prot_access,
    });
    let syscall_event =
        rt.rt.syscall_event(start_clk, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
    rt.add_precompile_event(syscall_code, syscall_event, event);

    None
}
