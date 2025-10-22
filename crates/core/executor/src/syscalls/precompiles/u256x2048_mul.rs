use num::{BigUint, Integer, One};

use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le_vec};

use crate::{
    events::{PrecompileEvent, U256xU2048MulEvent, U256xU2048MulPageProtRecords},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
    Register::{X12, X13},
};

const U256_NUM_WORDS: usize = 4;
const U2048_NUM_WORDS: usize = 32;
const U256_NUM_BYTES: usize = U256_NUM_WORDS * 8;
const U2048_NUM_BYTES: usize = U2048_NUM_WORDS * 8;

pub(crate) fn u256x2048_mul<E: ExecutorConfig>(
    rt: &mut SyscallContext<E>,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let clk = rt.clk;

    let a_ptr = arg1;
    let b_ptr = arg2;

    let (lo_ptr_memory, lo_ptr) = rt.rr_traced(X12);
    let (hi_ptr_memory, hi_ptr) = rt.rr_traced(X13);

    let (a_memory_records, a, read_a_page_prot_records) = rt.mr_slice(a_ptr, U256_NUM_WORDS);
    rt.clk += 1;
    let (b_memory_records, b, read_b_page_prot_records) = rt.mr_slice(b_ptr, U2048_NUM_WORDS);

    let uint256_a = BigUint::from_bytes_le(&words_to_bytes_le_vec(&a));
    let uint2048_b = BigUint::from_bytes_le(&words_to_bytes_le_vec(&b));

    let result = uint256_a * uint2048_b;

    let two_to_2048 = BigUint::one() << 2048;

    let (hi, lo) = result.div_rem(&two_to_2048);

    let mut lo_bytes = lo.to_bytes_le();
    lo_bytes.resize(U2048_NUM_BYTES, 0u8);
    let lo_words = bytes_to_words_le::<U2048_NUM_WORDS>(&lo_bytes);

    let mut hi_bytes = hi.to_bytes_le();
    hi_bytes.resize(U256_NUM_BYTES, 0u8);
    let hi_words = bytes_to_words_le::<U256_NUM_WORDS>(&hi_bytes);

    // Increment clk so that the write is not at the same cycle as the read.
    rt.clk += 1;

    let (lo_memory_records, write_lo_page_prot_records) = rt.mw_slice(lo_ptr, &lo_words, false);
    rt.clk += 1;
    let (hi_memory_records, write_hi_page_prot_records) = rt.mw_slice(hi_ptr, &hi_words, false);

    let (local_mem_access, page_prot_local_events) = rt.postprocess();

    let page_prot_records = U256xU2048MulPageProtRecords {
        read_a_page_prot_records,
        read_b_page_prot_records,
        write_lo_page_prot_records,
        write_hi_page_prot_records,
    };

    let event = PrecompileEvent::U256xU2048Mul(U256xU2048MulEvent {
        clk,
        a_ptr,
        a,
        b_ptr,
        b,
        lo_ptr,
        lo: lo_words.to_vec(),
        hi_ptr,
        hi: hi_words.to_vec(),
        lo_ptr_memory,
        hi_ptr_memory,
        a_memory_records,
        b_memory_records,
        lo_memory_records,
        hi_memory_records,
        local_mem_access,
        page_prot_records,
        local_page_prot_access: page_prot_local_events,
    });

    let sycall_event =
        rt.rt.syscall_event(clk, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
    rt.add_precompile_event(syscall_code, sycall_event, event);

    None
}
