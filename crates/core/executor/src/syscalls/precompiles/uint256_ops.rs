use num::BigUint;

use crate::{
    events::{PrecompileEvent, Uint256Operation, Uint256OpsEvent, Uint256OpsPageProtRecords},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
    Register::{X12, X13, X14},
};

const U256_NUM_WORDS: usize = 4;

/// Executes uint256 operations: d, e <- ((a op b) + c) % (2^256), ((a op b) + c) // (2^256)
/// where op is either ADD or MUL.
///
/// Register layout:
/// - arg1 (a0): address of a (uint256)
/// - arg2 (a1): address of b (uint256)
/// - X12: address of c (uint256)
/// - X13: address of d (uint256, output low)
/// - X14: address of e (uint256, output high)
pub(crate) fn uint256_ops<E: ExecutorConfig>(
    rt: &mut SyscallContext<E>,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let clk = rt.clk;

    // Get the operation from the syscall code
    let op = syscall_code.uint256_op_map();

    // Read addresses - arg1 and arg2 come from the syscall, others from registers
    let a_ptr = arg1;
    let b_ptr = arg2;
    let (c_ptr_memory, c_ptr) = rt.rr_traced(X12);
    let (d_ptr_memory, d_ptr) = rt.rr_traced(X13);
    let (e_ptr_memory, e_ptr) = rt.rr_traced(X14);

    // Read input values (8 words = 32 bytes each for uint256)
    let (a_memory_records, a, read_a_page_prot_records) = rt.mr_slice(a_ptr, U256_NUM_WORDS);
    rt.clk += 1;
    let (b_memory_records, b, read_b_page_prot_records) = rt.mr_slice(b_ptr, U256_NUM_WORDS);
    rt.clk += 1;
    let (c_memory_records, c, read_c_page_prot_records) = rt.mr_slice(c_ptr, U256_NUM_WORDS);

    // Convert to BigUint
    let uint256_a = BigUint::from_slice(
        &a.iter().flat_map(|&x| [x as u32, (x >> 32) as u32]).collect::<Vec<_>>(),
    );
    let uint256_b = BigUint::from_slice(
        &b.iter().flat_map(|&x| [x as u32, (x >> 32) as u32]).collect::<Vec<_>>(),
    );
    let uint256_c = BigUint::from_slice(
        &c.iter().flat_map(|&x| [x as u32, (x >> 32) as u32]).collect::<Vec<_>>(),
    );

    // Perform the operation: (a op b) + c
    let intermediate_result = match op {
        Uint256Operation::Add => uint256_a + uint256_b + uint256_c,
        Uint256Operation::Mul => uint256_a * uint256_b + uint256_c,
    };

    let mut u64_result = intermediate_result.to_u64_digits();
    u64_result.resize(8, 0);

    // Write results
    rt.clk += 1;
    let (d_memory_records, write_d_page_prot_records) =
        rt.mw_slice(d_ptr, &u64_result[0..4], false);
    rt.clk += 1;
    let (e_memory_records, write_e_page_prot_records) =
        rt.mw_slice(e_ptr, &u64_result[4..8], false);

    let (local_mem_access, local_page_prot_access) = rt.postprocess();

    let event = PrecompileEvent::Uint256Ops(Uint256OpsEvent {
        clk,
        op,
        a_ptr,
        a: a.try_into().unwrap(),
        b_ptr,
        b: b.try_into().unwrap(),
        c_ptr,
        c: c.try_into().unwrap(),
        d_ptr,
        d: u64_result[0..4].try_into().unwrap(),
        e_ptr,
        e: u64_result[4..8].try_into().unwrap(),
        c_ptr_memory,
        d_ptr_memory,
        e_ptr_memory,
        a_memory_records,
        b_memory_records,
        c_memory_records,
        d_memory_records,
        e_memory_records,
        local_mem_access,
        page_prot_records: Uint256OpsPageProtRecords {
            read_a_page_prot_records,
            read_b_page_prot_records,
            read_c_page_prot_records,
            write_d_page_prot_records,
            write_e_page_prot_records,
        },
        local_page_prot_access,
    });

    let syscall_event =
        rt.rt.syscall_event(clk, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
    rt.add_precompile_event(syscall_code, syscall_event, event);

    None
}
