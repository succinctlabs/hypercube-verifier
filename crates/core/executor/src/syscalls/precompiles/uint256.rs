use num::{BigUint, One, Zero};

use sp1_curves::edwards::WORDS_FIELD_ELEMENT;
use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le_vec};

use crate::{
    events::{PrecompileEvent, Uint256MulEvent, Uint256MulPageProtRecords},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
};

pub(crate) fn uint256_mul<E: ExecutorConfig>(
    rt: &mut SyscallContext<E>,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let clk = rt.clk;

    let x_ptr = arg1;
    assert!(x_ptr.is_multiple_of(8), "x_ptr must be 8-byte aligned");
    let y_ptr = arg2;
    assert!(y_ptr.is_multiple_of(8), "y_ptr must be 8-byte aligned");

    // First read the words for the x value. We can read a slice_unsafe here because we write
    // the computed result to x later.
    let x = rt.slice_unsafe(x_ptr, WORDS_FIELD_ELEMENT);

    // Read both y and modulus values in a single contiguous read (y is followed by modulus).
    let (combined_memory_records, combined_values, read_y_modulus_page_prot_records) =
        rt.mr_slice(y_ptr, WORDS_FIELD_ELEMENT * 2);

    // Split the combined results into y and modulus components.
    let (y, modulus) = combined_values.split_at(WORDS_FIELD_ELEMENT);
    let y = y.to_vec();
    let modulus = modulus.to_vec();

    // Split the memory records - first half for y, second half for modulus.
    let (y_memory_records, modulus_memory_records) =
        combined_memory_records.split_at(WORDS_FIELD_ELEMENT);
    let y_memory_records = y_memory_records.to_vec();
    let modulus_memory_records = modulus_memory_records.to_vec();

    // Get the BigUint values for x, y, and the modulus.
    let uint256_x = BigUint::from_bytes_le(&words_to_bytes_le_vec(&x));
    let uint256_y = BigUint::from_bytes_le(&words_to_bytes_le_vec(&y));
    let uint256_modulus = BigUint::from_bytes_le(&words_to_bytes_le_vec(&modulus));

    // Perform the multiplication and take the result modulo the modulus.
    let result: BigUint = if uint256_modulus.is_zero() {
        let modulus = BigUint::one() << 256;
        (uint256_x * uint256_y) % modulus
    } else {
        (uint256_x * uint256_y) % uint256_modulus
    };

    let mut result_bytes = result.to_bytes_le();
    result_bytes.resize(32, 0u8); // Pad the result to 32 bytes.

    // Convert the result to little endian u64 words.
    let result = bytes_to_words_le::<4>(&result_bytes);

    // Increment clk so that the write is not at the same cycle as the read.
    rt.clk += 1;
    // Write the result to x and keep track of the memory records.
    let (x_memory_records, write_x_page_prot_records) = rt.mw_slice(x_ptr, &result, true);

    let (local_mem_access, local_page_prot_access) = rt.postprocess();

    let page_prot_records =
        Uint256MulPageProtRecords { write_x_page_prot_records, read_y_modulus_page_prot_records };

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
        local_mem_access,
        page_prot_records,
        local_page_prot_access,
    });
    let syscall_event =
        rt.rt.syscall_event(clk, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
    rt.add_precompile_event(syscall_code, syscall_event, event);

    None
}
