use crate::{
    events::{FieldOperation, FpOpEvent, FpPageProtRecords, PrecompileEvent},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
};
use num::BigUint;
use sp1_curves::{
    params::NumWords,
    weierstrass::{FieldType, FpOpField},
};
use sp1_primitives::consts::u64_to_u32;
use typenum::Unsigned;

pub(crate) fn fp_op_syscall<P: FpOpField, E: ExecutorConfig>(
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

    let op = syscall_code.fp_op_map();

    let num_words = <P as NumWords>::WordsFieldElement::USIZE;

    let x = rt.slice_unsafe(x_ptr, num_words);
    let (y_memory_records, y, read_page_prot_records) = rt.mr_slice(y_ptr, num_words);

    let x_32 = u64_to_u32(&x);
    let y_32 = u64_to_u32(&y);

    let modulus = &BigUint::from_bytes_le(P::MODULUS);
    let a = BigUint::from_slice(&x_32) % modulus;
    let b = BigUint::from_slice(&y_32) % modulus;

    let result = match op {
        FieldOperation::Add => (a + b) % modulus,
        FieldOperation::Sub => ((a + modulus) - b) % modulus,
        FieldOperation::Mul => (a * b) % modulus,
        _ => panic!("Unsupported operation"),
    };
    let mut result = result.to_u64_digits();
    result.resize(num_words, 0);

    rt.clk += 1;
    let (x_memory_records, write_page_prot_records) = rt.mw_slice(x_ptr, &result, true);

    let (local_mem_access, local_page_prot_access) = rt.postprocess();

    let event = FpOpEvent {
        clk,
        x_ptr,
        x,
        y_ptr,
        y,
        op,
        x_memory_records,
        y_memory_records,
        local_mem_access,
        page_prot_records: FpPageProtRecords { read_page_prot_records, write_page_prot_records },
        local_page_prot_access,
    };

    // Since all the Fp events are on the same table, we need to preserve the ordering of the
    // events b/c of the nonce.  In this table's trace_gen, the nonce is simply the row number.
    // Group all of the events for a specific curve into the same syscall code key.
    // TODO:  FIX THIS.

    match P::FIELD_TYPE {
        FieldType::Bn254 => {
            let syscall_code_key = match syscall_code {
                SyscallCode::BN254_FP_ADD
                | SyscallCode::BN254_FP_SUB
                | SyscallCode::BN254_FP_MUL => SyscallCode::BN254_FP_ADD,
                _ => unreachable!(),
            };

            let syscall_event =
                rt.rt.syscall_event(clk, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
            rt.add_precompile_event(
                syscall_code_key,
                syscall_event,
                PrecompileEvent::Bn254Fp(event),
            );
        }
        FieldType::Bls12381 => {
            let syscall_code_key = match syscall_code {
                SyscallCode::BLS12381_FP_ADD
                | SyscallCode::BLS12381_FP_SUB
                | SyscallCode::BLS12381_FP_MUL => SyscallCode::BLS12381_FP_ADD,
                _ => {
                    unreachable!()
                }
            };

            let syscall_event =
                rt.rt.syscall_event(clk, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
            rt.add_precompile_event(
                syscall_code_key,
                syscall_event,
                PrecompileEvent::Bls12381Fp(event),
            );
        }
    }

    None
}
