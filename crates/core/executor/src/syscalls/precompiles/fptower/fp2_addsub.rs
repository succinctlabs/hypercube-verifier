use num::BigUint;
use sp1_curves::{
    params::NumWords,
    weierstrass::{FieldType, FpOpField},
};
use typenum::Unsigned;

use crate::{
    events::{FieldOperation, Fp2AddSubEvent, FpPageProtRecords, PrecompileEvent},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
};

use sp1_primitives::consts::u64_to_u32;

pub(crate) fn fp2_addsub_syscall<P: FpOpField, E: ExecutorConfig>(
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

    let num_words = <P as NumWords>::WordsCurvePoint::USIZE;
    let op = syscall_code.fp_op_map();

    let x = rt.slice_unsafe(x_ptr, num_words);
    let (y_memory_records, y, read_page_prot_records) = rt.mr_slice(y_ptr, num_words);
    rt.clk += 1;

    let x_32 = u64_to_u32(&x);
    let y_32 = u64_to_u32(&y);
    let (ac0, ac1) = x_32.split_at(x_32.len() / 2);
    let (bc0, bc1) = y_32.split_at(y_32.len() / 2);

    let ac0 = &BigUint::from_slice(ac0);
    let ac1 = &BigUint::from_slice(ac1);
    let bc0 = &BigUint::from_slice(bc0);
    let bc1 = &BigUint::from_slice(bc1);
    let modulus = &BigUint::from_bytes_le(P::MODULUS);

    let (c0, c1) = match op {
        FieldOperation::Add => ((ac0 + bc0) % modulus, (ac1 + bc1) % modulus),
        FieldOperation::Sub => ((ac0 + modulus - bc0) % modulus, (ac1 + modulus - bc1) % modulus),
        _ => panic!("Invalid operation"),
    };

    // Each of c0 and c1 should use the same number of words.
    // This is regardless of how many u32 digits are required to express them.
    let mut result = c0.to_u64_digits();
    result.resize(num_words / 2, 0);
    result.append(&mut c1.to_u64_digits());
    result.resize(num_words, 0);
    let (x_memory_records, write_page_prot_records) = rt.mw_slice(x_ptr, &result, true);

    let op = syscall_code.fp_op_map();

    let (local_mem_access, local_page_prot_access) = rt.postprocess();

    let event = Fp2AddSubEvent {
        clk,
        op,
        x_ptr,
        x,
        y_ptr,
        y,
        x_memory_records,
        y_memory_records,
        local_mem_access,
        page_prot_records: FpPageProtRecords { read_page_prot_records, write_page_prot_records },
        local_page_prot_access,
    };
    match P::FIELD_TYPE {
        // All the fp2 add and sub events for a given curve are coalesced to the curve's fp2 add
        // operation.  Only check for that operation.
        // TODO:  Fix this.
        FieldType::Bn254 => {
            let syscall_code_key = match syscall_code {
                SyscallCode::BN254_FP2_ADD | SyscallCode::BN254_FP2_SUB => {
                    SyscallCode::BN254_FP2_ADD
                }
                _ => unreachable!(),
            };

            let syscall_event =
                rt.rt.syscall_event(clk, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
            rt.add_precompile_event(
                syscall_code_key,
                syscall_event,
                PrecompileEvent::Bn254Fp2AddSub(event),
            );
        }
        FieldType::Bls12381 => {
            let syscall_code_key = match syscall_code {
                SyscallCode::BLS12381_FP2_ADD | SyscallCode::BLS12381_FP2_SUB => {
                    SyscallCode::BLS12381_FP2_ADD
                }
                _ => unreachable!(),
            };

            let syscall_event =
                rt.rt.syscall_event(clk, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
            rt.add_precompile_event(
                syscall_code_key,
                syscall_event,
                PrecompileEvent::Bls12381Fp2AddSub(event),
            );
        }
    }
    None
}
