use sp1_jit::{RiscRegister, SyscallContext};
use sp1_primitives::consts::fd::{
    FD_BLS12_381_INVERSE, FD_BLS12_381_SQRT, FD_ECRECOVER_HOOK, FD_EDDECOMPRESS, FD_FP_INV,
    FD_FP_SQRT, FD_HINT, FD_PUBLIC_VALUES, FD_RSA_MUL_MOD,
};

pub(crate) unsafe fn write(ctx: &mut impl SyscallContext, arg1: u64, arg2: u64) -> Option<u64> {
    let a2 = RiscRegister::X12;
    // let rt = &mut ctx.rt;
    let fd = arg1;
    let buf_ptr = arg2;

    let nbytes = ctx.rr(a2);
    // Round down to low word start.
    let start = buf_ptr & !7;
    // Get the intra-word offset of the start.
    let head = (buf_ptr & 7) as usize;
    // Include the head bytes so we get the correct number of words.
    let nwords = (head + nbytes as usize).div_ceil(8);

    let slice = ctx.mr_slice_no_trace(start, nwords);
    let bytes = slice
        .into_iter()
        .copied()
        .flat_map(u64::to_le_bytes)
        .skip(head)
        .take(nbytes as usize)
        .collect::<Vec<u8>>();

    let slice = bytes.as_slice();
    if fd == 1 {
        let s = core::str::from_utf8(slice).unwrap();
        for line in s.lines() {
            eprintln!("stdout: {line}");
        }

        return None;
    } else if fd == 2 {
        let s = core::str::from_utf8(slice).unwrap();
        for line in s.lines() {
            eprintln!("stderr: {line}");
        }
        return None;
    } else if fd as u32 == FD_PUBLIC_VALUES {
        ctx.public_values_stream().extend_from_slice(slice);
        return None;
    } else if fd as u32 == FD_HINT {
        ctx.input_buffer().push_front(bytes);
        return None;
    }

    let hook_return = match fd as u32 {
        FD_BLS12_381_INVERSE => Some(crate::hooks::bls::hook_bls12_381_inverse(slice)),
        FD_BLS12_381_SQRT => Some(crate::hooks::bls::hook_bls12_381_sqrt(slice)),
        FD_FP_INV => Some(crate::hooks::fp_ops::hook_fp_inverse(slice)),
        FD_FP_SQRT => Some(crate::hooks::fp_ops::hook_fp_sqrt(slice)),
        FD_ECRECOVER_HOOK => Some(crate::hooks::hook_ecrecover(slice)),
        FD_EDDECOMPRESS => Some(crate::hooks::hook_ed_decompress(slice)),
        FD_RSA_MUL_MOD => Some(crate::hooks::hook_rsa_mul_mod(slice)),
        _ => {
            tracing::warn!("Unsupported file descriptor: {}", fd);
            None
        }
    };

    if let Some(hook_return) = hook_return {
        for item in hook_return.into_iter().rev() {
            ctx.input_buffer().push_front(item);
        }
    }

    None
}
