use sp1_curves::{CurveType, EllipticCurve};

use crate::{
    events::{create_ec_decompress_event, PrecompileEvent},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
};

/// Execute a weierstrass decompress syscall.
pub(crate) fn weierstrass_decompress_syscall<E: EllipticCurve, Ex: ExecutorConfig>(
    ctx: &mut SyscallContext<Ex>,
    syscall_code: SyscallCode,
    slice_ptr: u64,
    sign_bit: u64,
) -> Option<u64> {
    let event = create_ec_decompress_event::<E, Ex>(ctx, slice_ptr, sign_bit);
    let syscall_event = ctx.rt.syscall_event(
        event.clk,
        syscall_code,
        slice_ptr,
        sign_bit,
        false,
        ctx.next_pc,
        ctx.exit_code,
    );
    match E::CURVE_TYPE {
        CurveType::Secp256k1 => ctx.add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Secp256k1Decompress(event),
        ),
        CurveType::Secp256r1 => ctx.add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Secp256r1Decompress(event),
        ),

        CurveType::Bls12381 => ctx.add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Bls12381Decompress(event),
        ),
        _ => panic!("Unsupported curve"),
    }
    None
}
