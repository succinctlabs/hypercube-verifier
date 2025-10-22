use sp1_curves::{CurveType, EllipticCurve};

use crate::{
    events::{create_ec_add_event, PrecompileEvent},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
};

/// Execute a weierstrass add assign syscall.
pub(crate) fn weierstrass_add_assign_syscall<E: EllipticCurve, Ex: ExecutorConfig>(
    ctx: &mut SyscallContext<Ex>,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let event = create_ec_add_event::<E, Ex>(ctx, arg1, arg2);
    let syscall_event = ctx.rt.syscall_event(
        event.clk,
        syscall_code,
        arg1,
        arg2,
        false,
        ctx.next_pc,
        ctx.exit_code,
    );
    match E::CURVE_TYPE {
        CurveType::Secp256k1 => ctx.add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Secp256k1Add(event),
        ),
        CurveType::Bn254 => {
            ctx.add_precompile_event(syscall_code, syscall_event, PrecompileEvent::Bn254Add(event));
        }
        CurveType::Bls12381 => ctx.add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Bls12381Add(event),
        ),
        CurveType::Secp256r1 => ctx.add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Secp256r1Add(event),
        ),
        _ => panic!("Unsupported curve"),
    }
    None
}
