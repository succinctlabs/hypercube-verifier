use crate::events::{EllipticCurveDoubleEvent, PrecompileEvent};
use sp1_curves::{params::NumWords, CurveType, EllipticCurve};

use crate::{syscalls::SyscallCode, vm::syscall::SyscallRuntime};
use typenum::Unsigned;

pub(crate) fn weirstrass_double<'a, RT: SyscallRuntime<'a>, E: EllipticCurve>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let p_ptr: u64 = arg1;
    assert!(p_ptr.is_multiple_of(8), "p_ptr must be 8-byte aligned");

    let clk = rt.core().clk();

    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    let p = rt.mr_slice_unsafe(num_words);

    let p_memory_records = rt.mw_slice(p_ptr, num_words);

    if RT::TRACING {
        let event = EllipticCurveDoubleEvent {
            clk,
            p_ptr,
            p,
            p_memory_records,
            local_mem_access: rt.postprocess_precompile(),
            ..Default::default()
        };

        let syscall_event = rt.syscall_event(
            rt.core().clk(),
            syscall_code,
            arg1,
            arg2,
            false,
            rt.core().next_pc(),
            rt.core().exit_code(),
        );

        match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                rt.add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Secp256k1Double(event),
                );
            }
            CurveType::Secp256r1 => rt.add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256r1Double(event),
            ),
            CurveType::Bn254 => {
                rt.add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Bn254Double(event),
                );
            }
            CurveType::Bls12381 => {
                rt.add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Bls12381Double(event),
                );
            }
            _ => panic!("Unsupported curve"),
        }
    }

    None
}
