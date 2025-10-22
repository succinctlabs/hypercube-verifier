use sp1_curves::{params::NumWords, CurveType, EllipticCurve};

use crate::{
    events::{EllipticCurveAddEvent, PrecompileEvent},
    syscalls::SyscallCode,
    vm::syscall::SyscallRuntime,
};
use typenum::Unsigned;

pub(crate) fn weirstrass_add<'a, RT: SyscallRuntime<'a>, E: EllipticCurve>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    if !p_ptr.is_multiple_of(4) {
        panic!();
    }
    let q_ptr = arg2;
    if !q_ptr.is_multiple_of(4) {
        panic!();
    }

    let clk = rt.core().clk();
    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    // Accessed via slice unsafe, so ununsed.
    let p = rt.mr_slice_unsafe(num_words);

    let q_memory_records = rt.mr_slice(q_ptr, num_words);

    rt.increment_clk();

    let write_record = rt.mw_slice(p_ptr, num_words);

    if RT::TRACING {
        let q = q_memory_records.iter().map(|r| r.value).collect::<Vec<_>>();

        let event = EllipticCurveAddEvent {
            clk,
            p_ptr,
            p,
            q_ptr,
            q,
            p_memory_records: write_record,
            q_memory_records,
            local_mem_access: rt.postprocess_precompile(),
            ..Default::default()
        };

        let syscall_event = rt.syscall_event(
            clk,
            syscall_code,
            arg1,
            arg2,
            false,
            rt.core().next_pc(),
            rt.core().exit_code(),
        );

        match E::CURVE_TYPE {
            CurveType::Secp256k1 => rt.add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256k1Add(event),
            ),
            CurveType::Bn254 => {
                rt.add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Bn254Add(event),
                );
            }
            CurveType::Bls12381 => rt.add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Bls12381Add(event),
            ),
            CurveType::Secp256r1 => rt.add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256r1Add(event),
            ),
            _ => panic!("Unsupported curve"),
        }
    }

    None
}
