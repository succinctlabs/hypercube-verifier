use sp1_curves::{edwards::EdwardsParameters, EllipticCurve};

use crate::{
    events::{create_ec_add_event, PrecompileEvent},
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
};

pub(crate) fn edwards_add_assign_syscall<
    E: EllipticCurve + EdwardsParameters,
    Ex: ExecutorConfig,
>(
    rt: &mut SyscallContext<Ex>,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let event = create_ec_add_event::<E, Ex>(rt, arg1, arg2);
    let syscall_event =
        rt.rt.syscall_event(event.clk, syscall_code, arg1, arg2, false, rt.next_pc, rt.exit_code);
    rt.add_precompile_event(syscall_code, syscall_event, PrecompileEvent::EdAdd(event));
    None
}
