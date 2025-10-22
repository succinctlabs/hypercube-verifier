use sp1_curves::{edwards::EdwardsParameters, EllipticCurve};
use sp1_jit::SyscallContext;

pub unsafe fn edwards_add<E: EdwardsParameters + EllipticCurve>(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    crate::minimal::precompiles::ec::ec_add::<E>(ctx, arg1, arg2);

    None
}
