use num::BigUint;
use sp1_curves::{params::NumWords, weierstrass::FpOpField};
use sp1_jit::SyscallContext;
use sp1_primitives::consts::u64_to_u32;
use typenum::Unsigned;

pub(crate) unsafe fn fp2_mul_syscall<P: FpOpField>(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let x_ptr = arg1;
    if !x_ptr.is_multiple_of(4) {
        panic!("x_ptr must be 4-byte aligned");
    }
    let y_ptr = arg2;
    if !y_ptr.is_multiple_of(4) {
        panic!("y_ptr must be 4-byte aligned");
    }

    let num_words = <P as NumWords>::WordsCurvePoint::USIZE;

    let x_32 = u64_to_u32(ctx.mr_slice_unsafe(x_ptr, num_words));
    let y_32 = u64_to_u32(ctx.mr_slice(y_ptr, num_words));

    let (ac0, ac1) = x_32.split_at(x_32.len() / 2);
    let (bc0, bc1) = y_32.split_at(y_32.len() / 2);

    let ac0 = &BigUint::from_slice(ac0);
    let ac1 = &BigUint::from_slice(ac1);
    let bc0 = &BigUint::from_slice(bc0);
    let bc1 = &BigUint::from_slice(bc1);
    let modulus = &BigUint::from_bytes_le(P::MODULUS);

    #[allow(clippy::match_bool)]
    let c0 = match (ac0 * bc0) % modulus < (ac1 * bc1) % modulus {
        true => ((modulus + (ac0 * bc0) % modulus) - (ac1 * bc1) % modulus) % modulus,
        false => ((ac0 * bc0) % modulus - (ac1 * bc1) % modulus) % modulus,
    };
    let c1 = ((ac0 * bc1) % modulus + (ac1 * bc0) % modulus) % modulus;

    // Each of c0 and c1 should use the same number of words.
    // This is regardless of how many u64 digits are required to express them.
    let mut result = c0.to_u64_digits();
    result.resize(num_words / 2, 0);
    result.append(&mut c1.to_u64_digits());
    result.resize(num_words, 0);

    // Bump the clock before writing to memory.
    ctx.bump_memory_clk();
    ctx.mw_slice(x_ptr, &result);

    None
}
