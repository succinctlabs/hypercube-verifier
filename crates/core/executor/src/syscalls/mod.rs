//! Syscall definitions & implementations for the [`crate::Executor`].

mod code;
mod commit;
mod context;
mod deferred;
mod halt;
mod hint;
mod mprotect;
mod precompiles;
mod unconstrained;
mod verify;
mod write;

use commit::commit_syscall;
use deferred::commit_deferred_proofs_syscall;
use halt::halt_syscall;
use hint::{hint_len_syscall, hint_read_syscall};
use precompiles::{
    edwards::{add::edwards_add_assign_syscall, decompress::edwards_decompress_syscall},
    fptower::{fp2_addsub_syscall, fp2_mul_syscall, fp_op_syscall},
    keccak256::permute::keccak256_permute_syscall,
    poseidon2::poseidon2_syscall,
    sha256::{compress::sha256_compress_syscall, extend::sha256_extend_syscall},
    u256x2048_mul::u256x2048_mul,
    uint256::uint256_mul,
    uint256_ops::uint256_ops,
    weierstrass::{
        add::weierstrass_add_assign_syscall, decompress::weierstrass_decompress_syscall,
        double::weierstrass_double_assign_syscall,
    },
};

use sp1_curves::{
    edwards::ed25519::Ed25519,
    weierstrass::{
        bls12_381::{Bls12381, Bls12381BaseField},
        bn254::{Bn254, Bn254BaseField},
        secp256k1::Secp256k1,
        secp256r1::Secp256r1,
    },
};
use unconstrained::{enter_unconstrained_syscall, exit_unconstrained_syscall};
use verify::verify_syscall;
use write::write_syscall;

use crate::{syscalls::mprotect::mprotect_syscall, ExecutionError, ExecutorConfig};

pub use code::*;
pub use context::*;

/// A system call in the SP1 RISC-V zkVM.
///
/// This trait implements methods needed to execute a system call inside the [`crate::Executor`].
pub struct Syscall<'a, 'b, E: ExecutorConfig> {
    /// The handler for the syscall.
    pub handler: SyscallHandler<'a, 'b, E>,
}

impl<'a, 'b, E: ExecutorConfig> Syscall<'a, 'b, E> {
    /// Create a new syscall.
    #[inline]
    pub fn new(handler: SyscallHandler<'a, 'b, E>) -> Self {
        Self { handler }
    }
}

/// A type alias for a syscall handler.
pub type SyscallHandler<'a, 'b, E> =
    fn(&mut SyscallContext<'a, 'b, E>, SyscallCode, u64, u64) -> Option<u64>;

/// Maps syscall codes to their implementations.
#[allow(clippy::too_many_lines)]
pub fn get_syscall<'a, 'b, E: ExecutorConfig>(
    code: SyscallCode,
) -> Result<Syscall<'a, 'b, E>, ExecutionError> {
    match code {
        // Control flow
        SyscallCode::HALT => Ok(Syscall::new(halt_syscall)),
        SyscallCode::WRITE => Ok(Syscall::new(write_syscall)),
        SyscallCode::COMMIT => Ok(Syscall::new(commit_syscall)),
        SyscallCode::COMMIT_DEFERRED_PROOFS => Ok(Syscall::new(commit_deferred_proofs_syscall)),
        SyscallCode::VERIFY_SP1_PROOF => Ok(Syscall::new(verify_syscall)),
        SyscallCode::HINT_LEN => Ok(Syscall::new(hint_len_syscall)),
        SyscallCode::HINT_READ => Ok(Syscall::new(hint_read_syscall)),
        SyscallCode::ENTER_UNCONSTRAINED => Ok(Syscall::new(enter_unconstrained_syscall)),
        SyscallCode::EXIT_UNCONSTRAINED => Ok(Syscall::new(exit_unconstrained_syscall)),
        // Weierstrass curve operations
        SyscallCode::SECP256K1_ADD => {
            Ok(Syscall::new(weierstrass_add_assign_syscall::<Secp256k1, E>))
        }
        SyscallCode::SECP256K1_DOUBLE => {
            Ok(Syscall::new(weierstrass_double_assign_syscall::<Secp256k1, E>))
        }
        SyscallCode::SECP256K1_DECOMPRESS => {
            Ok(Syscall::new(weierstrass_decompress_syscall::<Secp256k1, E>))
        }
        SyscallCode::BLS12381_ADD => {
            Ok(Syscall::new(weierstrass_add_assign_syscall::<Bls12381, E>))
        }
        SyscallCode::BLS12381_DOUBLE => {
            Ok(Syscall::new(weierstrass_double_assign_syscall::<Bls12381, E>))
        }
        SyscallCode::BLS12381_DECOMPRESS => {
            Ok(Syscall::new(weierstrass_decompress_syscall::<Bls12381, E>))
        }
        SyscallCode::BN254_ADD => Ok(Syscall::new(weierstrass_add_assign_syscall::<Bn254, E>)),
        SyscallCode::BN254_DOUBLE => {
            Ok(Syscall::new(weierstrass_double_assign_syscall::<Bn254, E>))
        }
        SyscallCode::SECP256R1_ADD => {
            Ok(Syscall::new(weierstrass_add_assign_syscall::<Secp256r1, E>))
        }
        SyscallCode::SECP256R1_DOUBLE => {
            Ok(Syscall::new(weierstrass_double_assign_syscall::<Secp256r1, E>))
        }
        SyscallCode::SECP256R1_DECOMPRESS => {
            Ok(Syscall::new(weierstrass_decompress_syscall::<Secp256r1, E>))
        }
        // Edwards curve operations
        SyscallCode::ED_ADD => Ok(Syscall::new(edwards_add_assign_syscall::<Ed25519, E>)),
        SyscallCode::ED_DECOMPRESS => Ok(Syscall::new(edwards_decompress_syscall::<E>)),
        // Field operations
        SyscallCode::BLS12381_FP2_ADD | SyscallCode::BLS12381_FP2_SUB => {
            Ok(Syscall::new(fp2_addsub_syscall::<Bls12381BaseField, E>))
        }
        SyscallCode::BN254_FP2_ADD | SyscallCode::BN254_FP2_SUB => {
            Ok(Syscall::new(fp2_addsub_syscall::<Bn254BaseField, E>))
        }
        SyscallCode::BLS12381_FP_ADD
        | SyscallCode::BLS12381_FP_SUB
        | SyscallCode::BLS12381_FP_MUL => Ok(Syscall::new(fp_op_syscall::<Bls12381BaseField, E>)),
        SyscallCode::BN254_FP_ADD | SyscallCode::BN254_FP_SUB | SyscallCode::BN254_FP_MUL => {
            Ok(Syscall::new(fp_op_syscall::<Bn254BaseField, E>))
        }
        SyscallCode::BLS12381_FP2_MUL => Ok(Syscall::new(fp2_mul_syscall::<Bls12381BaseField, E>)),
        SyscallCode::BN254_FP2_MUL => Ok(Syscall::new(fp2_mul_syscall::<Bn254BaseField, E>)),
        // Hash functions
        SyscallCode::KECCAK_PERMUTE => Ok(Syscall::new(keccak256_permute_syscall)),
        SyscallCode::SHA_COMPRESS => Ok(Syscall::new(sha256_compress_syscall)),
        SyscallCode::SHA_EXTEND => Ok(Syscall::new(sha256_extend_syscall)),
        // Misc
        SyscallCode::UINT256_MUL => Ok(Syscall::new(uint256_mul)),
        SyscallCode::UINT256_ADD_CARRY | SyscallCode::UINT256_MUL_CARRY => {
            Ok(Syscall::new(uint256_ops))
        }
        SyscallCode::U256XU2048_MUL => Ok(Syscall::new(u256x2048_mul)),
        SyscallCode::MPROTECT => Ok(Syscall::new(mprotect_syscall)),
        SyscallCode::POSEIDON2 => Ok(Syscall::new(poseidon2_syscall)),
    }
}
