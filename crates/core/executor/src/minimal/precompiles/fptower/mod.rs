pub mod fp;
pub mod fp2_addsub;
pub mod fp2_mul;

pub(crate) use fp::fp_op_syscall;
pub(crate) use fp2_addsub::fp2_addsub_syscall;
pub(crate) use fp2_mul::fp2_mul_syscall;
