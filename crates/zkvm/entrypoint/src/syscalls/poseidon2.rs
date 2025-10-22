#[cfg(target_os = "zkvm")]
use core::arch::asm;

#[repr(align(8))]
pub struct Poseidon2State(pub [u32; 16]);

/// Poseidon2 hash function syscall for the SP1 RISC-V zkVM.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_poseidon2(inout: &Poseidon2State) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::POSEIDON2,
            in("a0") inout.0.as_ptr(),
            in("a1") 0,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
