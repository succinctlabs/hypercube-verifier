// To generate the .bin file, run:
// 1) cargo +succinct build --target riscv64im-succinct-zkvm-elf --release
// 2) riscv64-unknown-elf-objcopy -O binary ../../target/riscv64im-succinct-zkvm-elf/release/dynamic-program-jit-program dynamic-program-jit-program.bin
// 3) Make a nit edit in the program/src/main.rs to ensure it rebuilds

// This dynamic program invokes the following instructions:
// event: "addi", "sll", "addi", "sd", "ld", "addi", "jalr"

#![no_std]
#![no_main]

use core::ptr;

#[no_mangle]
pub extern "C" fn _start() -> u64 {
    let mut a: u64 = 1;
    let mut b: u64 = 2;
    let mut c: u64 = 0;
    let base: u64 = 0x8000_0000;

    unsafe {
        // Use store (SD) and load (LD)
        let mem = base as *mut u64;
        ptr::write_volatile(mem, 42);
        c = ptr::read_volatile(mem);
    }

    // Arithmetic ops
    c = a + b; // ADD
    c = c.wrapping_sub(1); // SUB
    c = c.wrapping_mul(3); // MUL
    c = c.wrapping_div(2); // DIV
    c = c.wrapping_rem(5); // REM

    // Logic ops
    c = c & 0b1111; // AND
    c = c | 0b0101; // OR
    c = c ^ 0b0011; // XOR

    // Shift ops
    c = c << 1; // SLL
    c = c >> 1; // SRL
    c = ((c as i64) >> 1) as u64; // SRA

    // Control flow (BEQ, BNE, BLT, etc.)
    if a == b {
        c += 1;
    } else if a < b {
        c += 2;
    } else {
        c += 3;
    }

    // Loop (uses BNE, ADDI)
    for i in 0..5 {
        c += i;
    }

    // Function call (JAL)
    c += square(3);

    c
}

fn square(x: u64) -> u64 {
    x * x
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
