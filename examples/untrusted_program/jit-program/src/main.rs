// To generate the .bin file, run:
// 1) cargo +succinct build --target riscv64im-succinct-zkvm-elf --release
// 2) riscv64-unknown-elf-objcopy -O binary ../../target/riscv64im-succinct-zkvm-elf/release/dynamic-program-jit-program dynamic-program-jit-program.bin
// 3) Make a nit edit in the program/src/main.rs to ensure it rebuilds

// Includes 88 dynamic instructions, including LUI

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};

static mut MEM: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

#[no_mangle]
pub extern "C" fn _start() -> u64 {
    let mut acc: u64 = 0;
    let mut i: u64 = 0;

    unsafe {
        // Memory load loop
        while i < 8 {
            let val = read_volatile(&MEM[i as usize]);
            acc = acc.wrapping_add(val); // ADD
            acc ^= val << (i % 8); // XOR, SLL
            acc = acc.wrapping_sub(val >> 1); // SUB, SRL
            acc |= i; // OR
            acc &= !i; // AND
            if acc < 1000 {
                acc += 3; // SLT-like branching
            } else {
                acc -= 7;
            }

            write_volatile(&mut MEM[i as usize], acc); // SD
            i += 1;
        }
    }

    acc
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
