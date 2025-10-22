#![no_main]
sp1_zkvm::entrypoint!(main);

use crypto_bigint::{Encoding, Limb, Uint};

pub fn main() {
    let times = sp1_lib::io::read::<u8>();

    for _ in 0..times {
        let a: [u64; 4] = sp1_lib::io::read::<[u64; 4]>();
        let b: [u64; 4] = sp1_lib::io::read::<[u64; 4]>();
        let a = Uint::<4>::from_words(a);
        let b = Uint::<4>::from_words(b);

        let c: u64 = 356u64;
        let c = Limb(c);
        let result = a.mul_mod_special(&b, c);

        sp1_lib::io::commit(&result.to_be_bytes().to_vec());
    }
}
