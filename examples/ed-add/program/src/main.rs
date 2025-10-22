#![no_main]

use hex_literal::hex;
use sp1_zkvm::syscalls::{syscall_ed_add, syscall_ed_decompress};
sp1_zkvm::entrypoint!(main);

#[inline]
fn as_bytes_le(xs: &mut [u64; 8]) -> &mut [u8; 64] {
    #[cfg(not(target_endian = "little"))]
    compile_error!("expected target to be little endian");
    // SAFETY: Arrays are always laid out in the obvious way. Any possible element value is
    // always valid. The pointee types have the same size, and the target of each transmute has
    // finer alignment than the source.
    // Although not a safety invariant, note that the guest target is always little-endian,
    // which was just sanity-checked, so this will always have the expected behavior.
    unsafe { core::mem::transmute::<&mut [u64; 8], &mut [u8; 64]>(xs) }
}

pub fn main() {
    for _ in 0..1 {
        // 90393249858788985237231628593243673548167146579814268721945474994541877372611
        // 33321104029277118100578831462130550309254424135206412570121538923759338004303
        let mut a: [u8; 64] = [
            195, 166, 157, 207, 218, 220, 175, 197, 111, 177, 123, 23, 73, 72, 114, 103, 28, 246,
            66, 207, 66, 146, 187, 234, 136, 238, 133, 145, 47, 196, 216, 199, 79, 31, 224, 30,
            179, 122, 51, 84, 116, 12, 4, 189, 198, 198, 190, 22, 71, 201, 143, 249, 92, 56, 147,
            133, 92, 187, 130, 33, 152, 19, 171, 73,
        ];

        // 61717728572175158701898635111983295176935961585742968051419350619945173564869
        // 28137966556353620208933066709998005335145594788896528644015312259959272398451
        let b: [u8; 64] = [
            197, 189, 200, 77, 201, 212, 57, 105, 191, 133, 123, 170, 167, 50, 114, 38, 37, 102,
            188, 29, 215, 227, 157, 142, 252, 31, 129, 67, 24, 255, 114, 136, 115, 94, 94, 55, 43,
            200, 117, 224, 139, 251, 238, 45, 80, 154, 70, 213, 219, 78, 201, 108, 73, 203, 72, 45,
            167, 131, 199, 47, 82, 134, 53, 62,
        ];

        syscall_ed_add(a.as_mut_ptr() as *mut [u64; 8], b.as_ptr() as *mut [u64; 8]);

        // 36213413123116753589144482590359479011148956763279542162278577842046663495729
        // 17093345531692682197799066694073110060588941459686871373458223451938707761683
        let c: [u8; 64] = [
            49, 144, 129, 197, 86, 163, 62, 48, 222, 208, 213, 200, 219, 90, 163, 54, 211, 248,
            178, 224, 238, 167, 235, 219, 251, 247, 189, 239, 194, 16, 16, 80, 19, 106, 20, 198,
            72, 56, 103, 111, 68, 201, 29, 107, 75, 208, 193, 232, 181, 186, 175, 22, 213, 187,
            253, 125, 44, 80, 222, 209, 159, 125, 202, 37,
        ];

        assert_eq!(a, c);

        let pub_bytes = hex!("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
        let mut decompressed = [0_u64; 8];
        as_bytes_le(&mut decompressed)[32..].copy_from_slice(&pub_bytes);

        println!("before: {:?}", decompressed);

        syscall_ed_decompress(&mut decompressed);

        let expected: [u8; 64] = [
            47, 252, 114, 91, 153, 234, 110, 201, 201, 153, 152, 14, 68, 231, 90, 221, 137, 110,
            250, 67, 10, 64, 37, 70, 163, 101, 111, 223, 185, 1, 180, 88, 236, 23, 43, 147, 173,
            94, 86, 59, 244, 147, 44, 112, 225, 36, 80, 52, 195, 84, 103, 239, 46, 253, 77, 100,
            235, 248, 25, 104, 52, 103, 226, 63,
        ];
        println!("after: {:?}", decompressed);
        assert_eq!(as_bytes_le(&mut decompressed), &expected);
    }

    println!("done");
}
