use slop_algebra::{
    extension::BinomialExtensionField, AbstractExtensionField, AbstractField, Field, PrimeField32,
};
use sp1_primitives::SP1Field;

#[no_mangle]
pub extern "C" fn koalabearextinv(a: u32, b: u32, c: u32, d: u32, i: u32) -> u32 {
    let a = SP1Field::from_wrapped_u32(a);
    let b = SP1Field::from_wrapped_u32(b);
    let c = SP1Field::from_wrapped_u32(c);
    let d = SP1Field::from_wrapped_u32(d);
    let inv = BinomialExtensionField::<SP1Field, 4>::from_base_slice(&[a, b, c, d]).inverse();
    let inv: &[SP1Field] = inv.as_base_slice();
    inv[i as usize].as_canonical_u32()
}

#[no_mangle]
pub extern "C" fn koalabearinv(a: u32) -> u32 {
    let a = SP1Field::from_wrapped_u32(a);
    a.inverse().as_canonical_u32()
}

#[cfg(test)]
pub mod test {
    use super::koalabearextinv;

    #[test]
    fn test_koalabearextinv() {
        koalabearextinv(1, 2, 3, 4, 0);
    }
}
