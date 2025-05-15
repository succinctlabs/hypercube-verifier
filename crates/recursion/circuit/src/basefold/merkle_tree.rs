use crate::{CircuitConfig, FieldHasherVariable};
use hypercube_recursion_compiler::ir::Builder;

pub fn verify<C: CircuitConfig, HV: FieldHasherVariable<C>>(
    builder: &mut Builder<C>,
    path: Vec<HV::DigestVariable>,
    index: Vec<C::Bit>,
    value: HV::DigestVariable,
    commitment: HV::DigestVariable,
) {
    let mut value = value;
    for (sibling, bit) in path.iter().zip(index.iter()) {
        let sibling = *sibling;
        // If the index is odd, swap the order of [value, sibling].
        let new_pair = HV::select_chain_digest(builder, *bit, [value, sibling]);
        value = HV::compress(builder, new_pair);
    }
    HV::assert_digest_eq(builder, value, commitment);
}
