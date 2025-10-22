use slop_algebra::AbstractField;
use sp1_primitives::SP1Field;
use sp1_recursion_executor::NUM_BITS;

use super::{Builder, Config, DslIr, Felt, Var};

impl<C: Config> Builder<C> {
    /// Converts a variable to bits inside a circuit.
    pub fn num2bits_v_circuit(&mut self, num: Var<C::N>, bits: usize) -> Vec<Var<C::N>> {
        let mut output = Vec::new();
        for _ in 0..bits {
            output.push(self.uninit());
        }

        self.push_op(DslIr::CircuitNum2BitsV(num, bits, output.clone()));

        output
    }

    /// Converts a felt to bits inside a circuit.
    pub fn num2bits_f_circuit(&mut self, num: Felt<SP1Field>) -> Vec<Var<C::N>> {
        let mut output = Vec::new();
        for _ in 0..NUM_BITS {
            output.push(self.uninit());
        }

        self.push_op(DslIr::CircuitNum2BitsF(num, output.clone()));

        output
    }

    /// Convert bits to a variable inside a circuit.
    pub fn bits2num_v_circuit(&mut self, bits: &[Var<C::N>]) -> Var<C::N> {
        let result: Var<_> = self.eval(C::N::zero());
        for i in 0..bits.len() {
            self.assign(result, result + bits[i] * C::N::from_canonical_u32(1 << i));
        }
        result
    }
}
