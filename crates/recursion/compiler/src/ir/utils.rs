use slop_algebra::{AbstractExtensionField, AbstractField};
use sp1_primitives::{SP1ExtensionField, SP1Field};
use std::ops::{Mul, MulAssign};

use super::{Builder, Config, DslIr, Ext, Felt, SymbolicExt, Var, Variable};

impl<C: Config> Builder<C> {
    /// The generator for the field.
    ///
    /// Reference: [p3_koala_bear::KoalaBear]
    pub fn generator(&mut self) -> Felt<SP1Field> {
        self.eval(SP1Field::generator())
    }

    /// Select a variable based on a condition.
    pub fn select_v(&mut self, cond: Var<C::N>, a: Var<C::N>, b: Var<C::N>) -> Var<C::N> {
        let c = self.uninit();
        self.push_op(DslIr::CircuitSelectV(cond, a, b, c));
        c
    }

    /// Select a felt based on a condition.
    pub fn select_f(
        &mut self,
        cond: Var<C::N>,
        a: Felt<SP1Field>,
        b: Felt<SP1Field>,
    ) -> Felt<SP1Field> {
        let c = self.uninit();
        self.push_op(DslIr::CircuitSelectF(cond, a, b, c));
        c
    }

    /// Select an extension based on a condition.
    pub fn select_ef(
        &mut self,
        cond: Var<C::N>,
        a: Ext<SP1Field, SP1ExtensionField>,
        b: Ext<SP1Field, SP1ExtensionField>,
    ) -> Ext<SP1Field, SP1ExtensionField> {
        let c = self.uninit();
        self.push_op(DslIr::CircuitSelectE(cond, a, b, c));
        c
    }

    /// Exponentiates a variable to a power of two.
    pub fn exp_power_of_2<V: Variable<C>, E: Into<V::Expression>>(
        &mut self,
        e: E,
        power_log: usize,
    ) -> V
    where
        V::Expression: MulAssign<V::Expression> + Clone,
    {
        let mut e = e.into();
        for _ in 0..power_log {
            e *= e.clone();
        }
        self.eval(e)
    }

    /// Exponentiates a felt to a list of bits in little endian.
    pub fn exp_f_bits(&mut self, x: Felt<SP1Field>, power_bits: Vec<Var<C::N>>) -> Felt<SP1Field> {
        let mut result = self.eval(SP1Field::one());
        let mut power_f: Felt<_> = self.eval(x);
        for i in 0..power_bits.len() {
            let bit = power_bits[i];
            let tmp = self.eval(result * power_f);
            result = self.select_f(bit, tmp, result);
            power_f = self.eval(power_f * power_f);
        }
        result
    }

    /// Exponentiates a extension to a list of bits in little endian.
    pub fn exp_e_bits(
        &mut self,
        x: Ext<SP1Field, SP1ExtensionField>,
        power_bits: Vec<Var<C::N>>,
    ) -> Ext<SP1Field, SP1ExtensionField> {
        let mut result = self.eval(SymbolicExt::from_f(SP1ExtensionField::one()));
        let mut power_f: Ext<_, _> = self.eval(x);
        for i in 0..power_bits.len() {
            let bit = power_bits[i];
            let tmp = self.eval(result * power_f);
            result = self.select_ef(bit, tmp, result);
            power_f = self.eval(power_f * power_f);
        }
        result
    }

    /// Exponentiates a variable to a list of bits in little endian inside a circuit.
    pub fn exp_power_of_2_v_circuit<V>(
        &mut self,
        base: impl Into<V::Expression>,
        power_log: usize,
    ) -> V
    where
        V: Copy + Mul<Output = V::Expression> + Variable<C>,
    {
        let mut result: V = self.eval(base);
        for _ in 0..power_log {
            result = self.eval(result * result)
        }
        result
    }

    /// Creates an ext from a slice of felts.
    pub fn ext_from_base_slice(
        &mut self,
        arr: &[Felt<SP1Field>],
    ) -> Ext<SP1Field, SP1ExtensionField> {
        assert!(arr.len() <= <SP1ExtensionField as AbstractExtensionField<SP1Field>>::D);
        let mut res = SymbolicExt::from_f(SP1ExtensionField::zero());
        for i in 0..arr.len() {
            res += arr[i]
                * SymbolicExt::from_f(
                    <SP1ExtensionField as AbstractExtensionField<SP1Field>>::monomial(i),
                );
        }
        self.eval(res)
    }

    pub fn felts2ext(&mut self, felts: &[Felt<SP1Field>]) -> Ext<SP1Field, SP1ExtensionField> {
        assert_eq!(felts.len(), 4);
        let out: Ext<SP1Field, SP1ExtensionField> = self.uninit();
        self.push_op(DslIr::CircuitFelts2Ext(felts.try_into().unwrap(), out));
        out
    }

    /// Converts an ext to a slice of felts inside a circuit.
    pub fn ext2felt_circuit(
        &mut self,
        value: Ext<SP1Field, SP1ExtensionField>,
    ) -> [Felt<SP1Field>; 4] {
        let a = self.uninit();
        let b = self.uninit();
        let c = self.uninit();
        let d = self.uninit();
        self.push_op(DslIr::CircuitExt2Felt([a, b, c, d], value));
        [a, b, c, d]
    }
}
