use std::{borrow::BorrowMut, mem::MaybeUninit};

use hypercube_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{DslIr, Var},
    prelude::{Builder, Config, Ext, Felt},
};
use hypercube_recursion_executor::{HASH_RATE, NUM_BITS, PERMUTATION_WIDTH};
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_field::{AbstractField, Field, PrimeField32};
use p3_symmetric::CryptographicPermutation;
use serde::{Deserialize, Serialize};
use slop_merkle_tree::{OUTER_CHALLENGER_RATE, OUTER_DIGEST_SIZE};
use slop_multilinear::Point;
use sp1_derive::AlignedBorrow;

use crate::CircuitConfig;

// Constants for the Multifield challenger.
pub const POSEIDON_2_BB_RATE: usize = 16;

// use crate::{DigestVariable, VerifyingKeyVariable};

pub trait CanCopyChallenger<C: Config> {
    fn copy(&self, builder: &mut Builder<C>) -> Self;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpongeChallengerShape {
    pub input_buffer_len: usize,
    pub output_buffer_len: usize,
}

/// Reference: [p3_challenger::CanObserve].
pub trait CanObserveVariable<C: Config, V> {
    fn observe(&mut self, builder: &mut Builder<C>, value: V);

    fn observe_slice(&mut self, builder: &mut Builder<C>, values: impl IntoIterator<Item = V>) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

pub trait CanSampleVariable<C: Config, V> {
    fn sample(&mut self, builder: &mut Builder<C>) -> V;
}

/// Reference: [p3_challenger::FieldChallenger].
pub trait FieldChallengerVariable<C: Config, Bit>:
    CanObserveVariable<C, Felt<C::F>> + CanSampleVariable<C, Felt<C::F>> + CanSampleBitsVariable<C, Bit>
{
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF>;

    fn check_witness(&mut self, builder: &mut Builder<C>, nb_bits: usize, witness: Felt<C::F>);

    fn duplexing(&mut self, builder: &mut Builder<C>);

    fn sample_point(
        &mut self,
        builder: &mut Builder<C>,
        dimension: u32,
    ) -> Point<Ext<C::F, C::EF>> {
        (0..dimension).map(|_| self.sample_ext(builder)).collect()
    }

    fn observe_ext_element(&mut self, builder: &mut Builder<C>, element: Ext<C::F, C::EF>)
    where
        C: CircuitConfig,
    {
        let felts = C::ext2felt(builder, element);
        self.observe_slice(builder, felts);
    }
}

pub trait CanSampleBitsVariable<C: Config, V> {
    fn sample_bits(&mut self, builder: &mut Builder<C>, nb_bits: usize) -> Vec<V>;
}

/// Reference: [p3_challenger::DuplexChallenger]
#[derive(Clone, Debug)]
pub struct DuplexChallengerVariable<C: Config> {
    pub sponge_state: [Felt<C::F>; PERMUTATION_WIDTH],
    pub input_buffer: Vec<Felt<C::F>>,
    pub output_buffer: Vec<Felt<C::F>>,
}

impl<C: Config<F = BabyBear>> DuplexChallengerVariable<C> {
    /// Creates a new duplex challenger with the default state.
    pub fn new(builder: &mut Builder<C>) -> Self {
        DuplexChallengerVariable::<C> {
            sponge_state: core::array::from_fn(|_| builder.eval(C::F::zero())),
            input_buffer: vec![],
            output_buffer: vec![],
        }
    }

    /// Creates a new challenger variable with the same state as an existing challenger.
    pub fn from_challenger<P: CryptographicPermutation<[BabyBear; PERMUTATION_WIDTH]>>(
        builder: &mut Builder<C>,
        challenger: &DuplexChallenger<BabyBear, P, PERMUTATION_WIDTH, HASH_RATE>,
    ) -> Self {
        let sponge_state = challenger.sponge_state.map(|x| builder.eval(x));
        let input_buffer = challenger.input_buffer.iter().map(|x| builder.eval(*x)).collect();
        let output_buffer = challenger.output_buffer.iter().map(|x| builder.eval(*x)).collect();
        DuplexChallengerVariable::<C> { sponge_state, input_buffer, output_buffer }
    }

    /// Creates a new challenger with the same state as an existing challenger.
    pub fn copy(&self, builder: &mut Builder<C>) -> Self {
        let DuplexChallengerVariable { sponge_state, input_buffer, output_buffer } = self;
        let sponge_state = sponge_state.map(|x| builder.eval(x));
        let mut copy_vec = |v: &Vec<Felt<C::F>>| v.iter().map(|x| builder.eval(*x)).collect();
        DuplexChallengerVariable::<C> {
            sponge_state,
            input_buffer: copy_vec(input_buffer),
            output_buffer: copy_vec(output_buffer),
        }
    }

    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        self.output_buffer.clear();

        self.input_buffer.push(value);

        if self.input_buffer.len() == HASH_RATE {
            self.duplexing(builder);
        }
    }

    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing(builder);
        }

        self.output_buffer.pop().expect("output buffer should be non-empty")
    }

    fn sample_bits(&mut self, builder: &mut Builder<C>, nb_bits: usize) -> Vec<Felt<C::F>> {
        assert!(nb_bits <= NUM_BITS);
        let rand_f = self.sample(builder);
        let mut rand_f_bits = builder.num2bits_v2_f(rand_f, NUM_BITS);
        rand_f_bits.truncate(nb_bits);
        rand_f_bits
    }

    pub fn public_values(&self, builder: &mut Builder<C>) -> ChallengerPublicValues<Felt<C::F>> {
        assert!(self.input_buffer.len() <= PERMUTATION_WIDTH);
        assert!(self.output_buffer.len() <= PERMUTATION_WIDTH);

        let sponge_state = self.sponge_state;
        let num_inputs = builder.eval(C::F::from_canonical_usize(self.input_buffer.len()));
        let num_outputs = builder.eval(C::F::from_canonical_usize(self.output_buffer.len()));

        let input_buffer: [_; PERMUTATION_WIDTH] = self
            .input_buffer
            .iter()
            .copied()
            .chain((self.input_buffer.len()..PERMUTATION_WIDTH).map(|_| builder.eval(C::F::zero())))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let output_buffer: [_; PERMUTATION_WIDTH] = self
            .output_buffer
            .iter()
            .copied()
            .chain(
                (self.output_buffer.len()..PERMUTATION_WIDTH).map(|_| builder.eval(C::F::zero())),
            )
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        ChallengerPublicValues {
            sponge_state,
            num_inputs,
            input_buffer,
            num_outputs,
            output_buffer,
        }
    }
}

impl<C: Config<F = BabyBear>> CanCopyChallenger<C> for DuplexChallengerVariable<C> {
    fn copy(&self, builder: &mut Builder<C>) -> Self {
        DuplexChallengerVariable::copy(self, builder)
    }
}

impl<C: Config<F = BabyBear>> CanObserveVariable<C, Felt<C::F>> for DuplexChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        DuplexChallengerVariable::observe(self, builder, value);
    }

    fn observe_slice(
        &mut self,
        builder: &mut Builder<C>,
        values: impl IntoIterator<Item = Felt<C::F>>,
    ) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

impl<C: Config<F = BabyBear>, const N: usize> CanObserveVariable<C, [Felt<C::F>; N]>
    for DuplexChallengerVariable<C>
{
    fn observe(&mut self, builder: &mut Builder<C>, values: [Felt<C::F>; N]) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

impl<C: Config<F = BabyBear>> CanSampleVariable<C, Felt<C::F>> for DuplexChallengerVariable<C> {
    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        DuplexChallengerVariable::sample(self, builder)
    }
}

impl<C: Config<F = BabyBear>> CanSampleBitsVariable<C, Felt<C::F>> for DuplexChallengerVariable<C> {
    fn sample_bits(&mut self, builder: &mut Builder<C>, nb_bits: usize) -> Vec<Felt<C::F>> {
        DuplexChallengerVariable::sample_bits(self, builder, nb_bits)
    }
}

impl<C: Config<F = BabyBear>> FieldChallengerVariable<C, Felt<C::F>>
    for DuplexChallengerVariable<C>
{
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.ext_from_base_slice(&[a, b, c, d])
    }

    fn check_witness(
        &mut self,
        builder: &mut Builder<C>,
        nb_bits: usize,
        witness: Felt<<C as Config>::F>,
    ) {
        self.observe(builder, witness);
        let element_bits = self.sample_bits(builder, nb_bits);
        for bit in element_bits {
            builder.assert_felt_eq(bit, C::F::zero());
        }
    }

    fn duplexing(&mut self, builder: &mut Builder<C>) {
        assert!(self.input_buffer.len() <= HASH_RATE);

        self.sponge_state[0..self.input_buffer.len()].copy_from_slice(self.input_buffer.as_slice());
        self.input_buffer.clear();

        self.sponge_state = builder.poseidon2_permute_v2(self.sponge_state);

        self.output_buffer.clear();
        self.output_buffer.extend_from_slice(&self.sponge_state);
    }
}

#[derive(Clone)]
pub struct MultiField32ChallengerVariable<C: Config> {
    sponge_state: [Var<C::N>; 3],
    input_buffer: Vec<Felt<C::F>>,
    output_buffer: Vec<Felt<C::F>>,
    num_f_elms: usize,
}

impl<C: Config> MultiField32ChallengerVariable<C> {
    pub fn new(builder: &mut Builder<C>) -> Self {
        MultiField32ChallengerVariable::<C> {
            sponge_state: [
                builder.eval(C::N::zero()),
                builder.eval(C::N::zero()),
                builder.eval(C::N::zero()),
            ],
            input_buffer: vec![],
            output_buffer: vec![],
            num_f_elms: C::N::bits() / 64,
        }
    }

    pub fn duplexing(&mut self, builder: &mut Builder<C>) {
        assert!(self.input_buffer.len() <= self.num_f_elms * OUTER_CHALLENGER_RATE);

        for (i, f_chunk) in self.input_buffer.chunks(self.num_f_elms).enumerate() {
            self.sponge_state[i] = reduce_32(builder, f_chunk);
        }
        self.input_buffer.clear();

        // TODO make this a method for the builder.
        builder.push_op(DslIr::CircuitPoseidon2Permute(self.sponge_state));

        self.output_buffer.clear();
        for &pf_val in self.sponge_state.iter() {
            let f_vals = split_32(builder, pf_val, self.num_f_elms);
            for f_val in f_vals {
                self.output_buffer.push(f_val);
            }
        }
    }

    pub fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        self.output_buffer.clear();

        self.input_buffer.push(value);
        if self.input_buffer.len() == self.num_f_elms * OUTER_CHALLENGER_RATE {
            self.duplexing(builder);
        }
    }

    pub fn observe_commitment(
        &mut self,
        builder: &mut Builder<C>,
        value: [Var<C::N>; OUTER_DIGEST_SIZE],
    ) {
        for val in value {
            let f_vals: Vec<Felt<C::F>> = split_32(builder, val, self.num_f_elms);
            for f_val in f_vals {
                self.observe(builder, f_val);
            }
        }
    }

    pub fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing(builder);
        }

        self.output_buffer.pop().expect("output buffer should be non-empty")
    }

    pub fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.felts2ext(&[a, b, c, d])
    }

    pub fn sample_bits(&mut self, builder: &mut Builder<C>, bits: usize) -> Vec<Var<C::N>> {
        let rand_f = self.sample(builder);
        builder.num2bits_f_circuit(rand_f)[0..bits].to_vec()
    }

    pub fn check_witness(&mut self, builder: &mut Builder<C>, bits: usize, witness: Felt<C::F>) {
        self.observe(builder, witness);
        let element = self.sample_bits(builder, bits);
        for bit in element {
            builder.assert_var_eq(bit, C::N::from_canonical_usize(0));
        }
    }
}

impl<C: Config> CanCopyChallenger<C> for MultiField32ChallengerVariable<C> {
    /// Creates a new challenger with the same state as an existing challenger.
    fn copy(&self, builder: &mut Builder<C>) -> Self {
        let MultiField32ChallengerVariable {
            sponge_state,
            input_buffer,
            output_buffer,
            num_f_elms,
        } = self;
        let sponge_state = sponge_state.map(|x| builder.eval(x));
        let mut copy_vec = |v: &Vec<Felt<C::F>>| v.iter().map(|x| builder.eval(*x)).collect();
        MultiField32ChallengerVariable::<C> {
            sponge_state,
            num_f_elms: *num_f_elms,
            input_buffer: copy_vec(input_buffer),
            output_buffer: copy_vec(output_buffer),
        }
    }
}

impl<C: Config> CanObserveVariable<C, Felt<C::F>> for MultiField32ChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        MultiField32ChallengerVariable::observe(self, builder, value);
    }
}

impl<C: Config> CanObserveVariable<C, [Var<C::N>; OUTER_DIGEST_SIZE]>
    for MultiField32ChallengerVariable<C>
{
    fn observe(&mut self, builder: &mut Builder<C>, value: [Var<C::N>; OUTER_DIGEST_SIZE]) {
        self.observe_commitment(builder, value)
    }
}

impl<C: Config> CanObserveVariable<C, Var<C::N>> for MultiField32ChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, value: Var<C::N>) {
        self.observe_commitment(builder, [value])
    }
}

impl<C: Config> CanSampleVariable<C, Felt<C::F>> for MultiField32ChallengerVariable<C> {
    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        MultiField32ChallengerVariable::sample(self, builder)
    }
}

impl<C: Config> CanSampleBitsVariable<C, Var<C::N>> for MultiField32ChallengerVariable<C> {
    fn sample_bits(&mut self, builder: &mut Builder<C>, bits: usize) -> Vec<Var<C::N>> {
        MultiField32ChallengerVariable::sample_bits(self, builder, bits)
    }
}

impl<C: Config> FieldChallengerVariable<C, Var<C::N>> for MultiField32ChallengerVariable<C> {
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        MultiField32ChallengerVariable::sample_ext(self, builder)
    }

    fn check_witness(&mut self, builder: &mut Builder<C>, bits: usize, witness: Felt<C::F>) {
        MultiField32ChallengerVariable::check_witness(self, builder, bits, witness);
    }

    fn duplexing(&mut self, builder: &mut Builder<C>) {
        MultiField32ChallengerVariable::duplexing(self, builder);
    }
}

pub fn reduce_32<C: Config>(builder: &mut Builder<C>, vals: &[Felt<C::F>]) -> Var<C::N> {
    let mut power = C::N::one();
    let result: Var<C::N> = builder.eval(C::N::zero());
    for val in vals.iter() {
        let val = builder.felt2var_circuit(*val);
        builder.assign(result, result + val * power);
        power *= C::N::from_canonical_u64(1u64 << 32);
    }
    result
}

pub fn split_32<C: Config>(builder: &mut Builder<C>, val: Var<C::N>, n: usize) -> Vec<Felt<C::F>> {
    let bits = builder.num2bits_v_circuit(val, 256);
    let mut results = Vec::new();
    for i in 0..n {
        let result: Felt<C::F> = builder.eval(C::F::zero());
        for j in 0..64 {
            let bit = bits[i * 64 + j];
            let t = builder.eval(result + C::F::from_wrapped_u64(1 << j));
            let z = builder.select_f(bit, t, result);
            builder.assign(result, z);
        }
        results.push(result);
    }
    results
}

pub const CHALLENGER_STATE_NUM_ELTS: usize = size_of::<ChallengerPublicValues<u8>>();

#[derive(AlignedBorrow, Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct ChallengerPublicValues<T> {
    pub sponge_state: [T; PERMUTATION_WIDTH],
    pub num_inputs: T,
    pub input_buffer: [T; PERMUTATION_WIDTH],
    pub num_outputs: T,
    pub output_buffer: [T; PERMUTATION_WIDTH],
}

impl<T: Clone> ChallengerPublicValues<T> {
    pub fn set_challenger<P: CryptographicPermutation<[T; PERMUTATION_WIDTH]>>(
        &self,
        challenger: &mut DuplexChallenger<T, P, PERMUTATION_WIDTH, HASH_RATE>,
    ) where
        T: PrimeField32,
    {
        challenger.sponge_state = self.sponge_state;
        let num_inputs = self.num_inputs.as_canonical_u32() as usize;
        challenger.input_buffer = self.input_buffer[..num_inputs].to_vec();
        let num_outputs = self.num_outputs.as_canonical_u32() as usize;
        challenger.output_buffer = self.output_buffer[..num_outputs].to_vec();
    }

    pub fn as_array(&self) -> [T; CHALLENGER_STATE_NUM_ELTS]
    where
        T: Copy,
    {
        unsafe {
            let mut ret = [MaybeUninit::<T>::zeroed().assume_init(); CHALLENGER_STATE_NUM_ELTS];
            let pv: &mut ChallengerPublicValues<T> = ret.as_mut_slice().borrow_mut();
            *pv = *self;
            ret
        }
    }
}

impl<T: Copy> IntoIterator for ChallengerPublicValues<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, CHALLENGER_STATE_NUM_ELTS>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_array().into_iter()
    }
}
