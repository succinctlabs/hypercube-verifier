use itertools::Itertools;
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::{PROOF_NONCE_NUM_WORDS, PV_DIGEST_NUM_WORDS};
use sp1_primitives::SP1Field;
use sp1_recursion_compiler::ir::{Builder, Felt};
use sp1_recursion_executor::{RecursionPublicValues, DIGEST_SIZE, NUM_PV_ELMS_TO_HASH};

use crate::{hash::Poseidon2SP1FieldHasherVariable, CircuitConfig};

#[derive(Debug, Clone, Copy, Default, AlignedBorrow)]
#[repr(C)]
pub struct RootPublicValues<T> {
    pub(crate) inner: RecursionPublicValues<T>,
}

/// Verifies the digest of a recursive public values struct.
pub(crate) fn assert_recursion_public_values_valid<C, H>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<SP1Field>>,
) where
    C: CircuitConfig,
    H: Poseidon2SP1FieldHasherVariable<C>,
{
    let digest = recursion_public_values_digest::<C, H>(builder, public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(digest) {
        builder.assert_felt_eq(value, expected);
    }
}

/// Verifies the digest of a recursive public values struct.
pub(crate) fn recursion_public_values_digest<C, H>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<SP1Field>>,
) -> [Felt<SP1Field>; DIGEST_SIZE]
where
    C: CircuitConfig,
    H: Poseidon2SP1FieldHasherVariable<C>,
{
    let pv_slice = public_values.as_array();
    H::poseidon2_hash(builder, &pv_slice[..NUM_PV_ELMS_TO_HASH])
}

/// Assert that the digest of the root public values is correct.
pub(crate) fn assert_root_public_values_valid<C, H>(
    builder: &mut Builder<C>,
    public_values: &RootPublicValues<Felt<SP1Field>>,
) where
    C: CircuitConfig,
    H: Poseidon2SP1FieldHasherVariable<C>,
{
    let expected_digest = root_public_values_digest::<C, H>(builder, &public_values.inner);
    for (value, expected) in public_values.inner.digest.iter().copied().zip_eq(expected_digest) {
        builder.assert_felt_eq(value, expected);
    }
}

/// Compute the digest of the root public values.
pub(crate) fn root_public_values_digest<C, H>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<SP1Field>>,
) -> [Felt<SP1Field>; DIGEST_SIZE]
where
    C: CircuitConfig,
    H: Poseidon2SP1FieldHasherVariable<C>,
{
    let input = public_values
        .sp1_vk_digest
        .into_iter()
        .chain(public_values.committed_value_digest.into_iter().flat_map(|word| word.into_iter()))
        .chain(std::iter::once(public_values.exit_code))
        .chain(public_values.vk_root)
        .chain(public_values.proof_nonce)
        .collect::<Vec<_>>();
    H::poseidon2_hash(builder, &input)
}

impl<T> RootPublicValues<T> {
    pub const fn new(inner: RecursionPublicValues<T>) -> Self {
        Self { inner }
    }

    #[inline]
    pub const fn sp1_vk_digest(&self) -> &[T; DIGEST_SIZE] {
        &self.inner.sp1_vk_digest
    }

    #[inline]
    pub const fn committed_value_digest(&self) -> &[[T; 4]; PV_DIGEST_NUM_WORDS] {
        &self.inner.committed_value_digest
    }

    #[inline]
    pub const fn digest(&self) -> &[T; DIGEST_SIZE] {
        &self.inner.digest
    }

    #[inline]
    pub const fn exit_code(&self) -> &T {
        &self.inner.exit_code
    }

    #[inline]
    pub const fn vk_root(&self) -> &[T; DIGEST_SIZE] {
        &self.inner.vk_root
    }

    #[inline]
    pub const fn proof_nonce(&self) -> &[T; PROOF_NONCE_NUM_WORDS] {
        &self.inner.proof_nonce
    }
}
