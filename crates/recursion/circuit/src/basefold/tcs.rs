use std::marker::PhantomData;

use hypercube_recursion_compiler::ir::{Builder, Felt, IrIter};
use hypercube_stark::BabyBearPoseidon2;
use itertools::Itertools;
use slop_merkle_tree::{MerkleTreeTcs, MerkleTreeTcsProof, Poseidon2BabyBearConfig};
use slop_tensor::Tensor;

use crate::{basefold::merkle_tree::verify, hash::FieldHasherVariable, AsRecursive, CircuitConfig};

pub trait RecursiveTcs: Sized {
    type Data;
    type Commitment;
    type Proof;
    type Circuit: CircuitConfig<Bit = Self::Bit>;
    type Bit;

    fn verify_tensor_openings(
        builder: &mut Builder<Self::Circuit>,
        commit: &Self::Commitment,
        indices: &[Vec<Self::Bit>],
        opening: &RecursiveTensorCsOpening<Self>,
    );
}

/// An opening of a tensor commitment scheme.
pub struct RecursiveTensorCsOpening<C: RecursiveTcs> {
    /// The claimed values of the opening.
    pub values: Tensor<C::Data>,
    /// The proof of the opening.
    pub proof: <C as RecursiveTcs>::Proof,
}

#[derive(Debug, Copy, PartialEq, Eq)]
pub struct RecursiveMerkleTreeTcs<C, M>(pub PhantomData<(C, M)>);

impl<C, M> Clone for RecursiveMerkleTreeTcs<C, M> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<C: CircuitConfig> AsRecursive<C> for MerkleTreeTcs<Poseidon2BabyBearConfig> {
    type Recursive = RecursiveMerkleTreeTcs<C, BabyBearPoseidon2>;
}

impl<C, M> RecursiveTcs for RecursiveMerkleTreeTcs<C, M>
where
    C: CircuitConfig,
    M: FieldHasherVariable<C>,
{
    type Data = Felt<C::F>;
    type Commitment = M::DigestVariable;
    type Proof = MerkleTreeTcsProof<M::DigestVariable>;
    type Circuit = C;
    type Bit = C::Bit;

    fn verify_tensor_openings(
        builder: &mut Builder<Self::Circuit>,
        commit: &Self::Commitment,
        indices: &[Vec<Self::Bit>],
        opening: &RecursiveTensorCsOpening<Self>,
    ) {
        let chunk_size = indices.len().div_ceil(8);
        indices
            .iter()
            .zip_eq(opening.proof.paths.split())
            .chunks(chunk_size)
            .into_iter()
            .enumerate()
            .ir_par_map_collect::<Vec<_>, _, _>(builder, |builder, (i, chunk)| {
                for (j, (index, path)) in chunk.into_iter().enumerate() {
                    let claimed_values_slices =
                        opening.values.get(i * chunk_size + j).unwrap().as_slice().to_vec();

                    let path = path.as_slice().to_vec();
                    let digest = M::hash(builder, &claimed_values_slices);

                    verify::<C, M>(builder, path, index.to_vec(), digest, *commit);
                }
            });
    }
}
