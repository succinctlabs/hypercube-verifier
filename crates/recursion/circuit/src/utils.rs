use slop_algebra::{AbstractField, PrimeField32};
use slop_bn254::Bn254Fr;
use sp1_primitives::SP1Field;

use sp1_recursion_compiler::ir::{Builder, Config, Felt, Var};
use sp1_recursion_executor::DIGEST_SIZE;

/// Convert 8 SP1Field words into a Bn254Fr field element by shifting by 31 bits each time. The last
/// word becomes the least significant bits.
pub fn koalabears_to_bn254(digest: &[SP1Field; 8]) -> Bn254Fr {
    let mut result = Bn254Fr::zero();
    for word in digest.iter() {
        // Since SP1Field prime is less than 2^31, we can shift by 31 bits each time and still be
        // within the Bn254Fr field, so we don't have to truncate the top 3 bits.
        result *= Bn254Fr::from_canonical_u64(1 << 31);
        result += Bn254Fr::from_canonical_u32(word.as_canonical_u32());
    }
    result
}

pub fn koalabears_proof_nonce_to_bn254(nonce: &[SP1Field; 4]) -> Bn254Fr {
    let mut result = Bn254Fr::zero();
    for word in nonce.iter() {
        // Since SP1Field prime is less than 2^31, we can shift by 31 bits each time and still be
        // within the Bn254Fr field, so we don't have to truncate the top 3 bits.
        result *= Bn254Fr::from_canonical_u64(1 << 31);
        result += Bn254Fr::from_canonical_u32(word.as_canonical_u32());
    }
    result
}

/// Convert 32 SP1Field bytes into a Bn254Fr field element. The first byte's most significant 3 bits
/// (which would become the 3 most significant bits) are truncated.
pub fn koalabear_bytes_to_bn254(bytes: &[SP1Field; 32]) -> Bn254Fr {
    let mut result = Bn254Fr::zero();
    for (i, byte) in bytes.iter().enumerate() {
        debug_assert!(byte < &SP1Field::from_canonical_u32(256));
        if i == 0 {
            // 32 bytes is more than Bn254 prime, so we need to truncate the top 3 bits.
            result = Bn254Fr::from_canonical_u32(byte.as_canonical_u32() & 0x1f);
        } else {
            result *= Bn254Fr::from_canonical_u32(256);
            result += Bn254Fr::from_canonical_u32(byte.as_canonical_u32());
        }
    }
    result
}

pub fn felts_to_bn254_var<C: Config>(
    builder: &mut Builder<C>,
    digest: &[Felt<SP1Field>; DIGEST_SIZE],
) -> Var<C::N> {
    let var_2_31: Var<_> = builder.constant(C::N::from_canonical_u32(1 << 31));
    let result = builder.constant(C::N::zero());
    for (i, word) in digest.iter().enumerate() {
        let word_var = builder.felt2var_circuit(*word);
        if i == 0 {
            builder.assign(result, word_var);
        } else {
            builder.assign(result, result * var_2_31 + word_var);
        }
    }
    result
}

pub fn felt_proof_nonce_to_bn254_var<C: Config>(
    builder: &mut Builder<C>,
    nonce: &[Felt<SP1Field>; 4],
) -> Var<C::N> {
    let var_2_31: Var<_> = builder.constant(C::N::from_canonical_u32(1 << 31));
    let result = builder.constant(C::N::zero());
    for (i, word) in nonce.iter().enumerate() {
        let word_var = builder.felt2var_circuit(*word);
        if i == 0 {
            builder.assign(result, word_var);
        } else {
            builder.assign(result, result * var_2_31 + word_var);
        }
    }
    result
}

pub fn felt_bytes_to_bn254_var<C: Config>(
    builder: &mut Builder<C>,
    bytes: &[Felt<SP1Field>; 32],
) -> Var<C::N> {
    let var_256: Var<_> = builder.constant(C::N::from_canonical_u32(256));
    let zero_var: Var<_> = builder.constant(C::N::zero());
    let result = builder.constant(C::N::zero());
    for (i, byte) in bytes.iter().enumerate() {
        let byte_bits = builder.num2bits_f_circuit(*byte);
        if i == 0 {
            // Since 32 bytes doesn't fit into Bn254, we need to truncate the top 3 bits.
            // For first byte, zero out 3 most significant bits.
            for i in 0..3 {
                builder.assign(byte_bits[8 - i - 1], zero_var);
            }
            let byte_var = builder.bits2num_v_circuit(&byte_bits);
            builder.assign(result, byte_var);
        } else {
            let byte_var = builder.bits2num_v_circuit(&byte_bits);
            builder.assign(result, result * var_256 + byte_var);
        }
    }
    result
}

pub fn words_to_bytes<T: Copy>(words: &[[T; 4]]) -> Vec<T> {
    words.iter().flat_map(|w| w.iter()).copied().collect::<Vec<_>>()
}
