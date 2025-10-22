use std::{fs::File, io::Write};

use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField, PrimeField};
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::ir::{Config, Witness};

/// A witness that can be used to initialize values for witness generation inside Gnark.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GnarkWitness {
    pub vars: Vec<String>,
    pub felts: Vec<String>,
    pub exts: Vec<Vec<String>>,
    pub vkey_hash: String,
    pub committed_values_digest: String,
    pub exit_code: String,
    pub vk_root: String,
    pub proof_nonce: String,
}

impl GnarkWitness {
    /// Creates a new witness from a given [Witness].
    pub fn new<C: Config>(mut witness: Witness<C>) -> Self {
        witness.vars.push(C::N::from_canonical_usize(999));
        witness.felts.push(SP1Field::from_canonical_usize(999));
        witness.exts.push(SP1ExtensionField::from_canonical_usize(999));
        GnarkWitness {
            vars: witness.vars.into_iter().map(|w| w.as_canonical_biguint().to_string()).collect(),
            felts: witness
                .felts
                .into_iter()
                .map(|w| w.as_canonical_biguint().to_string())
                .collect(),
            exts: witness
                .exts
                .into_iter()
                .map(|w| {
                    <SP1ExtensionField as AbstractExtensionField<SP1Field>>::as_base_slice(&w)
                        .iter()
                        .map(|x| x.as_canonical_biguint().to_string())
                        .collect()
                })
                .collect(),
            vkey_hash: witness.vkey_hash.as_canonical_biguint().to_string(),
            committed_values_digest: witness
                .committed_values_digest
                .as_canonical_biguint()
                .to_string(),
            exit_code: witness.exit_code.as_canonical_biguint().to_string(),
            vk_root: witness.vk_root.as_canonical_biguint().to_string(),
            proof_nonce: witness.proof_nonce.as_canonical_biguint().to_string(),
        }
    }

    /// Saves the witness to a given path.
    pub fn save(&self, path: &str) {
        let serialized = serde_json::to_string(self).unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();
    }
}
