use p3_field::Field;

use super::InteractionKind;

/// The data for an interaction.
#[derive(Debug)]
pub struct InteractionData<F: Field> {
    /// The chip name.
    pub chip_name: String,
    /// The kind of interaction.
    pub kind: InteractionKind,
    /// The row of the interaction.
    pub row: usize,
    /// The interaction number.
    pub interaction_number: usize,
    /// Whether the interaction is a send.
    pub is_send: bool,
    /// The multiplicity of the interaction.
    pub multiplicity: F,
}

/// Converts a vector of field elements to a string.
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn vec_to_string<F: Field>(vec: Vec<F>) -> String {
    let mut result = String::from("(");
    for (i, value) in vec.iter().enumerate() {
        if i != 0 {
            result.push_str(", ");
        }
        result.push_str(&value.to_string());
    }
    result.push(')');
    result
}
