use p3_air::BaseAir;
use p3_field::Field;

// TODO: add Id type and also fn id()

#[macro_export]
/// Macro to get the name of a chip.
macro_rules! chip_name {
    ($chip:ident, $field:ty) => {
        <$chip as MachineAir<$field>>::name(&$chip {})
    };
}

/// An AIR that is part of a multi table AIR arithmetization.
pub trait MachineAir<F: Field>: BaseAir<F> + 'static + Send + Sync {
    /// A unique identifier for this AIR as part of a machine.
    fn name(&self) -> String;

    /// The width of the preprocessed trace.
    fn preprocessed_width(&self) -> usize {
        0
    }
}
