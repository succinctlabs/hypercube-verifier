use crate::air::SP1AirBuilder;
use hashbrown::HashMap;
use p3_field::AbstractField;

/// A record that can be proven by a machine.
pub trait MachineRecord: Default + Sized + Send + Sync + Clone {
    /// The statistics of the record.
    fn stats(&self) -> HashMap<String, usize>;

    /// Appends two records together.
    fn append(&mut self, other: &mut Self);

    /// Returns the public values of the record.
    fn public_values<F: AbstractField>(&self) -> Vec<F>;

    // /// Extracts the global cumulative sum from the public values.
    // fn global_cumulative_sum<F: Field>(public_values: &[F]) -> SepticDigest<F>;

    /// Constrains the public values of the record.
    fn eval_public_values<AB: SP1AirBuilder>(builder: &mut AB);
}
