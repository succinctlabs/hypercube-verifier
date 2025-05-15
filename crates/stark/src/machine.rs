use derive_where::derive_where;
use p3_field::Field;
use std::collections::BTreeSet;

use crate::{air::MachineAir, Chip};

/// A shape for a machine.
#[derive(Debug)]
#[derive_where(Clone)]
pub struct MachineShape<F: Field, A> {
    chip_clusters: Vec<BTreeSet<Chip<F, A>>>,
}

impl<F: Field, A: MachineAir<F>> MachineShape<F, A> {
    /// Create a single shape that always includes all the chips.
    #[must_use]
    pub fn all(chips: &[Chip<F, A>]) -> Self {
        let chip_clusters = vec![chips.iter().cloned().collect()];
        Self { chip_clusters }
    }

    /// Create a new shape from a list of chip clusters.
    #[must_use]
    pub const fn new(chip_clusters: Vec<BTreeSet<Chip<F, A>>>) -> Self {
        Self { chip_clusters }
    }

    /// Returns the smallest shape cluster that contains all the chips with given names.
    #[must_use]
    pub fn smallest_cluster(&self, chips: &BTreeSet<Chip<F, A>>) -> Option<&BTreeSet<Chip<F, A>>> {
        self.chip_clusters
            .iter()
            .filter(|cluster| chips.is_subset(cluster))
            .min_by_key(|cluster| cluster.len())
    }
}

/// A STARK for proving RISC-V execution.
#[derive(Debug)]
#[derive_where(Clone)]
pub struct Machine<F: Field, A> {
    /// The chips that make up the RISC-V STARK machine, in order of their execution.
    chips: Vec<Chip<F, A>>,
    /// The number of public values elements that the machine uses
    num_pv_elts: usize,
    /// The shape of the machine.
    shape: MachineShape<F, A>,
}

impl<F, A> Machine<F, A>
where
    F: Field,
    A: MachineAir<F>,
{
    /// Creates a new [`StarkMachine`].
    #[must_use]
    pub const fn new(
        chips: Vec<Chip<F, A>>,
        num_pv_elts: usize,
        shape: MachineShape<F, A>,
    ) -> Self {
        Self { chips, num_pv_elts, shape }
    }

    /// Returns the chips in the machine.
    #[must_use]
    pub fn chips(&self) -> &[Chip<F, A>] {
        &self.chips
    }

    /// Returns the number of public values elements.
    #[must_use]
    pub const fn num_pv_elts(&self) -> usize {
        self.num_pv_elts
    }

    /// Returns the smallest shape cluster that contains all the chips with given names.
    #[must_use]
    pub fn smallest_cluster(&self, chips: &BTreeSet<Chip<F, A>>) -> Option<&BTreeSet<Chip<F, A>>> {
        self.shape.smallest_cluster(chips)
    }

    // /// Generates the dependencies of the given records.
    // #[allow(clippy::needless_for_each)]
    // pub fn generate_dependencies(
    //     &self,
    //     records: &mut [A::Record],
    //     chips_filter: Option<&[String]>,
    // ) {
    //     let chips = self
    //         .chips
    //         .iter()
    //         .filter(|chip| {
    //             if let Some(chips_filter) = chips_filter {
    //                 chips_filter.contains(&chip.name())
    //             } else {
    //                 true
    //             }
    //         })
    //         .collect::<Vec<_>>();

    //     records.iter_mut().for_each(|record| {
    //         chips.iter().for_each(|chip| {
    //             let mut output = A::Record::default();
    //             chip.generate_dependencies(record, &mut output);
    //             record.append(&mut output);
    //         });
    //         // tracing::debug_span!("register nonces").in_scope(|| record.register_nonces(opts));
    //     });
    // }
}
