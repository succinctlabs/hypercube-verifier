use std::{fmt::Display, hash::Hash, sync::Arc};

use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{get_max_constraint_degree, get_symbolic_constraints, SymbolicAirBuilder};

use crate::{
    air::{MachineAir, MultiTableAirBuilder, SP1AirBuilder},
    log2_ceil_usize,
    lookup::{Interaction, InteractionBuilder, InteractionKind},
};

use super::PROOF_MAX_NUM_PVS;

/// The maximum constraint degree for a chip.
pub const MAX_CONSTRAINT_DEGREE: usize = 3;

/// An Air that encodes lookups based on interactions.
#[derive(Debug)]
pub struct Chip<F: Field, A> {
    /// The underlying AIR of the chip for constraint evaluation.
    pub air: Arc<A>,
    /// The interactions that the chip sends.
    pub sends: Arc<Vec<Interaction<F>>>,
    /// The interactions that the chip receives.
    pub receives: Arc<Vec<Interaction<F>>>,
    /// The relative log degree of the quotient polynomial, i.e. `log2(max_constraint_degree - 1)`.
    pub log_quotient_degree: usize,
    /// The total number of constraints in the chip.
    pub num_constraints: usize,
}

impl<F: Field, A> Clone for Chip<F, A> {
    fn clone(&self) -> Self {
        Self {
            air: self.air.clone(),
            sends: self.sends.clone(),
            receives: self.receives.clone(),
            log_quotient_degree: self.log_quotient_degree,
            num_constraints: self.num_constraints,
        }
    }
}

impl<F: Field, A> Chip<F, A> {
    /// The send interactions of the chip.
    #[must_use]
    pub fn sends(&self) -> &[Interaction<F>] {
        &self.sends
    }

    /// The receive interactions of the chip.
    #[must_use]
    pub fn receives(&self) -> &[Interaction<F>] {
        &self.receives
    }

    /// The relative log degree of the quotient polynomial, i.e. `log2(max_constraint_degree - 1)`.
    #[must_use]
    pub const fn log_quotient_degree(&self) -> usize {
        self.log_quotient_degree
    }

    /// Consumes the chip and returns the underlying air.
    #[must_use]
    pub fn into_inner(self) -> Option<A> {
        Arc::into_inner(self.air)
    }
}

impl<F, A> Chip<F, A>
where
    F: Field,
    A: BaseAir<F>,
{
    /// Records the interactions and constraint degree from the air and crates a new chip.
    pub fn new(air: A) -> Self
    where
        A: MachineAir<F> + Air<InteractionBuilder<F>> + Air<SymbolicAirBuilder<F>>,
    {
        let mut builder = InteractionBuilder::new(air.preprocessed_width(), air.width());
        air.eval(&mut builder);
        let (sends, receives) = builder.interactions();

        let nb_byte_sends = sends.iter().filter(|s| s.kind == InteractionKind::Byte).count();
        let nb_byte_receives = receives.iter().filter(|r| r.kind == InteractionKind::Byte).count();
        tracing::debug!(
            "chip {} has {} byte interactions",
            air.name(),
            nb_byte_sends + nb_byte_receives
        );

        let mut max_constraint_degree =
            get_max_constraint_degree(&air, air.preprocessed_width(), PROOF_MAX_NUM_PVS);

        if !sends.is_empty() || !receives.is_empty() {
            max_constraint_degree = std::cmp::max(max_constraint_degree, MAX_CONSTRAINT_DEGREE);
        }
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);

        // Count the number of constraints.
        // TODO: unify this with the constraint degree calculation.
        let num_constraints =
            get_symbolic_constraints(&air, air.preprocessed_width(), PROOF_MAX_NUM_PVS).len();

        let sends = Arc::new(sends);
        let receives = Arc::new(receives);

        let air = Arc::new(air);
        Self { air, sends, receives, log_quotient_degree, num_constraints }
    }

    /// Returns the number of interactions in the chip.
    #[inline]
    #[must_use]
    pub fn num_interactions(&self) -> usize {
        self.sends.len() + self.receives.len()
    }

    /// Returns the number of sent byte lookups in the chip.
    #[inline]
    #[must_use]
    pub fn num_sent_byte_lookups(&self) -> usize {
        self.sends.iter().filter(|i| i.kind == InteractionKind::Byte).count()
    }

    /// Returns the number of sends of the given kind.
    #[inline]
    #[must_use]
    pub fn num_sends_by_kind(&self, kind: InteractionKind) -> usize {
        self.sends.iter().filter(|i| i.kind == kind).count()
    }

    /// Returns the number of receives of the given kind.
    #[inline]
    #[must_use]
    pub fn num_receives_by_kind(&self, kind: InteractionKind) -> usize {
        self.receives.iter().filter(|i| i.kind == kind).count()
    }

    /// Returns the cost of a row in the chip.
    #[inline]
    #[must_use]
    pub fn cost(&self) -> u64
    where
        A: MachineAir<F>,
    {
        let preprocessed_cols = self.preprocessed_width();
        let main_cols = self.width();
        (preprocessed_cols + main_cols) as u64
    }

    /// Returns the width of the quotient polynomial.
    #[inline]
    #[must_use]
    pub const fn quotient_width(&self) -> usize {
        1 << self.log_quotient_degree
    }

    /// Returns the log2 of the batch size.
    #[inline]
    #[must_use]
    pub const fn logup_batch_size(&self) -> usize {
        1 << self.log_quotient_degree
    }
}

impl<F, A> BaseAir<F> for Chip<F, A>
where
    F: Field,
    A: BaseAir<F> + Send,
{
    fn width(&self) -> usize {
        self.air.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        panic!("Chip should not use the `BaseAir` method, but the `MachineAir` method.")
    }
}

impl<F, A> MachineAir<F> for Chip<F, A>
where
    F: Field,
    A: MachineAir<F>,
{
    // type Record = A::Record;

    // type Program = A::Program;

    fn name(&self) -> String {
        self.air.name()
    }

    fn preprocessed_width(&self) -> usize {
        <A as MachineAir<F>>::preprocessed_width(&self.air)
    }
}

// Implement AIR directly on Chip, evaluating both execution and permutation constraints.
impl<'a, F, A, AB> Air<AB> for Chip<F, A>
where
    F: Field,
    A: Air<AB> + MachineAir<F>,
    AB: SP1AirBuilder<F = F> + MultiTableAirBuilder<'a> + PairBuilder + 'a,
{
    fn eval(&self, builder: &mut AB) {
        // Evaluate the execution trace constraints.
        self.air.eval(builder);
    }
}

impl<F, A> PartialEq for Chip<F, A>
where
    F: Field,
    A: MachineAir<F>,
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.air.name() == other.air.name()
    }
}

impl<F: Field, A: MachineAir<F>> Eq for Chip<F, A> where F: Field + Eq {}

impl<F, A> Hash for Chip<F, A>
where
    F: Field,
    A: MachineAir<F>,
{
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.air.name().hash(state);
    }
}

impl<F: Field, A: MachineAir<F>> PartialOrd for Chip<F, A>
where
    F: Field,
    A: MachineAir<F>,
{
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: Field, A: MachineAir<F>> Ord for Chip<F, A>
where
    F: Field,
    A: MachineAir<F>,
{
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name().cmp(&other.name())
    }
}

/// Statistics about a chip.
#[derive(Debug, Clone)]
pub struct ChipStatistics<F> {
    /// The name of the chip.
    name: String,
    /// The height of the chip.
    height: usize,
    /// The number of preprocessed columns.
    preprocessed_cols: usize,
    /// The number of main columns.
    main_cols: usize,
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field> ChipStatistics<F> {
    /// Creates a new chip statistics from a chip and height.
    #[must_use]
    pub fn new<A: MachineAir<F>>(chip: &Chip<F, A>, height: usize) -> Self {
        let name = chip.name();
        let preprocessed_cols = chip.preprocessed_width();
        let main_cols = chip.width();
        Self { name, height, preprocessed_cols, main_cols, _marker: std::marker::PhantomData }
    }

    /// Returns the total width of the chip.
    #[must_use]
    #[inline]
    pub const fn total_width(&self) -> usize {
        self.preprocessed_cols + self.main_cols
    }

    /// Returns the total number of cells in the chip.
    #[must_use]
    #[inline]
    pub const fn total_number_of_cells(&self) -> usize {
        self.total_width() * self.height
    }

    /// Returns the total memory size of the chip in bytes.
    #[must_use]
    #[inline]
    pub const fn total_memory_size(&self) -> usize {
        self.total_number_of_cells() * std::mem::size_of::<F>()
    }
}

impl<F: Field> Display for ChipStatistics<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:<15} | Prep Cols = {:<5} | Main Cols = {:<5} | Rows = {:<5} | Cells = {:<10}",
            self.name,
            self.preprocessed_cols,
            self.main_cols,
            self.height,
            self.total_number_of_cells()
        )
    }
}
