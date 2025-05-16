use core::fmt::{Debug, Display};
use std::ops::Mul;

use p3_air::{PairCol, VirtualPairCol};
use p3_field::{AbstractField, Field};
use hypercube_multilinear::MleEval;

use crate::air::InteractionScope;

/// An interaction for a lookup or a permutation argument.
#[derive(Clone)]
pub struct Interaction<F: Field> {
    /// The values of the interaction.
    pub values: Vec<VirtualPairCol<F>>,
    /// The multiplicity of the interaction.
    pub multiplicity: VirtualPairCol<F>,
    /// The kind of interaction.
    pub kind: InteractionKind,
    /// The scope of the interaction.
    pub scope: InteractionScope,
}

/// The type of interaction for a lookup argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InteractionKind {
    /// Interaction with the memory table, such as read and write.
    Memory = 1,

    /// Interaction with the program table, loading an instruction at a given pc address.
    Program = 2,

    /// Interaction with instruction oracle.
    Instruction = 3,

    /// Interaction with the ALU operations.
    Alu = 4,

    /// Interaction with the byte lookup table for byte operations.
    Byte = 5,

    /// Requesting a range check for a given value and range.
    Range = 6,

    /// Interaction with the current CPU state.
    State = 7,

    /// Interaction with a syscall.
    Syscall = 8,

    /// Interaction with the global table.
    Global = 9,

    /// Interaction with the `ShaExtend` chip.
    ShaExtend = 10,

    /// Interaction with the `ShaCompress` chip.
    ShaCompress = 11,

    /// Interaction with the `Keccak` chip.
    Keccak = 12,

    /// Interaction to accumulate the global interaction digests.
    GlobalAccumulation = 13,

    /// Interaction with the `MemoryGlobalInit` chip.
    MemoryGlobalInitControl = 14,

    /// Interaction with the `MemoryGlobalFinalize` chip.
    MemoryGlobalFinalizeControl = 15,
}

impl InteractionKind {
    /// Returns all kinds of interactions.
    #[must_use]
    pub fn all_kinds() -> Vec<InteractionKind> {
        vec![
            InteractionKind::Memory,
            InteractionKind::Program,
            InteractionKind::Instruction,
            InteractionKind::Alu,
            InteractionKind::Byte,
            InteractionKind::Range,
            InteractionKind::State,
            InteractionKind::Syscall,
            InteractionKind::Global,
            InteractionKind::ShaExtend,
            InteractionKind::ShaCompress,
            InteractionKind::Keccak,
            InteractionKind::GlobalAccumulation,
            InteractionKind::MemoryGlobalInitControl,
            InteractionKind::MemoryGlobalFinalizeControl,
        ]
    }
}

impl<F: Field> Interaction<F> {
    /// Create a new interaction.
    pub const fn new(
        values: Vec<VirtualPairCol<F>>,
        multiplicity: VirtualPairCol<F>,
        kind: InteractionKind,
        scope: InteractionScope,
    ) -> Self {
        Self { values, multiplicity, kind, scope }
    }

    /// The index of the argument in the lookup table.
    pub const fn argument_index(&self) -> usize {
        self.kind as usize
    }

    /// Calculate the interactions evaluation.
    pub fn eval<Expr, Var>(
        &self,
        preprocessed: Option<&MleEval<Var>>,
        main: &MleEval<Var>,
        alpha: Expr,
        beta: &Expr,
    ) -> (Expr, Expr)
    where
        F: Into<Expr>,
        Expr: AbstractField + Mul<F, Output = Expr>,
        Var: Into<Expr> + Copy,
    {
        let mut multiplicity_eval = self.multiplicity.constant.into();
        // let mut mult_value = self.multiplicity.constant.into();
        let mut betas = beta.powers();
        for (column, weight) in self.multiplicity.column_weights.iter() {
            let weight: Expr = (*weight).into();
            match column {
                PairCol::Preprocessed(i) => {
                    multiplicity_eval += preprocessed.as_ref().unwrap()[*i].into() * weight;
                }
                PairCol::Main(i) => multiplicity_eval += main[*i].into() * weight,
            }
        }

        let mut fingerprint_eval =
            alpha + betas.next().unwrap() * Expr::from_canonical_usize(self.argument_index());
        for (element, beta_pow) in self.values.iter().zip(betas) {
            let evaluation = if let Some(preprocessed) = preprocessed {
                element.apply::<Expr, Var>(preprocessed, main)
            } else {
                element.apply::<Expr, Var>(&[], main)
            };
            fingerprint_eval += evaluation * beta_pow;
        }

        (multiplicity_eval, fingerprint_eval)
    }
}

impl<F: Field> Debug for Interaction<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interaction")
            .field("kind", &self.kind)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl Display for InteractionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InteractionKind::Memory => write!(f, "Memory"),
            InteractionKind::Program => write!(f, "Program"),
            InteractionKind::Instruction => write!(f, "Instruction"),
            InteractionKind::Alu => write!(f, "Alu"),
            InteractionKind::Byte => write!(f, "Byte"),
            InteractionKind::Range => write!(f, "Range"),
            InteractionKind::State => write!(f, "State"),
            InteractionKind::Syscall => write!(f, "Syscall"),
            InteractionKind::Global => write!(f, "Global"),
            InteractionKind::ShaExtend => write!(f, "ShaExtend"),
            InteractionKind::ShaCompress => write!(f, "ShaCompress"),
            InteractionKind::Keccak => write!(f, "Keccak"),
            InteractionKind::GlobalAccumulation => write!(f, "GlobalAccumulation"),
            InteractionKind::MemoryGlobalInitControl => write!(f, "MemoryGlobalInitControl"),
            InteractionKind::MemoryGlobalFinalizeControl => {
                write!(f, "MemoryGlobalFinalizeControl")
            }
        }
    }
}
