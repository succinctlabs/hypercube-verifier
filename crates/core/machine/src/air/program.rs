use slop_air::AirBuilder;
use sp1_hypercube::{
    air::{AirInteraction, BaseAirBuilder, InteractionScope},
    InteractionKind,
};

use crate::program::instruction::InstructionCols;

/// A trait which contains methods related to program interactions in an AIR.
pub trait ProgramAirBuilder: BaseAirBuilder {
    /// Sends an instruction.
    fn send_program(
        &mut self,
        pc: [impl Into<Self::Expr>; 3],
        instruction: InstructionCols<impl Into<Self::Expr>>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = pc
            .map(Into::into)
            .into_iter()
            .chain(instruction.into_iter().map(|x| x.into()))
            .collect();
        self.send(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::Program),
            InteractionScope::Local,
        );
    }

    /// Receives an instruction.
    fn receive_program(
        &mut self,
        pc: [impl Into<Self::Expr>; 3],
        instruction: InstructionCols<impl Into<Self::Expr>>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values: Vec<<Self as AirBuilder>::Expr> = pc
            .map(Into::into)
            .into_iter()
            .chain(instruction.into_iter().map(|x| x.into()))
            .collect();
        self.receive(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::Program),
            InteractionScope::Local,
        );
    }

    fn send_instruction_fetch(
        &mut self,
        pc: [impl Into<Self::Expr>; 3],
        instruction: InstructionCols<impl Into<Self::Expr>>,
        instruction_field_consts: [Self::Expr; 4],
        clk: [impl Into<Self::Expr>; 2],
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = pc
            .map(Into::into)
            .into_iter()
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(instruction_field_consts)
            .chain(clk.map(Into::into))
            .collect();

        self.send(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::InstructionFetch),
            InteractionScope::Local,
        );
    }

    fn receive_instruction_fetch(
        &mut self,
        pc: [impl Into<Self::Expr>; 3],
        instruction: InstructionCols<impl Into<Self::Expr>>,
        instruction_field_consts: [Self::Expr; 4],
        clk: [impl Into<Self::Expr>; 2],
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values: Vec<<Self as AirBuilder>::Expr> = pc
            .map(Into::into)
            .into_iter()
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(instruction_field_consts)
            .chain(clk.map(Into::into))
            .collect();

        self.receive(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::InstructionFetch),
            InteractionScope::Local,
        );
    }

    fn send_instruction_decode(
        &mut self,
        word: [impl Into<Self::Expr>; 2],
        instruction: InstructionCols<impl Into<Self::Expr>>,
        instruction_field_consts: [Self::Expr; 4],
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = word
            .map(Into::into)
            .into_iter()
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(instruction_field_consts)
            .collect();

        self.send(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::InstructionDecode),
            InteractionScope::Local,
        );
    }

    fn receive_instruction_decode(
        &mut self,
        word: [impl Into<Self::Expr>; 2],
        instruction: InstructionCols<impl Into<Self::Expr>>,
        instruction_field_consts: [Self::Expr; 4],
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = word
            .map(Into::into)
            .into_iter()
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(instruction_field_consts)
            .collect();
        self.receive(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::InstructionDecode),
            InteractionScope::Local,
        );
    }
}
