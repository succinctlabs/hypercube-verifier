use std::fmt::Display;

use serde::{Deserialize, Serialize};
use slop_algebra::{ExtensionField, Field};

use crate::{
    air::{AirInteraction, InteractionScope},
    ir::{FuncDecl, Shape},
};

/// A binary operation used in the constraint compiler.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BinOp {
    /// Addition
    Add,
    /// Subtraction
    Sub,
    /// Multiply
    Mul,
}

/// An operation in the IR.
///
/// Operations can appear in the AST, and are used to represent the program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpExpr<Expr, ExprExt> {
    /// An assertion that an expression is zero.
    AssertZero(Expr),
    /// A send operation.
    Send(AirInteraction<Expr>, InteractionScope),
    /// A receive operation.
    Receive(AirInteraction<Expr>, InteractionScope),
    /// A function call.
    Call(FuncDecl<Expr, ExprExt>),
    /// A binary operation.
    BinOp(BinOp, Expr, Expr, Expr),
    /// A binary operation over the extension field.
    BinOpExt(BinOp, ExprExt, ExprExt, ExprExt),
    /// A binary operation over the base field and the extension field.
    BinOpBaseExt(BinOp, ExprExt, ExprExt, Expr),
    /// A negation operation.
    Neg(Expr, Expr),
    /// A negation operation over the extension field.
    NegExt(ExprExt, ExprExt),
    /// A conversion from the base field to the extension field.
    ExtFromBase(ExprExt, Expr),
    /// An assertion that an expression over the extension field is zero.
    AssertExtZero(ExprExt),
    /// An assignment operation.
    Assign(Expr, Expr),
}

impl<F, EF> OpExpr<crate::ir::ExprRef<F>, crate::ir::ExprExtRef<EF>>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn write_interaction<Expr>(
        f: &mut std::fmt::Formatter<'_>,
        interaction: &AirInteraction<Expr>,
        scope: InteractionScope,
    ) -> std::fmt::Result
    where
        Expr: Display,
    {
        write!(
            f,
            "kind: {}, scope: {scope}, multiplicity: {}, values: [",
            interaction.kind, interaction.multiplicity
        )?;
        for (i, value) in interaction.values.iter().enumerate() {
            write!(f, "{value}")?;
            if i < interaction.values.len() - 1 {
                write!(f, ", ")?;
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl<F, EF> Display for OpExpr<crate::ir::ExprRef<F>, crate::ir::ExprExtRef<EF>>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpExpr::AssertZero(x) => write!(f, "Assert({x} == 0)"),
            OpExpr::Send(interaction, scope) => {
                write!(f, "Send(")?;
                Self::write_interaction(f, interaction, *scope)?;
                write!(f, ")")?;
                Ok(())
            }
            OpExpr::Receive(interaction, scope) => {
                write!(f, "Receive(")?;
                Self::write_interaction(f, interaction, *scope)?;
                write!(f, ")")?;
                Ok(())
            }
            OpExpr::Assign(a, b) => write!(f, "{a} = {b}"),
            OpExpr::Call(func) => {
                match func.output {
                    Shape::Unit => {}
                    _ => write!(f, "{:?} = ", func.output)?,
                }
                write!(f, "{}(", func.name)?;
                for (i, inp) in func.input.iter().enumerate() {
                    write!(f, "{inp:?}")?;
                    if i < func.input.len() - 1 {
                        write!(f, ", ")?;
                    }
                }
                write!(f, ")")?;
                Ok(())
            }
            OpExpr::BinOp(op, a, b, c) => match op {
                BinOp::Add => write!(f, "{a} = {b} + {c}"),
                BinOp::Sub => write!(f, "{a} = {b} - {c}"),
                BinOp::Mul => write!(f, "{a} = {b} * {c}"),
            },
            OpExpr::BinOpExt(op, a, b, c) => match op {
                BinOp::Add => write!(f, "{a} = {b} + {c}"),
                BinOp::Sub => write!(f, "{a} = {b} - {c}"),
                BinOp::Mul => write!(f, "{a} = {b} * {c}"),
            },
            OpExpr::BinOpBaseExt(op, a, b, c) => match op {
                BinOp::Add => write!(f, "{a} = {b} + {c}"),
                BinOp::Sub => write!(f, "{a} = {b} - {c}"),
                BinOp::Mul => write!(f, "{a} = {b} * {c}"),
            },
            OpExpr::Neg(a, b) => write!(f, "{a} = -{b}"),
            OpExpr::NegExt(a, b) => write!(f, "{a} = -{b}"),
            OpExpr::ExtFromBase(a, b) => write!(f, "{a} = {b}"),
            OpExpr::AssertExtZero(a) => write!(f, "Assert({a} == 0)"),
        }
    }
}
