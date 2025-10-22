use slop_air::AirBuilder;

use crate::Word;

use super::{ConstraintCompiler, ExprRef, FuncCtx, GLOBAL_AST};

/// Trait for handling operation outputs in SP1.
///
/// This trait provides methods for allocating and assigning operation outputs.
pub trait SP1OperationOutput<T> {
    /// Allocates space for the output and returns the allocated value.
    fn alloc() -> T;

    /// Replace all contents with IrVar(Output...)
    fn to_output(&self, ctx: &mut FuncCtx) -> T;

    /// Assigns the output.
    fn assign(&self, other: T);
}

impl SP1OperationOutput<()> for () {
    fn alloc() {}

    fn to_output(&self, _: &mut FuncCtx) {}

    fn assign(&self, (): Self) {
        // Does nothing
    }
}

type F = <ConstraintCompiler as AirBuilder>::F;

impl SP1OperationOutput<ExprRef<F>> for ExprRef<F> {
    fn alloc() -> Self {
        GLOBAL_AST.lock().unwrap().alloc()
    }

    fn to_output(&self, ctx: &mut FuncCtx) -> Self {
        ExprRef::<F>::output_arg(ctx)
    }

    fn assign(&self, other: Self) {
        GLOBAL_AST.lock().unwrap().assign(other, *self);
    }
}

impl<const N: usize> SP1OperationOutput<[ExprRef<F>; N]> for [ExprRef<F>; N] {
    fn alloc() -> Self {
        GLOBAL_AST.lock().unwrap().alloc_array()
    }

    fn to_output(&self, ctx: &mut FuncCtx) -> Self {
        core::array::from_fn(|_| ExprRef::<F>::output_arg(ctx))
    }

    fn assign(&self, other: Self) {
        for (i, o) in self.iter().zip(other.iter()) {
            GLOBAL_AST.lock().unwrap().assign(*i, *o);
        }
    }
}

impl SP1OperationOutput<Word<ExprRef<F>>> for Word<ExprRef<F>> {
    fn alloc() -> Self {
        let a0 = GLOBAL_AST.lock().unwrap().alloc();
        let a1 = GLOBAL_AST.lock().unwrap().alloc();
        let a2 = GLOBAL_AST.lock().unwrap().alloc();
        let a3 = GLOBAL_AST.lock().unwrap().alloc();
        Word([a0, a1, a2, a3])
    }

    fn to_output(&self, ctx: &mut FuncCtx) -> Self {
        ExprRef::<F>::output_from_struct(ctx)
    }

    fn assign(&self, other: Self) {
        for (i, o) in self.0.iter().zip(other.0.iter()) {
            GLOBAL_AST.lock().unwrap().assign(*i, *o);
        }
    }
}
