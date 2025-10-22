use std::ops::{Add, Mul, MulAssign, Sub};

use slop_air::AirBuilder;
use slop_algebra::{AbstractField, ExtensionField, Field};
use slop_uni_stark::SymbolicAirBuilder;
use sp1_hypercube::{
    air::SP1AirBuilder, ConstraintSumcheckFolder, DebugConstraintBuilder,
    GenericVerifierConstraintFolder, InteractionBuilder,
};

use crate::{
    adapter::{
        register::{
            alu_type::ALUTypeReader,
            i_type::{ITypeReader, ITypeReaderImmutable},
            j_type::JTypeReader,
            r_type::{RTypeReader, RTypeReaderImmutable},
        },
        state::CPUState,
    },
    operations::{
        AddOperation, AddrAddOperation, AddressOperation, AddwOperation, BitwiseOperation,
        BitwiseU16Operation, IsEqualWordOperation, IsZeroOperation, IsZeroWordOperation,
        LtOperationSigned, LtOperationUnsigned, MulOperation, SubOperation, SubwOperation,
        U16CompareOperation, U16MSBOperation, U16toU8OperationSafe, U16toU8OperationUnsafe,
    },
};

type F<AB> = <AB as AirBuilder>::F;

pub trait SP1CoreOperationBuilder:
    SP1AirBuilder
    + SP1OperationBuilder<AddOperation<F<Self>>>
    + SP1OperationBuilder<U16toU8OperationSafe>
    + SP1OperationBuilder<U16toU8OperationUnsafe>
    + SP1OperationBuilder<IsZeroOperation<F<Self>>>
    + SP1OperationBuilder<IsZeroWordOperation<F<Self>>>
    + SP1OperationBuilder<IsEqualWordOperation<F<Self>>>
    + SP1OperationBuilder<BitwiseOperation<F<Self>>>
    + SP1OperationBuilder<BitwiseU16Operation<F<Self>>>
    + SP1OperationBuilder<RTypeReader<F<Self>>>
    + SP1OperationBuilder<CPUState<F<Self>>>
    + SP1OperationBuilder<RTypeReaderImmutable>
    + SP1OperationBuilder<ALUTypeReader<F<Self>>>
    + SP1OperationBuilder<CPUState<F<Self>>>
    + SP1OperationBuilder<SubOperation<F<Self>>>
    + SP1OperationBuilder<U16CompareOperation<F<Self>>>
    + SP1OperationBuilder<U16MSBOperation<F<Self>>>
    + SP1OperationBuilder<LtOperationUnsigned<F<Self>>>
    + SP1OperationBuilder<LtOperationSigned<F<Self>>>
    + SP1OperationBuilder<CPUState<F<Self>>>
    + SP1OperationBuilder<MulOperation<F<Self>>>
    + SP1OperationBuilder<ITypeReader<F<Self>>>
    + SP1OperationBuilder<AddwOperation<F<Self>>>
    + SP1OperationBuilder<SubwOperation<F<Self>>>
    + SP1OperationBuilder<JTypeReader<F<Self>>>
    + SP1OperationBuilder<ITypeReaderImmutable>
    + SP1OperationBuilder<AddrAddOperation<F<Self>>>
    + SP1OperationBuilder<AddressOperation<F<Self>>>
{
}

impl<AB> SP1CoreOperationBuilder for AB where
    AB: SP1AirBuilder
        + SP1OperationBuilder<AddOperation<F<Self>>>
        + SP1OperationBuilder<U16toU8OperationSafe>
        + SP1OperationBuilder<U16toU8OperationUnsafe>
        + SP1OperationBuilder<IsZeroOperation<F<Self>>>
        + SP1OperationBuilder<IsZeroWordOperation<F<Self>>>
        + SP1OperationBuilder<IsEqualWordOperation<F<Self>>>
        + SP1OperationBuilder<BitwiseOperation<F<Self>>>
        + SP1OperationBuilder<BitwiseU16Operation<F<Self>>>
        + SP1OperationBuilder<RTypeReaderImmutable>
        + SP1OperationBuilder<ALUTypeReader<F<Self>>>
        + SP1OperationBuilder<RTypeReader<F<Self>>>
        + SP1OperationBuilder<CPUState<F<Self>>>
        + SP1OperationBuilder<SubOperation<F<Self>>>
        + SP1OperationBuilder<U16CompareOperation<F<Self>>>
        + SP1OperationBuilder<U16MSBOperation<F<Self>>>
        + SP1OperationBuilder<LtOperationUnsigned<F<Self>>>
        + SP1OperationBuilder<LtOperationSigned<F<Self>>>
        + SP1OperationBuilder<MulOperation<F<Self>>>
        + SP1OperationBuilder<ITypeReader<F<Self>>>
        + SP1OperationBuilder<AddwOperation<F<Self>>>
        + SP1OperationBuilder<SubwOperation<F<Self>>>
        + SP1OperationBuilder<JTypeReader<F<Self>>>
        + SP1OperationBuilder<ITypeReaderImmutable>
        + SP1OperationBuilder<AddrAddOperation<F<Self>>>
        + SP1OperationBuilder<AddressOperation<F<Self>>>
{
}

/// A trait for operations that can be lowered to constraints in an AIR.
pub trait SP1Operation<AB: SP1AirBuilder> {
    /// The input arguments to the operation.
    type Input;

    /// The output of the operation.
    type Output;

    /// The underlying constraints corresponding to the operation.
    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output;

    /// Evaluate the operation on the given inputs.
    fn eval(builder: &mut AB, input: Self::Input) -> Self::Output
    where
        Self: Sized,
        AB: SP1OperationBuilder<Self>,
    {
        builder.eval_operation(input)
    }
}

/// A trait for handling an SP1 operation.
///
/// This trait enables an AIR builder to evaluate an operation in a specific way, such as emitting
/// code or changing state while keeping the semantic meaning of the operation being separated from
/// arbitrary constraints.
pub trait SP1OperationBuilder<O: SP1Operation<Self>>: SP1AirBuilder {
    fn eval_operation(&mut self, input: O::Input) -> O::Output;
}

/// A trait for demarking a builder that lowers every operation to it's underlying constraints.
pub trait TrivialOperationBuilder: SP1AirBuilder {}

impl<AB: TrivialOperationBuilder, O: SP1Operation<AB>> SP1OperationBuilder<O> for AB {
    fn eval_operation(&mut self, input: O::Input) -> O::Output {
        O::lower(self, input)
    }
}

impl<F: Field> TrivialOperationBuilder for InteractionBuilder<F> {}

impl<F: Field> TrivialOperationBuilder for SymbolicAirBuilder<F> {}

impl<F: Field, EF: ExtensionField<F>> TrivialOperationBuilder
    for DebugConstraintBuilder<'_, F, EF>
{
}

impl<
        'a,
        F: Field,
        K: Field + From<F> + Add<F, Output = K> + Sub<F, Output = K> + Mul<F, Output = K>,
        EF: Field + Mul<K, Output = EF>,
    > TrivialOperationBuilder for ConstraintSumcheckFolder<'a, F, K, EF>
{
}

impl<'a, F, EF, PubVar, Var, Expr> TrivialOperationBuilder
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: AbstractField<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
}
