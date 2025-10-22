use alloc::format;

use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField, Field};
use sp1_primitives::{SP1ExtensionField, SP1Field};

use super::{
    Builder, Config, DslIr, ExtConst, ExtHandle, FeltHandle, FromConstant, SymbolicExt,
    SymbolicFelt, SymbolicVar, VarHandle, Variable,
};

/// A variable that represents a native field element.
///
/// Used for counters, simple loops, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Var<N> {
    pub(crate) idx: u32,
    pub(crate) handle: *mut VarHandle<N>,
}

/// A variable that represents an emulated field element.
///
/// Used to do field arithmetic for recursive verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Felt<F> {
    pub(crate) idx: u32,
    pub(crate) handle: *mut FeltHandle<F>,
}

/// A variable that represents an emulated extension field element.
///
/// Used to do extension field arithmetic for recursive verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ext<F, EF> {
    pub(crate) idx: u32,
    pub(crate) handle: *mut ExtHandle<F, EF>,
}

unsafe impl<N> Send for Var<N> {}
unsafe impl<F, EF> Send for Ext<F, EF> {}
unsafe impl<F> Send for Felt<F> {}

unsafe impl<N> Sync for Var<N> {}
unsafe impl<F, EF> Sync for Ext<F, EF> {}
unsafe impl<F> Sync for Felt<F> {}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Witness<C: Config> {
    pub vars: Vec<C::N>,
    pub felts: Vec<SP1Field>,
    pub exts: Vec<SP1ExtensionField>,
    pub vkey_hash: C::N,
    pub committed_values_digest: C::N,
    pub exit_code: C::N,
    pub proof_nonce: C::N,
    pub vk_root: C::N,
}

impl<C: Config> Witness<C> {
    pub fn write_vkey_hash(&mut self, vkey_hash: C::N) {
        self.vars.push(vkey_hash);
        self.vkey_hash = vkey_hash;
    }

    pub fn write_committed_values_digest(&mut self, committed_values_digest: C::N) {
        self.vars.push(committed_values_digest);
        self.committed_values_digest = committed_values_digest
    }

    pub fn write_exit_code(&mut self, exit_code: C::N) {
        self.vars.push(exit_code);
        self.exit_code = exit_code;
    }

    pub fn write_vk_root(&mut self, vk_root: C::N) {
        self.vars.push(vk_root);
        self.vk_root = vk_root;
    }

    pub fn write_proof_nonce(&mut self, proof_nonce: C::N) {
        self.vars.push(proof_nonce);
        self.proof_nonce = proof_nonce;
    }
}

impl<N> Var<N> {
    pub(crate) const fn new(idx: u32, handle: *mut VarHandle<N>) -> Self {
        Self { idx, handle }
    }

    pub(crate) fn id(&self) -> String {
        format!("var{}", self.idx)
    }
}

impl<F> Felt<F> {
    pub(crate) const fn new(id: u32, handle: *mut FeltHandle<F>) -> Self {
        Self { idx: id, handle }
    }

    pub(crate) fn id(&self) -> String {
        format!("felt{}", self.idx)
    }

    pub(crate) fn inverse(&self) -> SymbolicFelt<F>
    where
        F: Field,
    {
        SymbolicFelt::<F>::one() / *self
    }
}

impl<F, EF> Ext<F, EF> {
    pub(crate) const fn new(id: u32, handle: *mut ExtHandle<F, EF>) -> Self {
        Self { idx: id, handle }
    }

    pub(crate) fn id(&self) -> String {
        format!("ext{}", self.idx)
    }
}

impl<C: Config> Variable<C> for Var<C::N> {
    type Expression = SymbolicVar<C::N>;

    fn uninit(builder: &mut Builder<C>) -> Self {
        let id = builder.variable_count();
        let var = Var::new(id, builder.var_handle.as_mut());
        builder.inner.get_mut().variable_count += 1;
        var
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        match src {
            SymbolicVar::Const(src) => {
                builder.push_op(DslIr::ImmV(*self, src));
            }
            SymbolicVar::Val(src) => {
                builder.push_op(DslIr::AddVI(*self, src, C::N::zero()));
            }
        }
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs)) => {
                assert_eq!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertEqVI(rhs, lhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs)) => {
                builder.push_traced_op(DslIr::AssertEqVI(lhs, rhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertEqV(lhs, rhs));
            }
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs)) => {
                assert_ne!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertNeVI(rhs, lhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs)) => {
                builder.push_traced_op(DslIr::AssertNeVI(lhs, rhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertNeV(lhs, rhs));
            }
        }
    }
}

impl<C: Config> Variable<C> for Felt<SP1Field> {
    type Expression = SymbolicFelt<SP1Field>;

    fn uninit(builder: &mut Builder<C>) -> Self {
        let idx = builder.variable_count();
        let felt = Felt::<SP1Field>::new(idx, builder.felt_handle.as_mut());
        builder.inner.get_mut().variable_count += 1;
        felt
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        match src {
            SymbolicFelt::Const(src) => {
                builder.push_op(DslIr::ImmF(*self, src));
            }
            SymbolicFelt::Val(src) => {
                builder.push_op(DslIr::AddFI(*self, src, SP1Field::zero()));
            }
        }
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicFelt::Const(lhs), SymbolicFelt::Const(rhs)) => {
                assert_eq!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicFelt::Const(lhs), SymbolicFelt::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertEqFI(rhs, lhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Const(rhs)) => {
                builder.push_traced_op(DslIr::AssertEqFI(lhs, rhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertEqF(lhs, rhs));
            }
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicFelt::Const(lhs), SymbolicFelt::Const(rhs)) => {
                assert_ne!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicFelt::Const(lhs), SymbolicFelt::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertNeFI(rhs, lhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Const(rhs)) => {
                builder.push_traced_op(DslIr::AssertNeFI(lhs, rhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertNeF(lhs, rhs));
            }
        }
    }
}

impl<C: Config> Variable<C> for Ext<SP1Field, SP1ExtensionField> {
    type Expression = SymbolicExt<SP1Field, SP1ExtensionField>;

    fn uninit(builder: &mut Builder<C>) -> Self {
        let idx = builder.variable_count();
        let ext = Ext::<SP1Field, SP1ExtensionField>::new(idx, builder.ext_handle.as_mut());
        builder.inner.get_mut().variable_count += 1;
        ext
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        match src {
            SymbolicExt::Const(src) => {
                builder.push_op(DslIr::ImmE(*self, src));
            }
            SymbolicExt::Base(src) => match src {
                SymbolicFelt::Const(src) => {
                    builder.push_op(DslIr::ImmE(*self, SP1ExtensionField::from_base(src)));
                }
                SymbolicFelt::Val(src) => {
                    builder.push_op(DslIr::AddEFFI(*self, src, SP1ExtensionField::zero()));
                }
            },
            SymbolicExt::Val(src) => {
                builder.push_op(DslIr::AddEI(*self, src, SP1ExtensionField::zero()));
            }
        }
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicExt::Const(lhs), SymbolicExt::Const(rhs)) => {
                assert_eq!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicExt::Const(lhs), SymbolicExt::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertEqEI(rhs, lhs));
            }
            (SymbolicExt::Const(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push_traced_op(DslIr::AssertEqEI(rhs_value, lhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Const(rhs)) => {
                builder.push_traced_op(DslIr::AssertEqEI(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertEqE(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push_traced_op(DslIr::AssertEqE(lhs, rhs_value));
            }
            (lhs, rhs) => {
                let lhs_value = Self::uninit(builder);
                lhs_value.assign(lhs, builder);
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push_traced_op(DslIr::AssertEqE(lhs_value, rhs_value));
            }
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicExt::Const(lhs), SymbolicExt::Const(rhs)) => {
                assert_ne!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicExt::Const(lhs), SymbolicExt::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertNeEI(rhs, lhs));
            }
            (SymbolicExt::Const(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push_traced_op(DslIr::AssertNeEI(rhs_value, lhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Const(rhs)) => {
                builder.push_traced_op(DslIr::AssertNeEI(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Val(rhs)) => {
                builder.push_traced_op(DslIr::AssertNeE(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push_traced_op(DslIr::AssertNeE(lhs, rhs_value));
            }
            (lhs, rhs) => {
                let lhs_value = Self::uninit(builder);
                lhs_value.assign(lhs, builder);
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push_traced_op(DslIr::AssertNeE(lhs_value, rhs_value));
            }
        }
    }
}

impl<C: Config> FromConstant<C> for Var<C::N> {
    type Constant = C::N;

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        builder.eval(value)
    }
}

impl<C: Config> FromConstant<C> for Felt<SP1Field> {
    type Constant = SP1Field;

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        builder.eval(value)
    }
}

impl<C: Config> FromConstant<C> for Ext<SP1Field, SP1ExtensionField> {
    type Constant = SP1ExtensionField;

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        builder.eval(value.cons())
    }
}
