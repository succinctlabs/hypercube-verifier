use slop_alloc::Buffer;
use slop_multilinear::{Mle, MleEval, Point};
use slop_tensor::Tensor;
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::ir::{Ext, Felt, SymbolicExt, SymbolicFelt};

use crate::CircuitConfig;

pub(crate) trait IntoSymbolic<C: CircuitConfig> {
    type Output;

    fn as_symbolic(&self) -> Self::Output;
}

impl<C: CircuitConfig> IntoSymbolic<C> for Felt<SP1Field> {
    type Output = SymbolicFelt<SP1Field>;

    fn as_symbolic(&self) -> Self::Output {
        SymbolicFelt::from(*self)
    }
}

impl<C: CircuitConfig> IntoSymbolic<C> for Ext<SP1Field, SP1ExtensionField> {
    type Output = SymbolicExt<SP1Field, SP1ExtensionField>;

    fn as_symbolic(&self) -> Self::Output {
        SymbolicExt::from(*self)
    }
}

impl<C: CircuitConfig, T: IntoSymbolic<C>> IntoSymbolic<C> for Point<T> {
    type Output = Point<T::Output>;

    fn as_symbolic(&self) -> Self::Output {
        Point::from(self.values().as_slice().iter().map(|x| x.as_symbolic()).collect::<Vec<_>>())
    }
}

impl<C: CircuitConfig, T: IntoSymbolic<C>> IntoSymbolic<C> for Vec<T> {
    type Output = Vec<T::Output>;

    fn as_symbolic(&self) -> Self::Output {
        let mut ret = Vec::with_capacity(self.len());
        for x in self.iter() {
            ret.push(x.as_symbolic());
        }
        ret
    }
}

impl<C: CircuitConfig, T: IntoSymbolic<C>> IntoSymbolic<C> for Tensor<T> {
    type Output = Tensor<T::Output>;

    fn as_symbolic(&self) -> Self::Output {
        let storage = self.storage.iter().map(|x| x.as_symbolic()).collect::<Buffer<_>>();
        let dimensions = self.dimensions.clone();
        Tensor { storage, dimensions }
    }
}

impl<C: CircuitConfig, T: IntoSymbolic<C>> IntoSymbolic<C> for Mle<T> {
    type Output = Mle<T::Output>;

    fn as_symbolic(&self) -> Self::Output {
        Mle::new(self.guts().as_symbolic())
    }
}

impl<C: CircuitConfig, T: IntoSymbolic<C>> IntoSymbolic<C> for MleEval<T> {
    type Output = MleEval<T::Output>;

    fn as_symbolic(&self) -> Self::Output {
        MleEval::new(self.evaluations().as_symbolic())
    }
}
