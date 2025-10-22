use slop_algebra::PrimeField;

mod arithmetic;
mod bits;
mod builder;
mod instructions;
mod iter;
mod symbolic;
mod types;
mod utils;
mod var;

pub(crate) use arithmetic::*;
pub use builder::*;
pub use instructions::*;
pub use iter::*;
pub use symbolic::*;
pub use types::*;
pub use var::*;

pub trait Config: Clone + Default + std::fmt::Debug {
    type N: PrimeField;

    // This function is called on the initialization of the builder.
    // Currently, this is used to save Poseidon2 round constants for `WrapConfig`.
    fn initialize(_: &mut Builder<Self>) {}
}
