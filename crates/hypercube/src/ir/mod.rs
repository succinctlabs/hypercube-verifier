//! Base types, enums, and structs for the constraint compiler.

// `Vec<(String, Shape<ExprRef<F>, ExprExtRef<EF>>)>` is not a complex type IMO.
#![allow(clippy::type_complexity)]
// https://rust-lang.github.io/rust-clippy/master/index.html#format_push_string
// Forces us to use `write!` instead of `String::push_str`, bad because we need to ignore the error
// from `write!`. See "Known Problems" from the link above.
#![allow(clippy::format_push_string)]

mod ast;
mod compiler;
mod conversions;
mod expr;
mod expr_impl;
mod func;
mod lean;
mod op;
mod output;
mod shape;
mod var;

pub use ast::*;
pub use compiler::*;
pub use expr::*;
pub use func::*;
pub use op::*;
pub use output::*;
pub use shape::*;
pub use var::*;
