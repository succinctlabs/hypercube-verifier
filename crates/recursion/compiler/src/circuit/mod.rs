mod builder;
mod compiler;
mod config;

pub use builder::*;
pub use compiler::*;
pub use config::*;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use sp1_primitives::SP1DiffusionMatrix;

    // use sp1_core_machine::utils::run_test_machine;
    // use sp1_recursion_core::{machine::RecursionAir, Runtime, RuntimeError};
    use sp1_hypercube::inner_perm;
    use sp1_primitives::SP1Field;
    use sp1_recursion_executor::{Executor, RuntimeError};

    use crate::{
        circuit::{AsmBuilder, AsmCompiler, CircuitV2Builder},
        ir::*,
    };

    type F = SP1Field;
    type EF = BinomialExtensionField<SP1Field, 4>;

    #[test]
    fn test_io() {
        let mut builder = AsmBuilder::default();

        let felts = builder.hint_felts_v2(3);
        assert_eq!(felts.len(), 3);
        let sum: Felt<_> = builder.eval(felts[0] + felts[1]);
        builder.assert_felt_eq(sum, felts[2]);

        let exts = builder.hint_exts_v2(3);
        assert_eq!(exts.len(), 3);
        let sum: Ext<_, _> = builder.eval(exts[0] + exts[1]);
        builder.assert_ext_ne(sum, exts[2]);

        let x = builder.hint_ext_v2();
        builder.assert_ext_eq(x, exts[0] + felts[0]);

        let y = builder.hint_felt_v2();
        let zero: Felt<_> = builder.constant(F::zero());
        builder.assert_felt_eq(y, zero);

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(program.clone(), inner_perm());
        executor.witness_stream = [
            vec![F::one().into(), F::one().into(), F::two().into()],
            vec![F::zero().into(), F::one().into(), F::two().into()],
            vec![F::one().into()],
            vec![F::zero().into()],
        ]
        .concat()
        .into();
        executor.run().unwrap();

        // let machine = A::compress_machine(SC::new());

        // let (pk, vk) = machine.setup(&program);
        // let result =
        //     run_test_machine(vec![executor.record], machine, pk, vk.clone()).expect("should
        // verify");

        // tracing::info!("num shard proofs: {}", result.shard_proofs.len());
    }

    #[test]
    #[allow(clippy::uninlined_format_args)]
    fn test_empty_witness_stream() {
        let mut builder = AsmBuilder::default();

        let felts = builder.hint_felts_v2(3);
        assert_eq!(felts.len(), 3);
        let sum: Felt<_> = builder.eval(felts[0] + felts[1]);
        builder.assert_felt_eq(sum, felts[2]);

        let exts = builder.hint_exts_v2(3);
        assert_eq!(exts.len(), 3);
        let sum: Ext<_, _> = builder.eval(exts[0] + exts[1]);
        builder.assert_ext_ne(sum, exts[2]);

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(program.clone(), inner_perm());
        executor.witness_stream =
            [vec![F::one().into(), F::one().into(), F::two().into()]].concat().into();

        match executor.run() {
            Err(RuntimeError::EmptyWitnessStream) => (),
            Ok(_) => panic!("should not succeed"),
            Err(x) => panic!("should not yield error variant: {x}"),
        }
    }
}
