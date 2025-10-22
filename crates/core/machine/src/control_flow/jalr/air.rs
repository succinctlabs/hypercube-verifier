use crate::{
    adapter::{
        register::i_type::{ITypeReader, ITypeReaderInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    operations::AddOperationInput,
};
use slop_air::{Air, AirBuilder};
use slop_algebra::{AbstractField, Field};
use slop_matrix::Matrix;
use sp1_core_executor::{ByteOpcode, Opcode, CLK_INC};
use sp1_hypercube::Word;
use std::borrow::Borrow;

use crate::operations::AddOperation;

use super::{JalrChip, JalrColumns};

impl<AB> Air<AB> for JalrChip
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &JalrColumns<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        let opcode = Opcode::JALR.as_field::<AB::F>();
        let funct3 = AB::Expr::from_canonical_u8(Opcode::JALR.funct3().unwrap());
        let funct7 = AB::Expr::from_canonical_u8(Opcode::JALR.funct7().unwrap_or(0));
        let base_opcode = AB::Expr::from_canonical_u32(Opcode::JALR.base_opcode().0);
        let instr_type = AB::Expr::from_canonical_u32(Opcode::JALR.instruction_type().0 as u32);

        // We constrain `next_pc` to be the sum of `op_b` and `op_c`.
        let op_input = AddOperationInput::<AB>::new(
            local.adapter.b().map(|x| x.into()),
            local.adapter.c().map(|x| x.into()),
            local.add_operation,
            local.is_real.into(),
        );
        <AddOperation<AB::F> as SP1Operation<AB>>::eval(builder, op_input);

        let next_pc = local.add_operation.value;
        builder.assert_zero(next_pc[3]);

        // Check that the `next_pc` value is a multiple of 4.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            next_pc[0].into() * AB::F::from_canonical_u32(4).inverse(),
            AB::Expr::from_canonical_u32(14),
            AB::Expr::zero(),
            local.is_real,
        );

        // Constrain the state of the CPU.
        // The `next_pc` is constrained by the AIR.
        // The clock is incremented by `8`.
        <CPUState<AB::F> as SP1Operation<AB>>::eval(
            builder,
            CPUStateInput::new(
                local.state,
                [next_pc[0].into(), next_pc[1].into(), next_pc[2].into()],
                AB::Expr::from_canonical_u32(CLK_INC),
                local.is_real.into(),
            ),
        );

        // Constrain the program and register reads.
        <ITypeReader<AB::F> as SP1Operation<AB>>::eval(
            builder,
            ITypeReaderInput::new(
                local.state.clk_high::<AB>(),
                local.state.clk_low::<AB>(),
                local.state.pc,
                opcode.into(),
                [instr_type, base_opcode, funct3, funct7],
                local.op_a_operation.value.map(|x| x.into()),
                local.adapter,
                local.is_real.into(),
            ),
        );

        builder.when_not(local.is_real).assert_zero(local.adapter.op_a_0);

        // Verify that pc_abs + 4 is saved in op_a.
        // When op_a is set to register X0, the RISC-V spec states that the jump instruction will
        // not have a return destination address (it is effectively a GOTO command).  In this case,
        // we shouldn't verify the return address.
        // If `op_a_0` is set, the `op_a_value` will be constrained to be zero.
        let op_input = AddOperationInput::<AB>::new(
            Word([
                local.state.pc[0].into(),
                local.state.pc[1].into(),
                local.state.pc[2].into(),
                AB::Expr::zero(),
            ]),
            Word([
                AB::Expr::from_canonical_u16(4),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
            ]),
            local.op_a_operation,
            local.is_real.into() - local.adapter.op_a_0,
        );
        <AddOperation<AB::F> as SP1Operation<AB>>::eval(builder, op_input);
        builder.assert_zero(local.op_a_operation.value[3]);
        for i in 0..3 {
            builder.when(local.adapter.op_a_0).assert_zero(local.op_a_operation.value[i]);
        }
    }
}
