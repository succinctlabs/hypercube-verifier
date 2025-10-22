use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_core_executor::{
    events::{ByteRecord, MemoryAccessPosition},
    JTypeRecord,
};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};

use sp1_hypercube::{air::SP1AirBuilder, Word};

use crate::{
    air::{MemoryAirBuilder, ProgramAirBuilder, SP1Operation, WordAirBuilder},
    memory::RegisterAccessCols,
    program::instruction::InstructionCols,
};

/// A set of columns to read operations with op_a being a register and op_b and op_c being
/// immediates.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, IntoShape, SP1OperationBuilder)]
#[repr(C)]
pub struct JTypeReader<T> {
    pub op_a: T,
    pub op_a_memory: RegisterAccessCols<T>,
    pub op_a_0: T,
    pub op_b_imm: Word<T>,
    pub op_c_imm: Word<T>,
    pub is_trusted: T,
}

impl<F: PrimeField32> JTypeReader<F> {
    pub fn populate(&mut self, blu_events: &mut impl ByteRecord, record: JTypeRecord) {
        self.op_a = F::from_canonical_u8(record.op_a);
        self.op_a_memory.populate(record.a, blu_events);
        self.op_a_0 = F::from_bool(record.op_a == 0);
        self.op_b_imm = Word::from(record.op_b);
        self.op_c_imm = Word::from(record.op_c);
        self.is_trusted = F::from_bool(!record.is_untrusted);
    }
}

impl<T> JTypeReader<T> {
    pub fn prev_a(&self) -> &Word<T> {
        &self.op_a_memory.prev_value
    }

    pub fn b(&self) -> &Word<T> {
        &self.op_b_imm
    }

    pub fn c(&self) -> &Word<T> {
        &self.op_c_imm
    }
}

impl<F: Field> JTypeReader<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder + MemoryAirBuilder + ProgramAirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: impl Into<AB::Expr> + Clone,
        instr_field_consts: [AB::Expr; 4],
        op_a_write_value: Word<impl Into<AB::Expr> + Clone>,
        cols: JTypeReader<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());
        let is_untrusted = is_real.clone() - cols.is_trusted;
        builder.assert_bool(is_untrusted.clone());
        builder.assert_bool(cols.is_trusted);

        // A real row must be executing either a trusted program or untrusted program.
        builder.assert_eq(is_untrusted.clone() + cols.is_trusted, is_real.clone());

        // If the row is running an untrusted program, the page protection checks must be on.
        let public_values = builder.extract_public_values();
        builder.when(is_untrusted.clone()).assert_one(public_values.is_untrusted_programs_enabled);

        let instruction = InstructionCols {
            opcode: opcode.clone().into(),
            op_a: cols.op_a.into(),
            op_b: cols.op_b_imm.map(Into::into),
            op_c: cols.op_c_imm.map(Into::into),
            op_a_0: cols.op_a_0.into(),
            imm_b: AB::Expr::one(),
            imm_c: AB::Expr::one(),
        };

        builder.send_program(pc, instruction.clone(), cols.is_trusted);
        builder.send_instruction_fetch(
            pc,
            instruction,
            instr_field_consts,
            [clk_high.clone(), clk_low.clone()],
            is_untrusted.clone(),
        );
        // Assert that `op_a` is zero if `op_a_0` is true.
        builder.when(cols.op_a_0).assert_word_eq(op_a_write_value.clone(), Word::zero::<AB>());
        builder.eval_register_access_write(
            clk_high.clone(),
            clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::A as u32),
            [cols.op_a.into(), AB::Expr::zero(), AB::Expr::zero()],
            cols.op_a_memory,
            op_a_write_value,
            is_real,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_op_a_immutable<AB: SP1AirBuilder + MemoryAirBuilder + ProgramAirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        pc: [AB::Var; 3],
        opcode: impl Into<AB::Expr> + Clone,
        instr_field_consts: [AB::Expr; 4],
        cols: JTypeReader<AB::Var>,
        is_real: AB::Expr,
    ) {
        Self::eval(
            builder,
            clk_high,
            clk_low,
            pc,
            opcode,
            instr_field_consts,
            cols.op_a_memory.prev_value,
            cols,
            is_real,
        );
    }
}

#[allow(clippy::too_many_arguments)]
#[derive(Debug, Clone, InputParams, InputExpr)]
pub struct JTypeReaderInput<AB: SP1AirBuilder, T: Into<AB::Expr> + Clone> {
    clk_high: AB::Expr,
    clk_low: AB::Expr,
    pc: [AB::Var; 3],
    opcode: AB::Expr,
    instr_field_consts: [AB::Expr; 4],
    op_a_write_value: Word<T>,
    cols: JTypeReader<AB::Var>,
    is_real: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for JTypeReader<AB::F> {
    type Input = JTypeReaderInput<AB, AB::Expr>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval(
            builder,
            input.clk_high,
            input.clk_low,
            input.pc,
            input.opcode,
            input.instr_field_consts,
            input.op_a_write_value,
            input.cols,
            input.is_real,
        )
    }
}
