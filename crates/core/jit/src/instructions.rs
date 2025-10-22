use crate::{RiscOperand, RiscRegister};

/// An ALU instruction backend for a specific target architecture.
///
/// This trait is implemented for each target architecture supported by the JIT transpiler.
pub trait ComputeInstructions: Sized {
    /// Add the values of two registers together, using 64bit arithmetic.
    ///
    /// add: rd = rs1 + rs2
    fn add(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Subtract the values of two registers from each other, using 64bit arithmetic.
    ///
    /// sub: rd = rs1 - rs2
    fn sub(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Bitwise XOR the values of two registers together.
    ///
    /// xor: rd = rs1 ^ rs2
    fn xor(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Bitwise OR the values of two registers together.
    ///
    /// or: rd = rs1 | rs2
    fn or(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Bitwise AND the values of two registers together.
    ///
    /// and: rd = rs1 & rs2
    fn and(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Shift the values of two registers left by the amount specified by the second register.
    ///
    /// sll: rd = rs1 << rs2
    fn sll(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Shift the values of two registers right by the amount specified by the second register.
    ///
    /// srl: rd = rs1 >> rs2
    fn srl(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Shift the values of two registers right by the amount specified by the second register,
    /// using arithmetic right shift.
    ///
    /// sra: rd = rs1 >> rs2
    fn sra(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Set if less than (signed comparison).
    ///
    /// slt: rd = (rs1 < rs2) ? 1 : 0
    fn slt(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Set if less than (unsigned comparison).
    ///
    /// sltu: rd = (rs1 < rs2) ? 1 : 0
    fn sltu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Multiply the values of two registers together, using 64bit arithmetic.
    ///
    /// mul: rd = rs1 * rs2
    fn mul(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Multiply the values of two registers together and return the high 64 bits (signed).
    ///
    /// mulh: rd = (rs1 * rs2) >> 64 (signed)
    fn mulh(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Multiply the values of two registers together and return the high 64 bits (unsigned).
    ///
    /// mulhu: rd = (rs1 * rs2) >> 64 (unsigned)
    fn mulhu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Multiply signed rs1 by unsigned rs2 and return the high 64 bits.
    ///
    /// mulhsu: rd = (rs1 * rs2) >> 64 (signed * unsigned)
    fn mulhsu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Divide the values of two registers (signed).
    ///
    /// div: rd = rs2 == 0 ? 0 : rs1 / rs2
    fn div(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Divide the values of two registers (unsigned).
    ///
    /// divu: rd = rs2 == 0 ? 0 : rs1 / rs2
    fn divu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Remainder of two registers (signed).
    ///
    /// rem: rd = rs2 == 0 ? 0 : rs1 % rs2
    fn rem(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Remainder of two registers (unsigned).
    ///
    /// remu: rd = rs2 == 0 ? 0 : rs1 % rs2
    fn remu(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Add the values of two registers together, using 64bit arithmetic, but only keeping lower 32
    /// bits.
    ///
    /// addw: rd = (rs1 + rs2) & 0xFFFFFFFF (sign-extended to 64-bit)
    fn addw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Subtract the values of two registers, using 64bit arithmetic, but only keeping lower 32
    /// bits.
    ///
    /// subw: rd = (rs1 - rs2) & 0xFFFFFFFF (sign-extended to 64-bit)
    fn subw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Shift the values of two registers left by the amount specified by the second register
    /// (32-bit).
    ///
    /// sllw: rd = (rs1 << (rs2 & 0x1F)) & 0xFFFFFFFF (sign-extended to 64-bit)
    fn sllw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Shift the values of two registers right by the amount specified by the second register
    /// (32-bit logical).
    ///
    /// srlw: rd = ((rs1 & 0xFFFFFFFF) >> (rs2 & 0x1F)) (sign-extended to 64-bit)
    fn srlw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Shift the values of two registers right by the amount specified by the second register
    /// (32-bit arithmetic).
    ///
    /// sraw: rd = ((rs1 as i32) >> (rs2 & 0x1F)) (sign-extended to 64-bit)
    fn sraw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Multiply the values of two registers together, using 32bit arithmetic (sign-extended to
    /// 64-bit).
    ///
    /// mulw: rd = (rs1 * rs2) & 0xFFFFFFFF (sign-extended to 64-bit)
    fn mulw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Divide the values of two registers together, using 32bit arithmetic (sign-extended to
    /// 64-bit).
    ///
    /// divw: rd = rs2 == 0 ? 0xFFFFFFFF : (rs1 as i32) / (rs2 as i32) (sign-extended to 64-bit)
    fn divw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Divide the values of two registers, unsigned 32bit (sign-extended to 64-bit).
    ///
    /// divuw: rd = rs2 == 0 ? 0xFFFFFFFF : (rs1 as u32) / (rs2 as u32) (sign-extended to 64-bit)
    fn divuw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Remainder the values of two registers together, using 32bit arithmetic (sign-extended to
    /// 64-bit).
    ///
    /// remw: rd = rs2 == 0 ? rs1 : (rs1 as i32) % (rs2 as i32) (sign-extended to 64-bit)
    fn remw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Remainder the values of two registers, unsigned 32bit (sign-extended to 64-bit).
    ///
    /// remuw: rd = rs2 == 0 ? rs1 : (rs1 as u32) % (rs2 as u32) (sign-extended to 64-bit)
    fn remuw(&mut self, rd: RiscRegister, rs1: RiscOperand, rs2: RiscOperand);

    /// Advance to the next pc, storing the current (pc + imm) in a register.
    ///
    /// auipc: rd = pc + imm, pc = pc + 4
    fn auipc(&mut self, rd: RiscRegister, imm: u64);

    /// Load upper immediate into a register.
    ///
    /// lui: rd = imm << 12
    fn lui(&mut self, rd: RiscRegister, imm: u64);
}

pub trait ControlFlowInstructions: Sized {
    /// Compare the values of two registers, and jump to an address if they are equal.
    ///
    /// beq: pc = pc + ((rs1 == rs2) ? imm : 4)
    ///
    /// NOTE: During transpilatiom, this method will emit the PC bumps for you,
    /// typically however, you will want to explicty call [`SP1RiscvTranspiler::set_pc`] at the end
    /// of each instruction.
    fn beq(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64);

    /// Compare the values of two registers, and jump to an address if they are not equal.
    ///
    /// bne: pc = pc + ((rs1 != rs2) ? imm : 4)
    ///
    /// NOTE: During transpilatiom, this method will emit the PC bumps for you,
    /// typically however, you will want to explicty call [`SP1RiscvTranspiler::set_pc`] at the end
    /// of each instruction.
    fn bne(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64);

    /// Compare the values of two registers, and jump to an address if the first is less than the
    /// second.
    ///
    /// blt: pc = pc + ((rs1 < rs2) ? imm : 4)
    ///
    /// NOTE: During transpilatiom, this method will emit the PC bumps for you,
    /// typically however, you will want to explicty call [`SP1RiscvTranspiler::set_pc`] at the end
    /// of each instruction.
    fn blt(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64);

    /// Compare the values of two registers, and jump to an address if the first is greater than or
    /// equal to the second.
    ///
    /// bge: pc = pc + ((rs1 >= rs2) ? imm : 4)
    ///
    /// NOTE: During transpilatiom, this method will emit the PC bumps for you,
    /// typically however, you will want to explicty call [`SP1RiscvTranspiler::set_pc`] at the end
    /// of each instruction.
    fn bge(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64);

    /// Compare the values of two registers, and jump to an address if the first is less than the
    /// second, unsigned.
    ///
    /// bltu: pc = pc + ((rs1 < rs2) ? imm : 4)
    ///
    /// NOTE: During transpilatiom, this method will emit the PC bumps for you,
    /// typically however, you will want to explicty call [`SP1RiscvTranspiler::set_pc`] at the end
    /// of each instruction.
    fn bltu(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64);

    /// Compare the values of two registers, and jump to an address if the first is greater than or
    /// equal to the second, unsigned.
    ///
    /// bgeu: pc = pc + ((rs1 >= rs2) ? imm : 4)
    ///
    /// NOTE: During transpilatiom, this method will emit the PC bumps for you,
    /// typically however, you will want to explicty call [`SP1RiscvTranspiler::set_pc`] at the end
    /// of each instruction.
    fn bgeu(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64);

    /// Jump to an address.
    ///
    /// jal: rd = pc + 4, pc = pc + imm
    ///
    /// NOTE: During transpilatiom, this method will emit the PC bumps for you,
    /// typically however, you will want to explicty call [`SP1RiscvTranspiler::set_pc`] at the end
    /// of each instruction.
    fn jal(&mut self, rd: RiscRegister, imm: u64);

    /// Jump to an address, and return to the previous address.
    ///
    /// jalr: rd = pc + 4, pc = rs1 + imm
    ///
    /// NOTE: During transpilatiom, this method will emit the PC bumps for you,
    /// typically however, you will want to explicty call [`SP1RiscvTranspiler::set_pc`] at the end
    /// of each instruction.
    fn jalr(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64);
}

pub trait MemoryInstructions: Sized {
    /// Load a byte from memory into a register.
    ///
    /// lb: rd = m8(rs1 + imm)
    fn lb(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64);

    /// Load a half word from memory into a register.
    ///
    /// lh: rd = m16(rs1 + imm)
    fn lh(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64);

    /// Load a word from memory into a register.
    ///
    /// lw: rd = m32(rs1 + imm)
    fn lw(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64);

    /// Load a byte from memory into a register, zero extended.
    ///
    /// lbu: rd = zx(m8(rs1 + imm))
    fn lbu(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64);

    /// Load a half word from memory into a register, zero extended.    
    ///
    /// lhu: rd = zx(m16(rs1 + imm))
    fn lhu(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64);

    /// Load a double word from memory into a register.
    ///
    /// ldu: rd = m64(rs1 + imm)
    fn ld(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64);

    /// Load a word from memory into a register, zero extended.
    ///
    /// lwu: rd = zx(m32(rs1 + imm))
    fn lwu(&mut self, rd: RiscRegister, rs1: RiscRegister, imm: u64);

    /// Store a byte into memory.
    ///
    /// sb: m8(rs1 + imm) = rs2[7:0]
    fn sb(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64);

    /// Store a half word into memory.
    ///
    /// sh: m16(rs1 + imm) = rs2[15:0]
    fn sh(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64);

    /// Store a word into memory.
    ///
    /// sw: m32(rs1 + imm) = rs2[31:0]
    fn sw(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64);

    /// Store a double word into memory.
    ///
    /// sd: m64(rs1 + imm) = rs2[63:0]
    fn sd(&mut self, rs1: RiscRegister, rs2: RiscRegister, imm: u64);
}

pub trait SystemInstructions: Sized {
    /// Transfer control to the operating system.
    fn ecall(&mut self);

    fn unimp(&mut self);
}
