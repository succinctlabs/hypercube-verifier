//! Opcodes for the SP1 zkVM.

use std::fmt::Display;

use deepsize2::DeepSizeOf;
use enum_map::Enum;
use rrs_lib::instruction_formats::{
    OPCODE_AUIPC, OPCODE_BRANCH, OPCODE_JAL, OPCODE_JALR, OPCODE_LOAD, OPCODE_LUI, OPCODE_OP,
    OPCODE_OP_32, OPCODE_OP_IMM, OPCODE_OP_IMM_32, OPCODE_STORE, OPCODE_SYSTEM,
};
use serde::{Deserialize, Serialize};
use slop_algebra::Field;

use crate::InstructionType;

/// An opcode (short for "operation code") specifies the operation to be performed by the processor.
///
/// In the context of the RISC-V ISA, an opcode specifies which operation (i.e., addition,
/// subtraction, multiplication, etc.) to perform on up to three operands such as registers,
/// immediates, or memory addresses.
///
/// While the SP1 zkVM targets the RISC-V ISA, it uses a custom instruction encoding that uses
/// a different set of opcodes. The main difference is that the SP1 zkVM encodes register
/// operations and immediate operations as the same opcode. For example, the RISC-V opcodes ADD and
/// ADDI both become ADD inside the SP1 zkVM. We utilize flags inside the instruction itself to
/// distinguish between the two.
///
/// Refer to the "RV32I Reference Card" [here](https://github.com/johnwinans/rvalp/releases) for
/// more details.
#[allow(non_camel_case_types)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    PartialOrd,
    Ord,
    Enum,
    DeepSizeOf,
)]
#[repr(u8)]
pub enum Opcode {
    /// rd ← rs1 + rs2, pc ← pc + 4
    ADD = 0,
    /// rd ← rs1 + imm, pc ← pc + 4
    ADDI = 1,
    /// rd ← rs1 - rs2, pc ← pc + 4
    SUB = 2,
    /// rd ← rs1 ^ rs2, pc ← pc + 4
    XOR = 3,
    /// rd ← rs1 | rs2, pc ← pc + 4
    OR = 4,
    /// rd ← rs1 & rs2, pc ← pc + 4
    AND = 5,
    /// rd ← rs1 << rs2, pc ← pc + 4
    SLL = 6,
    /// rd ← rs1 >> rs2 (logical), pc ← pc + 4
    SRL = 7,
    /// rd ← rs1 >> rs2 (arithmetic), pc ← pc + 4
    SRA = 8,
    /// rd ← (rs1 < rs2) ? 1 : 0 (signed), pc ← pc + 4
    SLT = 9,
    /// rd ← (rs1 < rs2) ? 1 : 0 (unsigned), pc ← pc + 4
    SLTU = 10,
    /// rd ← rs1 * rs2 (signed), pc ← pc + 4
    MUL = 11,
    /// rd ← rs1 * rs2 (half), pc ← pc + 4
    MULH = 12,
    /// rd ← rs1 * rs2 (half unsigned), pc ← pc + 4
    MULHU = 13,
    /// rd ← rs1 * rs2 (half signed unsigned), pc ← pc + 4
    MULHSU = 14,
    /// rd ← rs1 / rs2 (signed), pc ← pc + 4
    DIV = 15,
    /// rd ← rs1 / rs2 (unsigned), pc ← pc + 4
    DIVU = 16,
    /// rd ← rs1 % rs2 (signed), pc ← pc + 4
    REM = 17,
    /// rd ← rs1 % rs2 (unsigned), pc ← pc + 4
    REMU = 18,
    /// rd ← sx(m8(rs1 + imm)), pc ← pc + 4
    LB = 19,
    /// rd ← sx(m16(rs1 + imm)), pc ← pc + 4
    LH = 20,
    /// rd ← sx(m32(rs1 + imm)), pc ← pc + 4
    LW = 21,
    /// rd ← zx(m8(rs1 + imm)), pc ← pc + 4
    LBU = 22,
    /// rd ← zx(m16(rs1 + imm)), pc ← pc + 4
    LHU = 23,
    /// m8(rs1 + imm) ← rs2[7:0], pc ← pc + 4
    SB = 24,
    /// m16(rs1 + imm) ← rs2[15:0], pc ← pc + 4
    SH = 25,
    /// m32(rs1 + imm) ← rs2[31:0], pc ← pc + 4
    SW = 26,
    /// pc ← pc + ((rs1 == rs2) ? imm : 4)
    BEQ = 27,
    /// pc ← pc + ((rs1 != rs2) ? imm : 4)
    BNE = 28,
    /// pc ← pc + ((rs1 < rs2) ? imm : 4) (signed)
    BLT = 29,
    /// pc ← pc + ((rs1 >= rs2) ? imm : 4) (signed)
    BGE = 30,
    /// pc ← pc + ((rs1 < rs2) ? imm : 4) (unsigned)
    BLTU = 31,
    /// pc ← pc + ((rs1 >= rs2) ? imm : 4) (unsigned)
    BGEU = 32,
    /// rd ← pc + 4, pc ← pc + imm
    JAL = 33,
    /// rd ← pc + 4, pc ← (rs1 + imm) & ∼1
    JALR = 34,
    /// rd ← pc + imm, pc ← pc + 4
    AUIPC = 35,
    /// rd ← imm, pc ← pc + 4
    LUI = 36,
    /// Transfer control to the ecall handler.
    ECALL = 37,
    /// Transfer control to the debugger.
    EBREAK = 38,
    // RISCV-64
    /// rd ← rs1 + rs2, pc ← pc + 4
    ADDW = 39,
    /// rd ← rs1 - rs2, pc ← pc + 4
    SUBW = 40,
    /// rd ← rs1 << rs2, pc ← pc + 4
    SLLW = 41,
    /// rd ← rs1 >> rs2 (logical), pc ← pc + 4
    SRLW = 42,
    /// rd ← rs1 >> rs2 (arithmetic), pc ← pc + 4
    SRAW = 43,
    /// rd ← sx(m32(rs1 + imm)), pc ← pc + 4
    LWU = 44,
    /// rd ← sx(m8(rs1 + imm)), pc ← pc + 4
    LD = 45,
    /// m8(rs1 + imm) ← rs2[7:0], pc ← pc + 4
    SD = 46,
    /// rd ← rs1 + imm, pc ← pc + 4
    MULW = 47,
    /// rd ← rs1 / rs2 (signed), pc ← pc + 4
    DIVW = 48,
    /// rd ← rs1 / rs2 (unsigned), pc ← pc + 4
    DIVUW = 49,
    /// rd ← rs1 % rs2 (signed), pc ← pc + 4
    REMW = 50,
    /// rd ← rs1 % rs2 (unsigned), pc ← pc + 4
    REMUW = 51,
    /// Unimplemented instruction.
    UNIMP = 52,
}
/// Byte Opcode.
///
/// This represents a basic operation that can be performed on a byte. Usually, these operations
/// are performed via lookup tables on that iterate over the domain of two 8-bit values. The
/// operations include both bitwise operations (AND, OR, XOR) as well as basic arithmetic.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, DeepSizeOf,
)]
#[allow(clippy::upper_case_acronyms)]
pub enum ByteOpcode {
    /// Bitwise AND.
    AND = 0,
    /// Bitwise OR.
    OR = 1,
    /// Bitwise XOR.
    XOR = 2,
    /// Unsigned 8-bit Range Check.
    U8Range = 3,
    /// Unsigned Less Than.
    LTU = 4,
    /// Most Significant Bit.
    MSB = 5,
    /// Range Check.
    Range = 6,
}

impl Opcode {
    /// Get the mnemonic for the opcode.
    #[must_use]
    pub const fn mnemonic(&self) -> &str {
        match self {
            Opcode::ADD => "add",
            Opcode::ADDI => "addi",
            Opcode::SUB => "sub",
            Opcode::XOR => "xor",
            Opcode::OR => "or",
            Opcode::AND => "and",
            Opcode::SLL => "sll",
            Opcode::SRL => "srl",
            Opcode::SRA => "sra",
            Opcode::SLT => "slt",
            Opcode::SLTU => "sltu",
            Opcode::LB => "lb",
            Opcode::LH => "lh",
            Opcode::LW => "lw",
            Opcode::LBU => "lbu",
            Opcode::LHU => "lhu",
            Opcode::SB => "sb",
            Opcode::SH => "sh",
            Opcode::SW => "sw",
            Opcode::BEQ => "beq",
            Opcode::BNE => "bne",
            Opcode::BLT => "blt",
            Opcode::BGE => "bge",
            Opcode::BLTU => "bltu",
            Opcode::BGEU => "bgeu",
            Opcode::JAL => "jal",
            Opcode::JALR => "jalr",
            Opcode::AUIPC => "auipc",
            Opcode::LUI => "lui",
            Opcode::ECALL => "ecall",
            Opcode::EBREAK => "ebreak",
            Opcode::MUL => "mul",
            Opcode::MULH => "mulh",
            Opcode::MULHU => "mulhu",
            Opcode::MULHSU => "mulhsu",
            Opcode::DIV => "div",
            Opcode::DIVU => "divu",
            Opcode::REM => "rem",
            Opcode::REMU => "remu",
            Opcode::ADDW => "addw",
            Opcode::SUBW => "subw",
            Opcode::SLLW => "sllw",
            Opcode::SRLW => "srlw",
            Opcode::SRAW => "sraw",
            Opcode::LWU => "lwu",
            Opcode::LD => "ld",
            Opcode::SD => "sd",
            Opcode::MULW => "mulw",
            Opcode::DIVW => "divw",
            Opcode::DIVUW => "divuw",
            Opcode::REMW => "remw",
            Opcode::REMUW => "remuw",
            Opcode::UNIMP => "unimp",
        }
    }

    /// Convert the opcode to a field element.
    #[must_use]
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u32(self as u32)
    }

    /// Returns the funct3 field for the opcode.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn funct3(self: Opcode) -> Option<u8> {
        Some(match self {
            // R-type and I-type ALU
            Opcode::ADD | Opcode::SUB | Opcode::ADDI => 0b000,
            Opcode::SLL => 0b001,
            Opcode::SLT => 0b010,
            Opcode::SLTU => 0b011,
            Opcode::XOR => 0b100,
            Opcode::SRL | Opcode::SRA => 0b101,
            Opcode::OR => 0b110,
            Opcode::AND => 0b111,
            Opcode::ADDW => 0b000,
            Opcode::SUBW => 0b000,
            Opcode::SLLW => 0b001,
            Opcode::SRLW => 0b101,
            Opcode::SRAW => 0b101,
            Opcode::LWU => 0b110,
            Opcode::LD => 0b011,
            Opcode::SD => 0b011,
            Opcode::MULW => 0b000,
            Opcode::DIVW => 0b100,
            Opcode::DIVUW => 0b101,
            Opcode::REMW => 0b110,
            Opcode::REMUW => 0b111,

            // M-extension (same funct3 as ALU)
            Opcode::MUL => 0b000,
            Opcode::MULH => 0b001,
            Opcode::MULHSU => 0b010,
            Opcode::MULHU => 0b011,
            Opcode::DIV => 0b100,
            Opcode::DIVU => 0b101,
            Opcode::REM => 0b110,
            Opcode::REMU => 0b111,

            // Loads
            Opcode::LB => 0b000,
            Opcode::LH => 0b001,
            Opcode::LW => 0b010,
            Opcode::LBU => 0b100,
            Opcode::LHU => 0b101,

            // Stores
            Opcode::SB => 0b000,
            Opcode::SH => 0b001,
            Opcode::SW => 0b010,

            // Branches
            Opcode::BEQ => 0b000,
            Opcode::BNE => 0b001,
            Opcode::BLT => 0b100,
            Opcode::BGE => 0b101,
            Opcode::BLTU => 0b110,
            Opcode::BGEU => 0b111,

            // JAL/JALR
            Opcode::JALR => 0b000, // JALR has funct3 = 000

            // System instructions (ECALL, EBREAK, MRET): fixed encoding
            Opcode::ECALL | Opcode::EBREAK => 0b000,

            // Instructions without funct3 field
            Opcode::JAL | Opcode::AUIPC | Opcode::LUI | Opcode::UNIMP => return None,
        })
    }

    /// Returns the funct7 field for the opcode.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn funct7(self: Opcode) -> Option<u8> {
        use Opcode::{
            ADD, ADDI, ADDW, AND, AUIPC, BEQ, BGE, BGEU, BLT, BLTU, BNE, DIV, DIVU, DIVUW, DIVW,
            EBREAK, ECALL, JAL, JALR, LB, LBU, LD, LH, LHU, LUI, LW, LWU, MUL, MULH, MULHSU, MULHU,
            MULW, OR, REM, REMU, REMUW, REMW, SB, SD, SH, SLL, SLLW, SLT, SLTU, SRA, SRAW, SRL,
            SRLW, SUB, SUBW, SW, UNIMP, XOR,
        };
        Some(match self {
            ADD | SLL | SLT | SLTU | XOR | SRL | OR | AND | ADDW | SLLW | SRLW => 0b0000000,
            SUB | SRA | SUBW | SRAW => 0b0100000,
            MUL | MULH | MULHSU | MULHU | DIV | DIVU | REM | REMU | MULW | DIVW | DIVUW | REMW
            | REMUW => 0b0000001,
            ECALL | EBREAK => 0b0000000,
            ADDI | LB | LH | LW | LBU | LHU | SB | SH | SW | BEQ | BNE | BLT | BGE | BLTU
            | BGEU | JAL | JALR | AUIPC | LUI | UNIMP | LWU | LD | SD => return None,
        })
    }

    /// Returns the funct12 field for the opcode.
    #[must_use]
    pub fn funct12(self: Opcode) -> Option<u32> {
        use Opcode::ECALL;
        Some(match self {
            ECALL => 0x000,
            _ => return None,
        })
    }

    #[must_use]
    /// Returns the base opcode for the opcode.
    pub fn base_opcode(self: Opcode) -> (u32, Option<u32>) {
        match self {
            Opcode::SLL
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLT
            | Opcode::SLTU => (OPCODE_OP, Some(OPCODE_OP_IMM)),

            Opcode::ADD
            | Opcode::SUB
            | Opcode::MUL
            | Opcode::MULH
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::DIV
            | Opcode::DIVU
            | Opcode::REM
            | Opcode::REMU => (OPCODE_OP, Some(OPCODE_OP)),

            Opcode::ADDI => (OPCODE_OP_IMM, Some(OPCODE_OP_IMM)),

            Opcode::ECALL => (OPCODE_SYSTEM, None),

            Opcode::JALR => (OPCODE_JALR, Some(OPCODE_JALR)),

            Opcode::LB
            | Opcode::LH
            | Opcode::LW
            | Opcode::LBU
            | Opcode::LHU
            | Opcode::LWU
            | Opcode::LD => (OPCODE_LOAD, Some(OPCODE_LOAD)),

            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => (OPCODE_STORE, Some(OPCODE_STORE)),

            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                (OPCODE_BRANCH, Some(OPCODE_BRANCH))
            }

            Opcode::AUIPC => (OPCODE_AUIPC, Some(OPCODE_AUIPC)),

            Opcode::LUI => (OPCODE_LUI, Some(OPCODE_LUI)),

            Opcode::JAL => (OPCODE_JAL, Some(OPCODE_JAL)),

            // RISC-V 64-bit operations
            Opcode::ADDW | Opcode::SLLW | Opcode::SRLW | Opcode::SRAW => {
                (OPCODE_OP_32, Some(OPCODE_OP_IMM_32))
            }

            Opcode::SUBW
            | Opcode::MULW
            | Opcode::DIVW
            | Opcode::DIVUW
            | Opcode::REMW
            | Opcode::REMUW => (OPCODE_OP_32, None),

            _ => unreachable!("Opcode {:?} has no base opcode", self),
        }
    }

    #[must_use]
    /// Returns the instruction type for the opcode.
    pub fn instruction_type(self) -> (InstructionType, Option<InstructionType>) {
        match self {
            Opcode::SLL | Opcode::SRL | Opcode::SRA => {
                (InstructionType::RType, Some(InstructionType::ITypeShamt))
            }

            Opcode::SLLW | Opcode::SRLW | Opcode::SRAW => {
                (InstructionType::RType, Some(InstructionType::ITypeShamt32))
            }

            Opcode::ADDW | Opcode::XOR | Opcode::OR | Opcode::AND | Opcode::SLT | Opcode::SLTU => {
                (InstructionType::RType, Some(InstructionType::IType))
            }

            Opcode::ADD
            | Opcode::SUB
            | Opcode::SUBW
            | Opcode::MUL
            | Opcode::MULH
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::DIV
            | Opcode::DIVU
            | Opcode::REM
            | Opcode::REMU
            | Opcode::MULW
            | Opcode::DIVW
            | Opcode::DIVUW
            | Opcode::REMW
            | Opcode::REMUW => (InstructionType::RType, None),

            Opcode::ADDI => (InstructionType::IType, Some(InstructionType::IType)),

            Opcode::ECALL => (InstructionType::ECALL, None),

            Opcode::JALR
            | Opcode::LB
            | Opcode::LH
            | Opcode::LW
            | Opcode::LBU
            | Opcode::LHU
            | Opcode::LWU
            | Opcode::LD => (InstructionType::IType, None),

            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => (InstructionType::SType, None),

            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                (InstructionType::BType, None)
            }

            Opcode::AUIPC | Opcode::LUI => (InstructionType::UType, None),

            Opcode::JAL => (InstructionType::JType, None),

            _ => unreachable!("Opcode {:?} has no instruction type", self),
        }
    }
}

impl Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.mnemonic())
    }
}
