//! Instructions for the SP1 zkVM.

use core::fmt::Debug;
use rrs_lib::instruction_formats::{
    OPCODE_AUIPC, OPCODE_BRANCH, OPCODE_JAL, OPCODE_JALR, OPCODE_LOAD, OPCODE_LUI, OPCODE_OP,
    OPCODE_OP_32, OPCODE_OP_IMM, OPCODE_OP_IMM_32, OPCODE_STORE, OPCODE_SYSTEM,
};
use serde::{Deserialize, Serialize};

use crate::opcode::Opcode;

/// RV64 instruction types.
pub enum InstructionType {
    /// I-type instructions with shamt (32-bit).
    ITypeShamt32 = 0b0_0000_0001,
    /// I-type instructions with shamt.
    ITypeShamt = 0b0_0000_0010,
    /// I-type instructions.
    IType = 0b0_0000_0100,
    /// R-type instructions.
    RType = 0b0_0000_1000,
    /// J-type instructions.
    JType = 0b0_0001_0000,
    /// B-type instructions.
    BType = 0b0_0010_0000,
    /// S-type instructions.
    SType = 0b0_0100_0000,
    /// U-type instructions.
    UType = 0b0_1000_0000,
    /// ECALL instruction.
    ECALL = 0b1_0000_0000,
}

/// Validates that a u64 is properly sign-extended for a given bit width.
///
/// This function checks that all bits above the specified bit width are properly sign-extended
/// (either all 0s for positive values or all 1s for negative values).
///
/// Returns true if the value is properly sign-extended, false otherwise.
#[must_use]
#[inline]
pub const fn validate_sign_extension(value: u64, bit_width: u32) -> bool {
    if bit_width >= 64 {
        return true; // No sign extension needed
    }

    let sign_bit_mask = 1u64 << (bit_width - 1);
    let sign_bit = (value & sign_bit_mask) != 0;

    // Create mask for bits above the immediate width
    let upper_bits_mask = !((1u64 << bit_width) - 1);
    let upper_bits = value & upper_bits_mask;

    if sign_bit {
        // Negative value: upper bits should all be 1s
        upper_bits == upper_bits_mask
    } else {
        // Positive value: upper bits should all be 0s
        upper_bits == 0
    }
}

/// RISC-V 64IM Instruction.
///
/// The structure of the instruction differs from the RISC-V ISA. We do not encode the instructions
/// as 32-bit words, but instead use a custom encoding that is more friendly to decode in the
/// SP1 zkVM.
#[derive(Clone, Copy, Serialize, Deserialize, deepsize2::DeepSizeOf)]
#[repr(C)]
pub struct Instruction {
    /// The operation to execute.
    pub opcode: Opcode,
    /// The first operand.
    pub op_a: u8,
    /// The second operand.
    pub op_b: u64,
    /// The third operand.
    pub op_c: u64,
    /// Whether the second operand is an immediate value.
    pub imm_b: bool,
    /// Whether the third operand is an immediate value.
    pub imm_c: bool,
}

impl Instruction {
    /// Create a new [`RiscvInstruction`].
    #[must_use]
    pub const fn new(
        opcode: Opcode,
        op_a: u8,
        op_b: u64,
        op_c: u64,
        imm_b: bool,
        imm_c: bool,
    ) -> Self {
        Self { opcode, op_a, op_b, op_c, imm_b, imm_c }
    }

    /// Returns if the instruction is an ALU instruction.
    #[must_use]
    #[inline]
    pub const fn is_alu_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::ADD
                | Opcode::ADDI
                | Opcode::SUB
                | Opcode::XOR
                | Opcode::OR
                | Opcode::AND
                | Opcode::SLL
                | Opcode::SRL
                | Opcode::SRA
                | Opcode::SLT
                | Opcode::SLTU
                | Opcode::MUL
                | Opcode::MULH
                | Opcode::MULHU
                | Opcode::MULHSU
                | Opcode::DIV
                | Opcode::DIVU
                | Opcode::REM
                | Opcode::REMU
                // RISCV-64
                | Opcode::ADDW
                | Opcode::SUBW
                | Opcode::MULW
                | Opcode::DIVW
                | Opcode::DIVUW
                | Opcode::REMW
                | Opcode::REMUW
                | Opcode::SLLW
                | Opcode::SRLW
                | Opcode::SRAW
        )
    }

    /// Returns if the instruction is a ecall instruction.
    #[must_use]
    #[inline]
    pub const fn is_ecall_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::ECALL)
    }

    /// Returns if the instruction is a memory load instruction.
    #[must_use]
    #[inline]
    pub const fn is_memory_load_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                // RISCV-64
                | Opcode::LWU
                | Opcode::LD
        )
    }

    /// Returns if the instruction is a memory store instruction.
    #[must_use]
    #[inline]
    pub const fn is_memory_store_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::SB | Opcode::SH | Opcode::SW | /* RISCV-64 */ Opcode::SD)
    }

    /// Returns if the instruction is a branch instruction.
    #[must_use]
    #[inline]
    pub const fn is_branch_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU
        )
    }

    /// Returns if the instruction is a jump instruction.
    #[must_use]
    #[inline]
    pub const fn is_jump_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::JAL | Opcode::JALR)
    }

    /// Returns if the instruction is a jal instruction.
    #[must_use]
    #[inline]
    pub const fn is_jal_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::JAL)
    }

    /// Returns if the instruction is a jalr instruction.
    #[must_use]
    #[inline]
    pub const fn is_jalr_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::JALR)
    }

    /// Returns if the instruction is a utype instruction.
    #[must_use]
    #[inline]
    pub const fn is_utype_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::AUIPC | Opcode::LUI)
    }

    /// Returns if the instruction guarantees that the `next_pc` are with correct limbs.
    #[must_use]
    #[inline]
    pub const fn is_with_correct_next_pc(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::BEQ
                | Opcode::BNE
                | Opcode::BLT
                | Opcode::BGE
                | Opcode::BLTU
                | Opcode::BGEU
                | Opcode::JAL
                | Opcode::JALR
        )
    }

    /// Returns if the instruction is a divrem instruction.
    #[must_use]
    #[inline]
    pub const fn is_divrem_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::DIV | Opcode::DIVU | Opcode::REM | Opcode::REMU)
    }

    /// Returns if the instruction is an ebreak instruction.
    #[must_use]
    #[inline]
    pub const fn is_ebreak_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::EBREAK)
    }

    /// Returns if the instruction is an unimplemented instruction.
    #[must_use]
    #[inline]
    pub const fn is_unimp_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::UNIMP)
    }

    /// Returns the encoded RISC-V instruction.
    #[must_use]
    #[inline]
    #[allow(clippy::too_many_lines)]
    pub fn encode(&self) -> u32 {
        if self.opcode == Opcode::ECALL {
            0x00000073
        } else {
            let (mut base_opcode, imm_base_opcode) = self.opcode.base_opcode();

            let is_imm = self.imm_c;
            if is_imm {
                base_opcode = imm_base_opcode.expect("Opcode should have imm base opcode");
            }

            let funct3 = self.opcode.funct3();
            let funct7 = self.opcode.funct7();
            let funct12 = self.opcode.funct12();

            match base_opcode {
                // R-type instructions
                // Operands represent register indices, which must be 5 bits (0-31)
                OPCODE_OP | OPCODE_OP_32 => {
                    assert!(
                        self.op_a <= 31,
                        "Register index {} exceeds maximum value 31",
                        self.op_a
                    );
                    assert!(
                        self.op_b <= 31,
                        "Register index {} exceeds maximum value 31",
                        self.op_b
                    );
                    assert!(
                        self.op_c <= 31,
                        "Register index {} exceeds maximum value 31",
                        self.op_c
                    );

                    let (rd, rs1, rs2) = (self.op_a as u32, self.op_b as u32, self.op_c as u32);
                    let funct3: u32 = funct3.expect("Opcode should have funct3").into();
                    let funct7: u32 = funct7.expect("Opcode should have funct7").into();

                    (funct7 << 25)
                        | (rs2 << 20)
                        | (rs1 << 15)
                        | (funct3 << 12)
                        | (rd << 7)
                        | base_opcode
                }
                // I-type instructions
                // Operands a and b represent register indices, which must be 5 bits (0-31)
                // Operand c represents an immediate value, which must be 12 bits (signed)
                OPCODE_OP_IMM | OPCODE_OP_IMM_32 | OPCODE_LOAD | OPCODE_JALR | OPCODE_SYSTEM => {
                    assert!(
                        self.op_a <= 31,
                        "Register index {} exceeds maximum value 31",
                        self.op_a
                    );
                    assert!(
                        self.op_b <= 31,
                        "Register index {} exceeds maximum value 31",
                        self.op_b
                    );
                    assert!(
                        validate_sign_extension(self.op_c, 12),
                        "Immediate value {} is not properly sign-extended for 12 bits",
                        self.op_c
                    );

                    let (rd, rs1, imm) = (
                        self.op_a as u32,
                        self.op_b as u32,
                        // Extract original 12-bit immediate from sign-extended u64
                        (self.op_c & 0xFFF) as u32,
                    );
                    let funct3: u32 = funct3.expect("Opcode should have funct3").into();

                    // Check if it should be a I-type shamt instruction.
                    if (base_opcode == OPCODE_OP_IMM || base_opcode == OPCODE_OP_IMM_32)
                        && matches!(funct3, 0b001 | 0b101)
                    {
                        let funct7: u32 = funct7.expect("Opcode should have funct7").into();
                        (funct7 << 25)
                            | (imm << 20)
                            | (rs1 << 15)
                            | (funct3 << 12)
                            | (rd << 7)
                            | base_opcode
                    } else if base_opcode == OPCODE_SYSTEM && funct3 == 0 && rd == 0 && rs1 == 0 {
                        let funct12: u32 = funct12.expect("Opcode should have funct12");
                        (funct12 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | base_opcode
                    } else {
                        (imm << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | base_opcode
                    }
                }

                // S-type instructions
                // Operands a and b represent register indices, which must be 5 bits (0-31)
                // Operand c represents an immediate value, which must be 12 bits (signed) (split
                // b/w [31:25] + [11:7])
                OPCODE_STORE => {
                    assert!(
                        self.op_a <= 31,
                        "Register index {} exceeds maximum value 31",
                        self.op_a
                    );
                    assert!(
                        self.op_b <= 31,
                        "Register index {} exceeds maximum value 31",
                        self.op_b
                    );
                    assert!(
                        validate_sign_extension(self.op_c, 12),
                        "Immediate value {} is not properly sign-extended for 12 bits",
                        self.op_c
                    );

                    let funct3: u32 = funct3.expect("Opcode should have funct3").into();
                    let (rd, rs1, imm) = (
                        self.op_a as u32,
                        self.op_b as u32,
                        // Extract original 12-bit immediate from sign-extended u64
                        (self.op_c & 0xFFF) as u32,
                    );
                    let imm_11_5 = (imm >> 5) & 0b1111111;
                    let imm_4_0 = imm & 0b11111;

                    (imm_11_5 << 25)
                        | (rd << 20)
                        | (rs1 << 15)
                        | (funct3 << 12)
                        | (imm_4_0 << 7)
                        | base_opcode
                }

                // B-type instructions
                // Operands a and b represent register indices, which must be 5 bits (0-31)
                // Signed 13 bits for B-type instructions (bits [31:25] + [11:8] + [7])
                OPCODE_BRANCH => {
                    assert!(
                        self.op_a <= 31,
                        "Register index {} exceeds maximum value 31",
                        self.op_a
                    );
                    assert!(
                        self.op_b <= 31,
                        "Register index {} exceeds maximum value 31",
                        self.op_b
                    );
                    assert!(
                        validate_sign_extension(self.op_c, 13),
                        "Immediate value {} is not properly sign-extended for 13 bits",
                        self.op_c
                    );

                    let funct3: u32 = funct3.expect("Opcode should have funct3").into();
                    let (rd, rs1, imm) = (
                        self.op_a as u32,
                        self.op_b as u32,
                        // Extract original 13-bit immediate from sign-extended u64
                        (self.op_c & 0x1FFF) as u32,
                    );
                    assert!(imm & 0b1 == 0, "B-type immediate must be aligned (multiple of 2)");

                    let imm_12 = (imm >> 12) & 0b1;
                    let imm_10_5 = (imm >> 5) & 0b111111;
                    let imm_4_1 = (imm >> 1) & 0b1111;
                    let imm_11 = (imm >> 11) & 0b1;

                    (imm_12 << 31)
                        | (imm_10_5 << 25)
                        | (rs1 << 20)
                        | (rd << 15)
                        | (funct3 << 12)
                        | (imm_4_1 << 8)
                        | (imm_11 << 7)
                        | (base_opcode & 0b1111111)
                }
                // U-type instructions
                // 20 bits for U-type instructions (bits [31:12])
                OPCODE_AUIPC | OPCODE_LUI => {
                    assert!(
                        self.op_a <= 31,
                        "Register index {} exceeds maximum value 31",
                        self.op_a
                    );
                    let mut sign_extended_imm = self.op_b >> 12;
                    if self.op_b >= (1 << 32) {
                        sign_extended_imm += u64::MAX - (1u64 << 52) + 1;
                    }
                    assert!(
                        validate_sign_extension(sign_extended_imm, 20),
                        "Immediate value {} is not properly sign-extended for 20 bits",
                        self.op_b
                    );
                    let (rd, imm_upper) = (
                        self.op_a as u32,
                        // Extract original 20-bit immediate from sign-extended u64
                        self.op_b as u32,
                    );
                    imm_upper | (rd << 7) | base_opcode
                }
                // J-type instructions
                // 21 bits for J-type instructions (bits [31:12] + [20] + [19:12] + [30:21])
                OPCODE_JAL => {
                    assert!(
                        self.op_a <= 31,
                        "Register index {} exceeds maximum value 31",
                        self.op_a
                    );
                    assert!(
                        validate_sign_extension(self.op_b, 21),
                        "Immediate value {} is not properly sign-extended for 21 bits",
                        self.op_b
                    );
                    assert!(self.op_b & 0b1 == 0, "J-type immediate must be 2-byte aligned");
                    let (rd, imm) = (
                        self.op_a as u32,
                        // Extract original 21-bit immediate from sign-extended u64
                        (self.op_b & 0x1FFFFF) as u32,
                    );

                    let imm_20 = (imm >> 20) & 0x1;
                    let imm_10_1 = (imm >> 1) & 0x3FF;
                    let imm_11 = (imm >> 11) & 0x1;
                    let imm_19_12 = (imm >> 12) & 0xFF;

                    (imm_20 << 31)
                        | (imm_10_1 << 21)
                        | (imm_11 << 20)
                        | (imm_19_12 << 12)
                        | (rd << 7)
                        | base_opcode
                }

                _ => unreachable!(),
            }
        }
    }
}

impl Debug for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mnemonic = self.opcode.mnemonic();
        let op_a_formatted = format!("%x{}", self.op_a);
        let op_b_formatted = if self.imm_b || self.opcode == Opcode::AUIPC {
            format!("{}", self.op_b as i32)
        } else {
            format!("%x{}", self.op_b)
        };
        let op_c_formatted =
            if self.imm_c { format!("{}", self.op_c as i32) } else { format!("%x{}", self.op_c) };

        let width = 10;
        write!(
            f,
            "{mnemonic:<width$} {op_a_formatted:<width$} {op_b_formatted:<width$} {op_c_formatted:<width$}"
        )
    }
}
