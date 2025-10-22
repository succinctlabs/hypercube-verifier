//! Registers for the SP1 zkVM.

use sp1_jit::{RiscOperand, RiscRegister};

/// The number of registers.
pub const NUM_REGISTERS: usize = 32;

/// A register stores a 32-bit value used by operations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Register {
    /// %x0
    X0 = 0,
    /// %x1
    X1 = 1,
    /// %x2
    X2 = 2,
    /// %x3
    X3 = 3,
    /// %x4
    X4 = 4,
    /// %x5
    X5 = 5,
    /// %x6
    X6 = 6,
    /// %x7
    X7 = 7,
    /// %x8
    X8 = 8,
    /// %x9
    X9 = 9,
    /// %x10
    X10 = 10,
    /// %x11
    X11 = 11,
    /// %x12
    X12 = 12,
    /// %x13
    X13 = 13,
    /// %x14
    X14 = 14,
    /// %x15
    X15 = 15,
    /// %x16
    X16 = 16,
    /// %x17
    X17 = 17,
    /// %x18
    X18 = 18,
    /// %x19
    X19 = 19,
    /// %x20
    X20 = 20,
    /// %x21
    X21 = 21,
    /// %x22
    X22 = 22,
    /// %x23
    X23 = 23,
    /// %x24
    X24 = 24,
    /// %x25
    X25 = 25,
    /// %x26
    X26 = 26,
    /// %x27
    X27 = 27,
    /// %x28
    X28 = 28,
    /// %x29
    X29 = 29,
    /// %x30
    X30 = 30,
    /// %x31
    X31 = 31,
}

impl Register {
    /// Create a new register from a u8.
    ///
    /// # Panics
    ///
    /// This function will panic if the register is invalid.
    #[inline]
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Register::X0,
            1 => Register::X1,
            2 => Register::X2,
            3 => Register::X3,
            4 => Register::X4,
            5 => Register::X5,
            6 => Register::X6,
            7 => Register::X7,
            8 => Register::X8,
            9 => Register::X9,
            10 => Register::X10,
            11 => Register::X11,
            12 => Register::X12,
            13 => Register::X13,
            14 => Register::X14,
            15 => Register::X15,
            16 => Register::X16,
            17 => Register::X17,
            18 => Register::X18,
            19 => Register::X19,
            20 => Register::X20,
            21 => Register::X21,
            22 => Register::X22,
            23 => Register::X23,
            24 => Register::X24,
            25 => Register::X25,
            26 => Register::X26,
            27 => Register::X27,
            28 => Register::X28,
            29 => Register::X29,
            30 => Register::X30,
            31 => Register::X31,
            _ => panic!("invalid register {value}"),
        }
    }
}

impl From<Register> for RiscOperand {
    fn from(value: Register) -> Self {
        RiscOperand::Register(value.into())
    }
}

impl From<Register> for RiscRegister {
    fn from(value: Register) -> Self {
        match value {
            Register::X0 => RiscRegister::X0,
            Register::X1 => RiscRegister::X1,
            Register::X2 => RiscRegister::X2,
            Register::X3 => RiscRegister::X3,
            Register::X4 => RiscRegister::X4,
            Register::X5 => RiscRegister::X5,
            Register::X6 => RiscRegister::X6,
            Register::X7 => RiscRegister::X7,
            Register::X8 => RiscRegister::X8,
            Register::X9 => RiscRegister::X9,
            Register::X10 => RiscRegister::X10,
            Register::X11 => RiscRegister::X11,
            Register::X12 => RiscRegister::X12,
            Register::X13 => RiscRegister::X13,
            Register::X14 => RiscRegister::X14,
            Register::X15 => RiscRegister::X15,
            Register::X16 => RiscRegister::X16,
            Register::X17 => RiscRegister::X17,
            Register::X18 => RiscRegister::X18,
            Register::X19 => RiscRegister::X19,
            Register::X20 => RiscRegister::X20,
            Register::X21 => RiscRegister::X21,
            Register::X22 => RiscRegister::X22,
            Register::X23 => RiscRegister::X23,
            Register::X24 => RiscRegister::X24,
            Register::X25 => RiscRegister::X25,
            Register::X26 => RiscRegister::X26,
            Register::X27 => RiscRegister::X27,
            Register::X28 => RiscRegister::X28,
            Register::X29 => RiscRegister::X29,
            Register::X30 => RiscRegister::X30,
            Register::X31 => RiscRegister::X31,
        }
    }
}
