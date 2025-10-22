pub mod instruction;
mod instruction_decode;
mod instruction_fetch;
mod trusted;

use instruction::InstructionCols;
pub use instruction_decode::*;
pub use instruction_fetch::*;
pub use trusted::*;
