use serde::{Deserialize, Serialize};
use std::sync::mpsc;

pub trait DebugState {
    fn current_state(&self) -> State;
    fn new_debug_receiver(&mut self) -> Option<mpsc::Receiver<Option<State>>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct State {
    pub pc: u64,
    pub clk: u64,
    pub global_clk: u64,
    pub registers: [u64; 32],
}
