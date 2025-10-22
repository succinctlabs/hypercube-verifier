use hashbrown::HashMap;

use crate::{memory::Memory, state::ForkState, ExecutorConfig, Unconstrained, HALT_PC};

use super::{SyscallCode, SyscallContext};

/// Enter an unconstrained block.
///
/// In unconstrained mode, the executor will call `run_unconstrained`, which is a lightweight
/// version of `run` that hints bytes using the `write` syscall. Eventually, `run_unconstrained`
/// will exit, and the state of the runtime will be restored to the saved state. The hinted bytes
/// can then be read during normal execution.
#[allow(clippy::unnecessary_wraps)]
pub fn enter_unconstrained_syscall<E: ExecutorConfig>(
    ctx: &mut SyscallContext<E>,
    _: SyscallCode,
    _: u64,
    _: u64,
) -> Option<u64> {
    assert!(!E::UNCONSTRAINED, "Unconstrained block is already active.");

    // Save the state of the runtime before unconstrained execution.
    ctx.rt.unconstrained_state = Box::new(ForkState {
        global_clk: ctx.rt.state.global_clk,
        clk: ctx.rt.state.clk,
        pc: ctx.rt.state.pc,
        memory_diff: Memory::default(),
        page_prots_diff: HashMap::new(),
    });

    // Write `1` to `x5` to indicate that unconstrained execution is active, and advance the PC.
    ctx.rt.rw_cpu::<Unconstrained>(crate::Register::X5, 1);
    ctx.rt.state.pc = ctx.rt.state.pc.wrapping_add(4);

    // Run unconstrained execution until a call to `exit_unconstrained`.
    ctx.rt.run_unconstrained().expect("Unconstrained execution failed");

    // Update the state of the runtime to match the saved state.
    ctx.rt.state.global_clk = ctx.rt.unconstrained_state.global_clk;
    ctx.rt.state.clk = ctx.rt.unconstrained_state.clk;

    ctx.rt.state.pc = ctx.rt.unconstrained_state.pc;
    ctx.next_pc = ctx.rt.state.pc.wrapping_add(4);

    let memory_diff = std::mem::take(&mut ctx.rt.unconstrained_state.memory_diff);
    for (addr, value) in memory_diff {
        match value {
            Some(value) => {
                ctx.rt.state.memory.insert(addr, value);
            }
            None => {
                ctx.rt.state.memory.remove(addr);
            }
        }
    }

    let page_prots_diff = std::mem::take(&mut ctx.rt.unconstrained_state.page_prots_diff);
    for (addr, value) in page_prots_diff {
        ctx.rt.state.page_prots.insert(addr, value);
    }

    ctx.rt.unconstrained_state = Box::new(ForkState::default());
    Some(0)
}

/// Exit an unconstrained block.
///
/// This exits the entire program, just like halt(0). Constrained execution will resume from
/// the corresponding `enter_unconstrained` call.
#[allow(clippy::unnecessary_wraps)]
pub fn exit_unconstrained_syscall<E: ExecutorConfig>(
    ctx: &mut SyscallContext<E>,
    _: SyscallCode,
    _: u64,
    _: u64,
) -> Option<u64> {
    assert!(E::UNCONSTRAINED, "Unconstrained block is not active.");
    ctx.set_next_pc(HALT_PC);
    ctx.set_exit_code(0);
    Some(0)
}
