use sp1_jit::SyscallContext;

use tiny_keccak::keccakf;

pub(crate) const STATE_SIZE: usize = 25;

// The permutation state is 25 u64's.  Our word size is 32 bits, so it is 50 words.
pub const STATE_NUM_WORDS: usize = STATE_SIZE;

pub unsafe fn keccak_permute(ctx: &mut impl SyscallContext, arg1: u64, arg2: u64) -> Option<u64> {
    let state_ptr = arg1;
    if arg2 != 0 {
        panic!("Expected arg2 to be 0, got {arg2}");
    }

    let mut state: Vec<u64> = Vec::new();

    let state_values = ctx.mr_slice(state_ptr, STATE_NUM_WORDS);
    state.extend(state_values);

    let mut state = state.try_into().unwrap();
    keccakf(&mut state);

    // Bump the clock before writing to memory.
    ctx.bump_memory_clk();

    ctx.mw_slice(state_ptr, state.as_slice());

    None
}
