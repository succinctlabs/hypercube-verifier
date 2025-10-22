use sp1_primitives::consts::{DEFAULT_PAGE_PROT, PAGE_SIZE};

use crate::{
    events::{MProtectEvent, PageProtLocalEvent, PageProtRecord, PrecompileEvent},
    memory::MAX_LOG_ADDR,
    ExecutorConfig,
};

use super::{context::SyscallContext, SyscallCode};

pub fn mprotect_syscall<E: ExecutorConfig>(
    ctx: &mut SyscallContext<E>,
    syscall_code: SyscallCode,
    addr: u64,
    prot: u64,
) -> Option<u64> {
    let prot: u8 = prot.try_into().expect("prot must be 8 bits");

    assert!(addr.is_multiple_of(PAGE_SIZE as u64), "addr must be page aligned");
    assert!(addr < 1 << MAX_LOG_ADDR, "addr must be less than 2^48");

    let page_prot_page_idx = addr / PAGE_SIZE as u64;

    let page_prot = ctx.rt.state.page_prots.entry(page_prot_page_idx).or_insert(PageProtRecord {
        external_flag: ctx.external_flag,
        timestamp: 0,
        page_prot: DEFAULT_PAGE_PROT,
    });

    // Create the initial page protection record for the local event
    let initial_page_prot_access = PageProtRecord {
        external_flag: page_prot.external_flag,
        timestamp: page_prot.timestamp,
        page_prot: page_prot.page_prot,
    };

    // Create the final page protection record for the local event
    let final_page_prot_access = PageProtRecord {
        external_flag: ctx.external_flag,
        timestamp: ctx.rt.state.clk,
        page_prot: prot,
    };

    // Create the page protection local event
    let page_prot_local_event = PageProtLocalEvent {
        page_idx: page_prot_page_idx,
        initial_page_prot_access,
        final_page_prot_access,
    };

    // Add to local page protection access if tracking
    if let Some(local_page_prot_access) = &mut ctx.local_page_prot_access {
        local_page_prot_access.insert(page_prot_page_idx, page_prot_local_event);
    }
    assert!(ctx.local_page_prot_access.is_some());
    assert!(ctx.local_page_prot_access.as_ref().unwrap().len() == 1);

    // Set the new page protection in the global state.
    ctx.rt.state.page_prots.insert(page_prot_page_idx, final_page_prot_access);

    let (_, local_page_prot_access) = ctx.postprocess();

    // Emit precompile event for the mprotect chip.
    let event = PrecompileEvent::Mprotect(MProtectEvent { addr, local_page_prot_access });

    let syscall_event = ctx.rt.syscall_event(
        ctx.clk,
        syscall_code,
        addr,
        prot as u64,
        false,
        ctx.next_pc,
        ctx.exit_code,
    );
    ctx.add_precompile_event(syscall_code, syscall_event, event);

    None
}
