use std::marker::PhantomData;

use hashbrown::HashMap;
use sp1_primitives::consts::{PAGE_SIZE, PROT_READ, PROT_WRITE};

use crate::{
    events::{
        MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord, PageProtLocalEvent, PageProtRecord,
        PrecompileEvent, SyscallEvent,
    },
    ExecutionRecord, Executor, ExecutorConfig, ExecutorMode, Register,
};

use super::SyscallCode;

/// A runtime for syscalls that is protected so that developers cannot arbitrarily modify the
/// runtime.
#[allow(dead_code)]
pub struct SyscallContext<'a, 'b: 'a, E: ExecutorConfig> {
    /// The external flag.
    pub external_flag: bool,
    /// The clock cycle.
    pub clk: u64,
    /// The next program counter.
    pub next_pc: u64,
    /// The exit code.
    pub exit_code: u32,
    /// The runtime.
    pub rt: &'a mut Executor<'b>,
    /// The local memory access events for the syscall.
    pub local_memory_access: Option<HashMap<u64, MemoryLocalEvent>>,
    /// The local page protection access events for the syscall.
    pub local_page_prot_access: Option<HashMap<u64, PageProtLocalEvent>>,
    /// Phantom data.
    pub _phantom: PhantomData<E>,
}

impl<'a, 'b, E: ExecutorConfig> SyscallContext<'a, 'b, E> {
    /// Create a new [`SyscallContext`].
    pub fn new(runtime: &'a mut Executor<'b>, external_flag: bool) -> Self {
        let clk = runtime.state.clk;
        Self {
            external_flag,
            clk,
            next_pc: runtime.state.pc.wrapping_add(4),
            exit_code: 0,
            rt: runtime,
            local_memory_access: external_flag.then_some(HashMap::new()),
            local_page_prot_access: external_flag.then_some(HashMap::new()),
            _phantom: PhantomData,
        }
    }

    /// Get a mutable reference to the execution record.
    pub fn record_mut(&mut self) -> &mut ExecutionRecord {
        &mut self.rt.record
    }

    #[inline]
    /// Add a precompile event to the execution record.
    pub fn add_precompile_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        if E::MODE == ExecutorMode::Trace {
            self.record_mut().precompile_events.add_event(syscall_code, syscall_event, event);
        }
    }

    /// Read a word from memory.
    ///
    /// `addr` must be a pointer to main memory, not a register.
    pub fn mr(&mut self, addr: u64) -> (MemoryReadRecord, u64) {
        let mut record =
            self.rt.mr::<E>(addr, self.external_flag, self.clk, self.local_memory_access.as_mut());
        if self.rt.program.enable_untrusted_programs {
            let page_prot_record = self.rt.page_prot_access::<E>(
                addr / PAGE_SIZE as u64,
                PROT_READ,
                self.external_flag,
                self.clk,
                self.local_page_prot_access.as_mut(),
            );

            record.prev_page_prot_record = Some(page_prot_record);
        }
        (record, record.value)
    }

    /// Read a slice of words from memory.
    ///
    /// `addr` must be a pointer to main memory, not a register.
    ///
    /// Returns a tuple of (memory records, values, page protection records).
    pub fn mr_slice(
        &mut self,
        addr: u64,
        len: usize,
    ) -> (Vec<MemoryReadRecord>, Vec<u64>, Vec<PageProtRecord>) {
        let mut records = Vec::with_capacity(len);
        let mut values = Vec::with_capacity(len);
        let mut page_accesses = HashMap::new();

        for i in 0..len {
            let current_addr = addr + i as u64 * 8;
            let record = self.rt.mr::<E>(
                current_addr,
                self.external_flag,
                self.clk,
                self.local_memory_access.as_mut(),
            );
            records.push(record);
            values.push(record.value);

            let page_idx = current_addr / (PAGE_SIZE as u64);
            page_accesses.entry(page_idx).or_insert(PROT_READ);
        }
        // Generate the page prot records - one per unique page
        let mut page_prot_records = Vec::with_capacity(page_accesses.len());

        if self.rt.program.enable_untrusted_programs {
            let mut page_accesses: Vec<_> = page_accesses.iter().collect();
            page_accesses.sort_by_key(|(page_idx, _)| *page_idx);

            // Ensure we have at most 2 pages
            assert!(page_accesses.len() <= 2, "Memory read operation spans more than 2 pages");
            if page_accesses.len() == 2 {
                assert!(
                    page_accesses[1].0 - page_accesses[0].0 == 1,
                    "Memory read operation page accesses are not adjacent"
                );
            }

            for (page_idx, page_prot) in page_accesses {
                let page_prot_record = self.rt.page_prot_access::<E>(
                    *page_idx,
                    *page_prot,
                    self.external_flag,
                    self.clk,
                    self.local_page_prot_access.as_mut(),
                );
                page_prot_records.push(page_prot_record);
            }
        }
        (records, values, page_prot_records)
    }

    /// Write a word to memory.
    ///
    /// `addr` must be a pointer to main memory, not a register.
    ///
    /// `is_read_and_write` is used to determine if the page protection should also assert whether
    /// a read is permitted.
    pub fn mw(&mut self, addr: u64, value: u64, is_read_and_write: bool) -> MemoryWriteRecord {
        let mut record = self.rt.mw::<E>(
            addr,
            value,
            self.external_flag,
            self.clk,
            self.local_memory_access.as_mut(),
        );
        if self.rt.program.enable_untrusted_programs {
            let page_prot_bitmap =
                if is_read_and_write { PROT_READ | PROT_WRITE } else { PROT_WRITE };

            let page_prot_record = self.rt.page_prot_access::<E>(
                addr / PAGE_SIZE as u64,
                page_prot_bitmap,
                self.external_flag,
                self.clk,
                self.local_page_prot_access.as_mut(),
            );

            record.prev_page_prot_record = Some(page_prot_record);
        }
        record
    }

    /// Write a slice of words to memory.
    ///
    /// Returns a tuple of (memory records, page protection records).
    pub fn mw_slice(
        &mut self,
        addr: u64,
        values: &[u64],
        is_read_and_write: bool,
    ) -> (Vec<MemoryWriteRecord>, Vec<PageProtRecord>) {
        let mut records = Vec::with_capacity(values.len());
        let mut page_accesses = HashMap::new();

        for i in 0..values.len() {
            let current_addr = addr + i as u64 * 8;
            let record = self.rt.mw::<E>(
                current_addr,
                values[i],
                self.external_flag,
                self.clk,
                self.local_memory_access.as_mut(),
            );
            records.push(record);

            let page_idx = current_addr / (PAGE_SIZE as u64);
            let page_prot = if is_read_and_write { PROT_READ | PROT_WRITE } else { PROT_WRITE };
            page_accesses.entry(page_idx).or_insert(page_prot);
        }

        // Generate the page prot records - one per unique page
        let mut page_prot_records = Vec::with_capacity(page_accesses.len());
        if self.rt.program.enable_untrusted_programs {
            let mut page_accesses: Vec<_> = page_accesses.iter().collect();
            page_accesses.sort_by_key(|(page_idx, _)| *page_idx);

            // Ensure we have at most 2 pages
            assert!(page_accesses.len() <= 2, "Memory write operation spans more than 2 pages");
            if page_accesses.len() == 2 {
                assert!(
                    page_accesses[1].0 - page_accesses[0].0 == 1,
                    "Memory write operation page accesses are not adjacent"
                );
            }

            for (page_idx, page_prot) in page_accesses {
                let page_prot_record = self.rt.page_prot_access::<E>(
                    *page_idx,
                    *page_prot,
                    self.external_flag,
                    self.clk,
                    self.local_page_prot_access.as_mut(),
                );
                page_prot_records.push(page_prot_record);
            }
        }
        (records, page_prot_records)
    }

    /// Get the page protection records for a range of addresses.
    ///
    /// This is used to get the page protection records for a range of addresses that are not
    /// contiguous in memory, and are read and written to over a closed range of cycles.
    pub fn page_prot_range_access(
        &mut self,
        start_addr: u64,
        end_addr: u64,
        page_prot_bitmap: u8,
    ) -> Vec<PageProtRecord> {
        let mut page_prot_records = Vec::new();
        if self.rt.program.enable_untrusted_programs {
            let start_page_idx = start_addr / PAGE_SIZE as u64;
            let end_page_idx = end_addr / PAGE_SIZE as u64;
            assert!(
                end_page_idx == start_page_idx || end_page_idx == start_page_idx + 1,
                "Start and end addresses must be on the same page or adjacent pages"
            );

            let start_page_prot_record = self.rt.page_prot_access::<E>(
                start_page_idx,
                page_prot_bitmap,
                self.external_flag,
                self.clk,
                self.local_page_prot_access.as_mut(),
            );
            page_prot_records.push(start_page_prot_record);

            if end_page_idx > start_page_idx {
                let end_page_prot_record = self.rt.page_prot_access::<E>(
                    end_page_idx,
                    page_prot_bitmap,
                    self.external_flag,
                    self.clk,
                    self.local_page_prot_access.as_mut(),
                );
                page_prot_records.push(end_page_prot_record);
            }
        }
        page_prot_records
    }

    /// Read a register and record the memory access.
    pub fn rr_traced(&mut self, register: Register) -> (MemoryReadRecord, u64) {
        let record = self.rt.rr_traced::<E>(
            register,
            self.external_flag,
            self.clk,
            self.local_memory_access.as_mut(),
        );
        (record, record.value)
    }

    /// Write a register and record the memory access.
    pub fn rw_traced(&mut self, register: Register, value: u64) -> (MemoryWriteRecord, u64) {
        let record = self.rt.rw_traced::<E>(
            register,
            value,
            self.external_flag,
            self.clk,
            self.local_memory_access.as_mut(),
        );
        (record, record.value)
    }

    /// Postprocess the syscall.  Specifically will process the syscall's memory and page prot local
    /// events.
    pub fn postprocess(&mut self) -> (Vec<MemoryLocalEvent>, Vec<PageProtLocalEvent>) {
        let mut syscall_local_mem_events = Vec::new();
        let mut syscall_local_page_prot_events = Vec::new();

        if E::MODE == ExecutorMode::Trace && !E::UNCONSTRAINED {
            // Will need to transfer the existing memory local events in the executor to it's
            // record, and return all the syscall memory local events.  This is similar
            // to what `bump_record` does.
            if let Some(local_memory_access) = self.local_memory_access.as_mut() {
                for (addr, event) in local_memory_access.drain() {
                    let local_mem_access = self.rt.local_memory_access.remove(&addr);

                    if let Some(local_mem_access) = local_mem_access {
                        self.rt.record.cpu_local_memory_access.push(local_mem_access);
                    }

                    syscall_local_mem_events.push(event);
                }
            }
            if self.rt.program.enable_untrusted_programs {
                // Handle page protection local events similarly
                if let Some(local_page_prot_access) = self.local_page_prot_access.as_mut() {
                    for (page_idx, event) in local_page_prot_access.drain() {
                        let local_page_prot_access =
                            self.rt.local_page_prot_access.remove(&page_idx);

                        if let Some(local_page_prot_access) = local_page_prot_access {
                            self.rt.record.cpu_local_page_prot_access.push(local_page_prot_access);
                        }

                        syscall_local_page_prot_events.push(event);
                    }
                }
            }
        }

        (syscall_local_mem_events, syscall_local_page_prot_events)
    }

    /// Get the current value of a register, but doesn't use a memory record.
    /// This is generally unconstrained, so you must be careful using it.
    #[must_use]
    pub fn register_unsafe(&mut self, register: Register) -> u64 {
        self.rt.register::<E>(register)
    }

    /// Get the current value of a byte, but doesn't use a memory record.
    #[must_use]
    pub fn byte_unsafe(&mut self, addr: u64) -> u8 {
        self.rt.byte::<E>(addr)
    }

    /// Get the current value of a double word, but doesn't use a memory record.
    #[must_use]
    pub fn double_word_unsafe(&mut self, addr: u64) -> u64 {
        self.rt.double_word::<E>(addr)
    }

    /// Get a slice of double words, but doesn't use a memory record.
    #[must_use]
    pub fn slice_unsafe(&mut self, addr: u64, len: usize) -> Vec<u64> {
        let mut values = Vec::new();
        for i in 0..len {
            values.push(self.rt.double_word::<E>(addr + i as u64 * 8));
        }
        values
    }

    /// Set the next program counter.
    pub fn set_next_pc(&mut self, next_pc: u64) {
        self.next_pc = next_pc;
    }

    /// Set the exit code.
    pub fn set_exit_code(&mut self, exit_code: u32) {
        self.exit_code = exit_code;
    }
}
