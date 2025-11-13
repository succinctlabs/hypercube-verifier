use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use hashbrown::HashMap;
use sp1_hypercube::air::{PublicValues, PROOF_NONCE_NUM_WORDS};
use sp1_jit::MinimalTrace;

use crate::{
    events::{
        AluEvent, BranchEvent, IntoMemoryRecord, JumpEvent, MemInstrEvent, MemoryLocalEvent,
        MemoryReadRecord, MemoryRecord, MemoryRecordEnum, MemoryWriteRecord, PrecompileEvent,
        SyscallEvent, UTypeEvent,
    },
    syscalls::SyscallCode,
    vm::{
        results::{
            AluResult, BranchResult, CycleResult, EcallResult, JumpResult, LoadResult,
            MaybeImmediate, StoreResult, UTypeResult,
        },
        syscall::SyscallRuntime,
        CoreVM,
    },
    ALUTypeRecord, ExecutionError, ExecutionRecord, ITypeRecord, Instruction, JTypeRecord,
    MemoryAccessRecord, Opcode, Program, RTypeRecord, Register, SP1CoreOpts,
};

/// A RISC-V VM that uses a [`MinimalTrace`] to create a [`ExecutionRecord`].
pub struct TracingVM<'a> {
    /// The core VM.
    pub core: CoreVM<'a>,
    /// The local memory access for the CPU.
    pub local_memory_access: LocalMemoryAccess,
    /// The local memory access for any deferred precompiles.
    pub precompile_local_memory_access: Option<LocalMemoryAccess>,
    /// The execution record were populating.
    pub record: &'a mut ExecutionRecord,
}

impl TracingVM<'_> {
    /// Execute the program until it halts.
    pub fn execute(&mut self) -> Result<CycleResult, ExecutionError> {
        if self.core.is_done() {
            return Ok(CycleResult::Done(true));
        }

        loop {
            match self.execute_instruction()? {
                // Continue executing the program.
                CycleResult::Done(false) => {}
                CycleResult::TraceEnd => {
                    self.register_refresh();
                    self.postprocess();
                    return Ok(CycleResult::ShardBoundary);
                }
                CycleResult::Done(true) => {
                    self.postprocess();
                    return Ok(CycleResult::Done(true));
                }
                CycleResult::ShardBoundary => {
                    unreachable!("Shard boundary should never be returned for tracing VM")
                }
            }
        }
    }

    /// Execute the next instruction at the current PC.
    pub fn execute_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        let instruction = self.core.fetch();
        if instruction.is_none() {
            unreachable!("Fetching the next instruction failed");
        }

        // SAFETY: The instruction is guaranteed to be valid as we checked for `is_none` above.
        let instruction = unsafe { *instruction.unwrap_unchecked() };

        match &instruction.opcode {
            Opcode::ADD
            | Opcode::ADDI
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SLLW
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SRLW
            | Opcode::SRAW
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::MUL
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::MULH
            | Opcode::MULW
            | Opcode::DIVU
            | Opcode::REMU
            | Opcode::DIV
            | Opcode::REM
            | Opcode::DIVW
            | Opcode::ADDW
            | Opcode::SUBW
            | Opcode::DIVUW
            | Opcode::REMUW
            | Opcode::REMW => {
                self.execute_alu(&instruction);
            }
            Opcode::LB
            | Opcode::LBU
            | Opcode::LH
            | Opcode::LHU
            | Opcode::LW
            | Opcode::LWU
            | Opcode::LD => self.execute_load(&instruction)?,
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                self.execute_store(&instruction)?;
            }
            Opcode::JAL | Opcode::JALR => {
                self.execute_jump(&instruction);
            }
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.execute_branch(&instruction);
            }
            Opcode::LUI | Opcode::AUIPC => {
                self.execute_utype(&instruction);
            }
            Opcode::ECALL => self.execute_ecall(&instruction)?,
            Opcode::EBREAK | Opcode::UNIMP => {
                unreachable!("Invalid opcode for `execute_instruction`: {:?}", instruction.opcode)
            }
        }

        Ok(self.core.advance())
    }

    fn postprocess(&mut self) {
        if self.record.last_timestamp == 0 {
            self.record.last_timestamp = self.core.clk();
        }

        self.record.program = self.core.program.clone();
        if self.record.contains_cpu() {
            self.record.public_values.pc_start = self.record.pc_start.unwrap();
            self.record.public_values.next_pc = self.record.next_pc;
            self.record.public_values.exit_code = self.record.exit_code;
            self.record.public_values.last_timestamp = self.record.last_timestamp;
            self.record.public_values.initial_timestamp = self.record.initial_timestamp;
        }

        for (_, event) in self.local_memory_access.inner.drain() {
            self.record.cpu_local_memory_access.push(event);
        }
    }

    fn register_refresh(&mut self) {
        for (addr, record) in self.core.register_refresh().into_iter().enumerate() {
            self.local_memory_access.insert_record(addr as u64, record);

            self.record.bump_memory_events.push((
                MemoryRecordEnum::Read(record),
                addr as u64,
                true,
            ));
        }
    }

    /// Get the current registers (immutable).
    #[must_use]
    pub fn registers(&self) -> &[MemoryRecord; 32] {
        self.core.registers()
    }

    /// This object is used to read and write memory in a precompile.
    #[must_use]
    pub fn registers_mut(&mut self) -> &mut [MemoryRecord; 32] {
        self.core.registers_mut()
    }
}

impl<'a> TracingVM<'a> {
    /// Create a new full-tracing VM from a minimal trace.
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        opts: SP1CoreOpts,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        record: &'a mut ExecutionRecord,
    ) -> Self {
        record.initial_timestamp = trace.clk_start();

        Self {
            core: CoreVM::new(trace, program, opts, proof_nonce),
            record,
            local_memory_access: LocalMemoryAccess::default(),
            precompile_local_memory_access: None,
        }
    }

    /// Get the public values from the record.
    #[must_use]
    pub fn public_values(&self) -> &PublicValues<u32, u64, u64, u32> {
        &self.record.public_values
    }

    /// Execute a load instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the load instruction.
    pub fn execute_load(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let LoadResult { mut a, b, c, rs1, rd, addr, rr_record, rw_record, mr_record } =
            self.core.execute_load(instruction)?;

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rw_record)),
            b: Some(MemoryRecordEnum::Read(rr_record)),
            c: None,
            memory: Some(MemoryRecordEnum::Read(mr_record)),
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.local_memory_access.insert_record(rd as u64, rw_record);
        self.local_memory_access.insert_record(rs1 as u64, rr_record);
        self.local_memory_access.insert_record(addr & !0b111, mr_record);

        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);
        self.emit_mem_instr_event(instruction, a, b, c, &mem_access_record, op_a_0);

        Ok(())
    }

    /// Execute a store instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the store instruction.
    fn execute_store(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let StoreResult { mut a, b, c, rs1, rs2, addr, rs1_record, rs2_record, mw_record } =
            self.core.execute_store(instruction)?;

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Read(rs1_record)),
            b: Some(MemoryRecordEnum::Read(rs2_record)),
            c: None,
            memory: Some(MemoryRecordEnum::Write(mw_record)),
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.local_memory_access.insert_record(addr & !0b111, mw_record);
        self.local_memory_access.insert_record(rs1 as u64, rs1_record);
        self.local_memory_access.insert_record(rs2 as u64, rs2_record);

        self.emit_mem_instr_event(instruction, a, b, c, &mem_access_record, op_a_0);
        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);

        Ok(())
    }

    /// Execute an ALU instruction and emit the events.
    fn execute_alu(&mut self, instruction: &Instruction) {
        let AluResult { rd, rw_record, mut a, b, c, rs1, rs2 } = self.core.execute_alu(instruction);

        if let MaybeImmediate::Register(rs2, rs2_record) = rs2 {
            self.local_memory_access.insert_record(rs2 as u64, rs2_record);
        }

        if let MaybeImmediate::Register(rs1, rs1_record) = rs1 {
            self.local_memory_access.insert_record(rs1 as u64, rs1_record);
        }

        self.local_memory_access.insert_record(rd as u64, rw_record);

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rw_record)),
            b: rs1.record().map(|r| MemoryRecordEnum::Read(*r)),
            c: rs2.record().map(|r| MemoryRecordEnum::Read(*r)),
            memory: None,
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);
        self.emit_alu_event(instruction, a, b, c, &mem_access_record, op_a_0);
    }

    /// Execute a jump instruction and emit the events.
    fn execute_jump(&mut self, instruction: &Instruction) {
        let JumpResult { mut a, b, c, rd, rd_record, rs1 } = self.core.execute_jump(instruction);

        if let MaybeImmediate::Register(rs1, rs1_record) = rs1 {
            self.local_memory_access.insert_record(rs1 as u64, rs1_record);
        }

        self.local_memory_access.insert_record(rd as u64, rd_record);

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rd_record)),
            b: rs1.record().map(|r| MemoryRecordEnum::Read(*r)),
            c: None,
            memory: None,
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);
        match instruction.opcode {
            Opcode::JAL => self.emit_jal_event(
                instruction,
                a,
                b,
                c,
                &mem_access_record,
                op_a_0,
                self.core.next_pc(),
            ),
            Opcode::JALR => self.emit_jalr_event(
                instruction,
                a,
                b,
                c,
                &mem_access_record,
                op_a_0,
                self.core.next_pc(),
            ),
            _ => unreachable!("Invalid opcode for `execute_jump`: {:?}", instruction.opcode),
        }
    }

    /// Execute a branch instruction and emit the events.
    fn execute_branch(&mut self, instruction: &Instruction) {
        let BranchResult { mut a, rs1, a_record, b, rs2, b_record, c } =
            self.core.execute_branch(instruction);

        self.local_memory_access.insert_record(rs2 as u64, b_record);
        self.local_memory_access.insert_record(rs1 as u64, a_record);

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Read(a_record)),
            b: Some(MemoryRecordEnum::Read(b_record)),
            c: None,
            memory: None,
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);
        self.emit_branch_event(
            instruction,
            a,
            b,
            c,
            &mem_access_record,
            op_a_0,
            self.core.next_pc(),
        );
    }

    /// Execute a U-type instruction and emit the events.   
    fn execute_utype(&mut self, instruction: &Instruction) {
        let UTypeResult { mut a, b, c, rd, rw_record } = self.core.execute_utype(instruction);

        self.local_memory_access.insert_record(rd as u64, rw_record);

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rw_record)),
            b: None,
            c: None,
            memory: None,
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);
        self.emit_utype_event(instruction, a, b, c, &mem_access_record, op_a_0);
    }

    /// Execute an ecall instruction and emit the events.
    fn execute_ecall(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let code = self.core.read_code();

        // If the syscall is not retained, we need to track the local memory access separately.
        //
        // Note that the `precompile_local_memory_access` is set to `None` in the
        // `postprocess_precompile` method.
        if !self.core().is_retained_syscall(code) && code.should_send() == 1 {
            self.precompile_local_memory_access = Some(LocalMemoryAccess::default());
        }

        // Actually execute the ecall.
        let EcallResult { a: _, a_record, b, b_record, c, c_record } =
            CoreVM::<'a>::execute_ecall(self, instruction, code)?;

        self.local_memory_access.insert_record(Register::X11 as u64, c_record);
        self.local_memory_access.insert_record(Register::X10 as u64, b_record);
        self.local_memory_access.insert_record(Register::X5 as u64, a_record);

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(a_record)),
            b: Some(MemoryRecordEnum::Read(b_record)),
            c: Some(MemoryRecordEnum::Read(c_record)),
            memory: None,
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        self.emit_events(
            self.core.clk(),
            self.core.next_pc(),
            instruction,
            &mem_access_record,
            self.core.exit_code(),
        );

        self.emit_syscall_event(
            self.core.clk(),
            code,
            b,
            c,
            &mem_access_record,
            op_a_0,
            self.core.next_pc(),
            self.core.exit_code(),
            instruction,
        );

        Ok(())
    }
}

impl TracingVM<'_> {
    /// Emit events for this cycle.
    #[allow(clippy::too_many_arguments)]
    fn emit_events(
        &mut self,
        clk: u64,
        next_pc: u64,
        instruction: &Instruction,
        record: &MemoryAccessRecord,
        exit_code: u32,
    ) {
        self.record.pc_start.get_or_insert(self.core.pc());
        self.record.next_pc = next_pc;
        self.record.exit_code = exit_code;
        self.record.cpu_event_count += 1;

        let increment = self.core.next_clk() - clk;

        let bump1 = clk % (1 << 24) + increment >= (1 << 24);
        let bump2 = !instruction.is_with_correct_next_pc()
            && next_pc == self.core.pc().wrapping_add(4)
            && (next_pc >> 16) != (self.core.pc() >> 16);

        if bump1 || bump2 {
            self.record.bump_state_events.push((clk, increment, bump2, next_pc));
        }

        if let Some(x) = record.a {
            if x.current_record().timestamp >> 24 != x.previous_record().timestamp >> 24 {
                self.record.bump_memory_events.push((x, instruction.op_a as u64, false));
            }
        }
        if let Some(x) = record.b {
            if x.current_record().timestamp >> 24 != x.previous_record().timestamp >> 24 {
                self.record.bump_memory_events.push((x, instruction.op_b, false));
            }
        }
        if let Some(x) = record.c {
            if x.current_record().timestamp >> 24 != x.previous_record().timestamp >> 24 {
                self.record.bump_memory_events.push((x, instruction.op_c, false));
            }
        }
    }

    /// Emit a memory instruction event.
    #[inline]
    fn emit_mem_instr_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
    ) {
        let opcode = instruction.opcode;
        let event = MemInstrEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            opcode,
            a,
            b,
            c,
            op_a_0,
            // SAFETY: We explicity populate the memory of the record on the following callsites:
            // - `execute_load`
            // - `execute_store`
            mem_access: unsafe { record.memory.unwrap_unchecked() },
        };

        let record = ITypeRecord::new(record, instruction);
        if matches!(
            opcode,
            Opcode::LB
                | Opcode::LBU
                | Opcode::LH
                | Opcode::LHU
                | Opcode::LW
                | Opcode::LWU
                | Opcode::LD
        ) && op_a_0
        {
            self.record.memory_load_x0_events.push((event, record));
        } else if matches!(opcode, Opcode::LB | Opcode::LBU) {
            self.record.memory_load_byte_events.push((event, record));
        } else if matches!(opcode, Opcode::LH | Opcode::LHU) {
            self.record.memory_load_half_events.push((event, record));
        } else if matches!(opcode, Opcode::LW | Opcode::LWU) {
            self.record.memory_load_word_events.push((event, record));
        } else if opcode == Opcode::LD {
            self.record.memory_load_double_events.push((event, record));
        } else if opcode == Opcode::SB {
            self.record.memory_store_byte_events.push((event, record));
        } else if opcode == Opcode::SH {
            self.record.memory_store_half_events.push((event, record));
        } else if opcode == Opcode::SW {
            self.record.memory_store_word_events.push((event, record));
        } else if opcode == Opcode::SD {
            self.record.memory_store_double_events.push((event, record));
        }
    }

    /// Emit an ALU event.
    fn emit_alu_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
    ) {
        let opcode = instruction.opcode;
        let event = AluEvent { clk: self.core.clk(), pc: self.core.pc(), opcode, a, b, c, op_a_0 };
        match opcode {
            Opcode::ADD => {
                let record = RTypeRecord::new(record, instruction);
                self.record.add_events.push((event, record));
            }
            Opcode::ADDW => {
                let record = ALUTypeRecord::new(record, instruction);
                self.record.addw_events.push((event, record));
            }
            Opcode::ADDI => {
                let record = ITypeRecord::new(record, instruction);
                self.record.addi_events.push((event, record));
            }
            Opcode::SUB => {
                let record = RTypeRecord::new(record, instruction);
                self.record.sub_events.push((event, record));
            }
            Opcode::SUBW => {
                let record = RTypeRecord::new(record, instruction);
                self.record.subw_events.push((event, record));
            }
            Opcode::XOR | Opcode::OR | Opcode::AND => {
                let record = ALUTypeRecord::new(record, instruction);
                self.record.bitwise_events.push((event, record));
            }
            Opcode::SLL | Opcode::SLLW => {
                let record = ALUTypeRecord::new(record, instruction);
                self.record.shift_left_events.push((event, record));
            }
            Opcode::SRL | Opcode::SRA | Opcode::SRLW | Opcode::SRAW => {
                let record = ALUTypeRecord::new(record, instruction);
                self.record.shift_right_events.push((event, record));
            }
            Opcode::SLT | Opcode::SLTU => {
                let record = ALUTypeRecord::new(record, instruction);
                self.record.lt_events.push((event, record));
            }
            Opcode::MUL | Opcode::MULHU | Opcode::MULHSU | Opcode::MULH | Opcode::MULW => {
                let record = RTypeRecord::new(record, instruction);
                self.record.mul_events.push((event, record));
            }
            Opcode::DIVU
            | Opcode::REMU
            | Opcode::DIV
            | Opcode::REM
            | Opcode::DIVW
            | Opcode::DIVUW
            | Opcode::REMUW
            | Opcode::REMW => {
                let record = RTypeRecord::new(record, instruction);
                self.record.divrem_events.push((event, record));
            }
            _ => unreachable!(),
        }
    }

    /// Emit a jal event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_jal_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
        next_pc: u64,
    ) {
        let event = JumpEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            next_pc,
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
        let record = JTypeRecord::new(record, instruction);
        self.record.jal_events.push((event, record));
    }

    /// Emit a jalr event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_jalr_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
        next_pc: u64,
    ) {
        let event = JumpEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            next_pc,
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
        let record = ITypeRecord::new(record, instruction);
        self.record.jalr_events.push((event, record));
    }

    /// Emit a branch event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_branch_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
        next_pc: u64,
    ) {
        let event = BranchEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            next_pc,
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
        let record = ITypeRecord::new(record, instruction);
        self.record.branch_events.push((event, record));
    }

    /// Emit a `UType` event.
    #[inline]
    fn emit_utype_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
    ) {
        let event = UTypeEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
        let record = JTypeRecord::new(record, instruction);
        self.record.utype_events.push((event, record));
    }

    /// Emit a syscall event.
    #[allow(clippy::too_many_arguments)]
    fn emit_syscall_event(
        &mut self,
        clk: u64,
        syscall_code: SyscallCode,
        arg1: u64,
        arg2: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
        next_pc: u64,
        exit_code: u32,
        instruction: &Instruction,
    ) {
        let syscall_event =
            self.syscall_event(clk, syscall_code, arg1, arg2, op_a_0, next_pc, exit_code);

        let record = RTypeRecord::new(record, instruction);
        self.record.syscall_events.push((syscall_event, record));
    }
}

impl<'a> SyscallRuntime<'a> for TracingVM<'a> {
    const TRACING: bool = true;

    fn core(&self) -> &CoreVM<'a> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a> {
        &mut self.core
    }

    /// Create a syscall event.
    #[inline]
    fn syscall_event(
        &self,
        clk: u64,
        syscall_code: SyscallCode,
        arg1: u64,
        arg2: u64,
        op_a_0: bool,
        next_pc: u64,
        exit_code: u32,
    ) -> SyscallEvent {
        // should_send: if the syscall is usually sent and it is not manually set as internal.
        let should_send =
            syscall_code.should_send() != 0 && !self.core.is_retained_syscall(syscall_code);

        SyscallEvent {
            pc: self.core.pc(),
            next_pc,
            clk,
            op_a_0,
            should_send,
            syscall_code,
            syscall_id: syscall_code.syscall_id(),
            arg1,
            arg2,
            exit_code,
        }
    }

    fn add_precompile_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        self.record.precompile_events.add_event(syscall_code, syscall_event, event);
    }

    fn record_mut(&mut self) -> &mut ExecutionRecord {
        self.record
    }

    fn rr(&mut self, register: usize) -> MemoryReadRecord {
        let record = SyscallRuntime::rr(self.core_mut(), register);

        if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
            local_memory_access.insert_record(register as u64, record);
        } else {
            self.local_memory_access.insert_record(register as u64, record);
        }

        record
    }

    fn mr(&mut self, addr: u64) -> MemoryReadRecord {
        let record = SyscallRuntime::mr(self.core_mut(), addr);

        if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
            local_memory_access.insert_record(addr, record);
        } else {
            self.local_memory_access.insert_record(addr, record);
        }

        record
    }

    fn mr_slice(&mut self, addr: u64, len: usize) -> Vec<MemoryReadRecord> {
        let records = SyscallRuntime::mr_slice(self.core_mut(), addr, len);

        for (i, record) in records.iter().enumerate() {
            if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
                local_memory_access.insert_record(addr + i as u64 * 8, *record);
            } else {
                self.local_memory_access.insert_record(addr + i as u64 * 8, *record);
            }
        }

        records
    }

    fn mw(&mut self, addr: u64) -> MemoryWriteRecord {
        let record = SyscallRuntime::mw(self.core_mut(), addr);

        if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
            local_memory_access.insert_record(addr, record);
        } else {
            self.local_memory_access.insert_record(addr, record);
        }

        record
    }

    fn mw_slice(&mut self, addr: u64, len: usize) -> Vec<MemoryWriteRecord> {
        let records = SyscallRuntime::mw_slice(self.core_mut(), addr, len);

        for (i, record) in records.iter().enumerate() {
            if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
                local_memory_access.insert_record(addr + i as u64 * 8, *record);
            } else {
                self.local_memory_access.insert_record(addr + i as u64 * 8, *record);
            }
        }

        records
    }

    fn postprocess_precompile(&mut self) -> Vec<MemoryLocalEvent> {
        let mut precompile_local_memory_access = Vec::new();

        if let Some(mut local_memory_access) =
            std::mem::take(&mut self.precompile_local_memory_access)
        {
            for (addr, event) in local_memory_access.drain() {
                if let Some(cpu_mem_access) = self.local_memory_access.remove(&addr) {
                    self.record.cpu_local_memory_access.push(cpu_mem_access);
                }

                precompile_local_memory_access.push(event);
            }
        }

        precompile_local_memory_access
    }
}

#[derive(Debug, Default)]
pub struct LocalMemoryAccess {
    pub inner: HashMap<u64, MemoryLocalEvent>,
}

impl LocalMemoryAccess {
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn insert_record(&mut self, addr: u64, event: impl IntoMemoryRecord) {
        self.inner
            .entry(addr)
            .and_modify(|e| {
                let current_record = event.current_record();
                let previous_record = event.previous_record();

                // The latest record is the one with the highest timestamp.
                if current_record.timestamp > e.final_mem_access.timestamp {
                    e.final_mem_access = current_record;
                }

                // The initial record is the one with the lowest timestamp.
                if previous_record.timestamp < e.initial_mem_access.timestamp {
                    e.initial_mem_access = previous_record;
                }
            })
            .or_insert_with(|| MemoryLocalEvent {
                addr,
                initial_mem_access: event.previous_record(),
                final_mem_access: event.current_record(),
            });
    }
}

impl Deref for LocalMemoryAccess {
    type Target = HashMap<u64, MemoryLocalEvent>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for LocalMemoryAccess {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
