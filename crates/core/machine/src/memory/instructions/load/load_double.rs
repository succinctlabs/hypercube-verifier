use slop_air::{Air, BaseAir};
use slop_matrix::Matrix;
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::PROT_READ;
use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use crate::{
    adapter::{
        register::i_type::{ITypeReader, ITypeReaderInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    memory::MemoryAccessCols,
    operations::{AddressOperation, AddressOperationInput},
    utils::{next_multiple_of_32, zeroed_f_vec},
};
use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::dense::RowMajorMatrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemInstrEvent, MemoryAccessPosition},
    ExecutionRecord, Opcode, Program, CLK_INC, PC_INC,
};

use sp1_hypercube::air::MachineAir;

#[derive(Default)]
pub struct LoadDoubleChip;

pub const NUM_LOAD_DOUBLE_COLUMNS: usize = size_of::<LoadDoubleColumns<u8>>();

/// The column layout for memory load double instructions.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct LoadDoubleColumns<T> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: ITypeReader<T>,

    /// Instance of `AddressOperation` to constrain the memory address.
    pub address_operation: AddressOperation<T>,

    /// Memory consistency columns for the memory access.
    pub memory_access: MemoryAccessCols<T>,

    /// Whether this is a real load word instruction.
    pub is_real: T,

    /// Whether the page protection is active.
    pub is_page_protect_active: T,
}

impl<F> BaseAir<F> for LoadDoubleChip {
    fn width(&self) -> usize {
        NUM_LOAD_DOUBLE_COLUMNS
    }
}

impl<F: PrimeField32> MachineAir<F> for LoadDoubleChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "LoadDouble".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = next_multiple_of_32(
            input.memory_load_double_events.len(),
            input.fixed_log2_rows::<F, _>(self),
        );
        Some(nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.memory_load_word_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows = <LoadDoubleChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_LOAD_DOUBLE_COLUMNS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_LOAD_DOUBLE_COLUMNS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_LOAD_DOUBLE_COLUMNS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut LoadDoubleColumns<F> = row.borrow_mut();

                    if idx < input.memory_load_double_events.len() {
                        let event = &input.memory_load_double_events[idx];
                        self.event_to_row(&event.0, cols, &mut blu);
                        cols.is_page_protect_active = F::from_canonical_u32(
                            input.public_values.is_untrusted_programs_enabled,
                        );
                        cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut blu, event.1);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_LOAD_DOUBLE_COLUMNS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.memory_load_double_events.is_empty()
        }
    }
}

impl LoadDoubleChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &MemInstrEvent,
        cols: &mut LoadDoubleColumns<F>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        // Populate memory accesses for reading from memory.
        cols.memory_access.populate(event.mem_access, blu);
        cols.address_operation.populate(blu, event.b, event.c);
        cols.is_real = F::one();
    }
}

impl<AB> Air<AB> for LoadDoubleChip
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &LoadDoubleColumns<AB::Var> = (*local).borrow();

        let clk_high = local.state.clk_high::<AB>();
        let clk_low = local.state.clk_low::<AB>();

        let opcode = AB::Expr::from_canonical_u32(Opcode::LD as u32);
        let funct3 = AB::Expr::from_canonical_u8(Opcode::LD.funct3().unwrap());
        let funct7 = AB::Expr::from_canonical_u8(Opcode::LD.funct7().unwrap_or(0));
        let base_opcode = AB::Expr::from_canonical_u32(Opcode::LD.base_opcode().0);
        let instr_type = AB::Expr::from_canonical_u32(Opcode::LD.instruction_type().0 as u32);

        builder.assert_bool(local.is_real);

        // Step 1. Compute the address, and check offsets and address bounds.
        let aligned_addr = <AddressOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            AddressOperationInput::new(
                local.adapter.b().map(Into::into),
                local.adapter.c().map(Into::into),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
                local.is_real.into(),
                local.address_operation,
            ),
        );

        // Step 2. Read the memory address and check page prot access.
        builder.eval_memory_access_read(
            clk_high.clone(),
            clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            &aligned_addr.clone().map(Into::into),
            local.memory_access,
            local.is_real,
        );

        // Check page protect active is set correctly based on public value and is_real
        let public_values = builder.extract_public_values();
        let expected_page_protect_active =
            public_values.is_untrusted_programs_enabled.into() * local.is_real;
        builder.assert_eq(local.is_page_protect_active, expected_page_protect_active);

        builder.send_page_prot(
            clk_high.clone(),
            clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            &aligned_addr.clone().map(Into::into),
            AB::Expr::from_canonical_u8(PROT_READ),
            local.is_page_protect_active.into(),
        );

        // This chip requires `op_a != x0`.
        builder.assert_zero(local.adapter.op_a_0);

        // Constrain the state of the CPU.
        <CPUState<AB::F> as SP1Operation<AB>>::eval(
            builder,
            CPUStateInput::new(
                local.state,
                [
                    local.state.pc[0] + AB::F::from_canonical_u32(PC_INC),
                    local.state.pc[1].into(),
                    local.state.pc[2].into(),
                ],
                AB::Expr::from_canonical_u32(CLK_INC),
                local.is_real.into(),
            ),
        );

        // Constrain the program and register reads.
        <ITypeReader<AB::F> as SP1Operation<AB>>::eval(
            builder,
            ITypeReaderInput::new(
                clk_high,
                clk_low,
                local.state.pc,
                opcode,
                [instr_type, base_opcode, funct3, funct7],
                local.memory_access.prev_value.map(Into::into),
                local.adapter,
                local.is_real.into(),
            ),
        );
    }
}
