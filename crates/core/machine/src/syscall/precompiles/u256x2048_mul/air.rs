use crate::{
    air::SP1CoreAirBuilder,
    memory::{MemoryAccessCols, MemoryAccessColsU8},
    operations::{field::field_op::FieldOpCols, AddrAddOperation, SyscallAddrOperation},
    utils::{limbs_to_words, next_multiple_of_32, words_to_bytes_le},
};
use itertools::Itertools;
use num::{BigUint, One, Zero};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteRecord, FieldOperation, MemoryRecordEnum, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program, Register,
};
use sp1_curves::{
    params::{Limbs, NumLimbs, NumWords},
    uint256::U256Field,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    Word,
};
use sp1_primitives::polynomial::Polynomial;
use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use typenum::Unsigned;

/// The number of columns in the U256x2048MulCols.
const NUM_COLS: usize = size_of::<U256x2048MulCols<u8>>();

#[derive(Default)]
pub struct U256x2048MulChip;

impl U256x2048MulChip {
    pub const fn new() -> Self {
        Self
    }
}
type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;
const LO_REGISTER: u64 = Register::X12 as u64;
const HI_REGISTER: u64 = Register::X13 as u64;

/// A set of columns for the U256x2048Mul operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct U256x2048MulCols<T> {
    /// The high bits of the clk of the syscall.
    pub clk_high: T,

    /// The low bits of the clk of the syscall.
    pub clk_low: T,

    /// The pointer to the first input.
    pub a_ptr: SyscallAddrOperation<T>,

    /// The pointer to the second input.
    pub b_ptr: SyscallAddrOperation<T>,

    pub lo_ptr: SyscallAddrOperation<T>,
    pub hi_ptr: SyscallAddrOperation<T>,

    pub a_addrs: [AddrAddOperation<T>; WORDS_FIELD_ELEMENT],
    pub b_addrs: [AddrAddOperation<T>; WORDS_FIELD_ELEMENT * 8],
    pub lo_addrs: [AddrAddOperation<T>; WORDS_FIELD_ELEMENT * 8],
    pub hi_addrs: [AddrAddOperation<T>; WORDS_FIELD_ELEMENT],

    pub lo_ptr_memory: MemoryAccessCols<T>,
    pub lo_ptr_memory_value: [T; 3],
    pub hi_ptr_memory: MemoryAccessCols<T>,
    pub hi_ptr_memory_value: [T; 3],

    // Memory columns.
    pub a_memory: [MemoryAccessColsU8<T>; WORDS_FIELD_ELEMENT],
    pub b_memory: [MemoryAccessColsU8<T>; WORDS_FIELD_ELEMENT * 8],
    pub lo_memory: [MemoryAccessCols<T>; WORDS_FIELD_ELEMENT * 8],
    pub hi_memory: [MemoryAccessCols<T>; WORDS_FIELD_ELEMENT],

    // Output values. We compute (x * y) % 2^2048 and (x * y) / 2^2048.
    pub a_mul_b1: FieldOpCols<T, U256Field>,
    pub ab2_plus_carry: FieldOpCols<T, U256Field>,
    pub ab3_plus_carry: FieldOpCols<T, U256Field>,
    pub ab4_plus_carry: FieldOpCols<T, U256Field>,
    pub ab5_plus_carry: FieldOpCols<T, U256Field>,
    pub ab6_plus_carry: FieldOpCols<T, U256Field>,
    pub ab7_plus_carry: FieldOpCols<T, U256Field>,
    pub ab8_plus_carry: FieldOpCols<T, U256Field>,
    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for U256x2048MulChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "U256XU2048Mul".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.get_precompile_events(SyscallCode::U256XU2048_MUL).len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows = <U256x2048MulChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::U256XU2048_MUL);
        let chunk_size = 1;
        let num_event_rows = events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let buffer_as_slice =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_COLS) };

        let mut new_byte_lookup_events = Vec::new();

        buffer_as_slice.chunks_exact_mut(chunk_size * NUM_COLS).enumerate().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    if idx < events.len() {
                        let event = &events[idx].1;
                        let event = if let PrecompileEvent::U256xU2048Mul(event) = event {
                            event
                        } else {
                            unreachable!()
                        };

                        let cols: &mut U256x2048MulCols<F> = row.borrow_mut();
                        // Assign basic values to the columns.
                        cols.is_real = F::one();

                        cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
                        cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

                        cols.a_ptr.populate(&mut new_byte_lookup_events, event.a_ptr, 32);
                        cols.b_ptr.populate(&mut new_byte_lookup_events, event.b_ptr, 256);
                        cols.lo_ptr.populate(&mut new_byte_lookup_events, event.lo_ptr, 256);
                        cols.hi_ptr.populate(&mut new_byte_lookup_events, event.hi_ptr, 32);

                        // Populate memory accesses for lo_ptr and hi_ptr.
                        let lo_ptr_memory_record = MemoryRecordEnum::Read(event.lo_ptr_memory);
                        let hi_ptr_memory_record = MemoryRecordEnum::Read(event.hi_ptr_memory);

                        assert_eq!(lo_ptr_memory_record.prev_value(), event.lo_ptr);
                        assert_eq!(hi_ptr_memory_record.prev_value(), event.hi_ptr);

                        cols.lo_ptr_memory
                            .populate(lo_ptr_memory_record, &mut new_byte_lookup_events);
                        cols.hi_ptr_memory
                            .populate(hi_ptr_memory_record, &mut new_byte_lookup_events);

                        // Populate memory columns.
                        for i in 0..WORDS_FIELD_ELEMENT {
                            let record = MemoryRecordEnum::Read(event.a_memory_records[i]);
                            cols.a_memory[i].populate(record, &mut new_byte_lookup_events);
                            cols.a_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.a_ptr,
                                (i * 8) as u64,
                            );
                        }
                        for i in 0..WORDS_FIELD_ELEMENT * 8 {
                            let record = MemoryRecordEnum::Read(event.b_memory_records[i]);
                            cols.b_memory[i].populate(record, &mut new_byte_lookup_events);
                            cols.b_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.b_ptr,
                                (i * 8) as u64,
                            );
                        }

                        for i in 0..WORDS_FIELD_ELEMENT * 8 {
                            let record = MemoryRecordEnum::Write(event.lo_memory_records[i]);
                            cols.lo_memory[i].populate(record, &mut new_byte_lookup_events);
                            cols.lo_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.lo_ptr,
                                8 * i as u64,
                            );
                        }

                        for i in 0..WORDS_FIELD_ELEMENT {
                            let record = MemoryRecordEnum::Write(event.hi_memory_records[i]);
                            cols.hi_memory[i].populate(record, &mut new_byte_lookup_events);
                            cols.hi_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.hi_ptr,
                                8 * i as u64,
                            );
                        }

                        let a = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.a));
                        let b_array: [BigUint; 8] = event
                            .b
                            .chunks(4)
                            .map(|chunk| BigUint::from_bytes_le(&words_to_bytes_le::<32>(chunk)))
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap();

                        let effective_modulus = BigUint::one() << 256;

                        let mut carries = vec![BigUint::zero(); 9];
                        let mut ab_plus_carry_cols = [
                            &mut cols.a_mul_b1,
                            &mut cols.ab2_plus_carry,
                            &mut cols.ab3_plus_carry,
                            &mut cols.ab4_plus_carry,
                            &mut cols.ab5_plus_carry,
                            &mut cols.ab6_plus_carry,
                            &mut cols.ab7_plus_carry,
                            &mut cols.ab8_plus_carry,
                        ];

                        for (i, col) in ab_plus_carry_cols.iter_mut().enumerate() {
                            let (_, carry) = col.populate_mul_and_carry(
                                &mut new_byte_lookup_events,
                                &a,
                                &b_array[i],
                                &carries[i],
                                &effective_modulus,
                            );
                            carries[i + 1] = carry;
                        }
                    }
                })
            },
        );

        for row in num_event_rows..padded_nb_rows {
            let row_start = row * NUM_COLS;
            let row = unsafe {
                core::slice::from_raw_parts_mut(
                    buffer[row_start..].as_mut_ptr() as *mut F,
                    NUM_COLS,
                )
            };

            let cols: &mut U256x2048MulCols<F> = row.borrow_mut();

            let x = BigUint::zero();
            let y = BigUint::zero();
            let z = BigUint::zero();
            let modulus = BigUint::one() << 256;

            // Populate all the mul and carry columns with zero values.
            cols.a_mul_b1.populate(&mut vec![], &x, &y, FieldOperation::Mul);
            cols.ab2_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab3_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab4_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab5_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab6_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab7_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab8_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::U256XU2048_MUL).is_empty()
        }
    }
}

impl<F> BaseAir<F> for U256x2048MulChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB> Air<AB> for U256x2048MulChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &U256x2048MulCols<AB::Var> = (*local).borrow();

        // Assert that is_real is a boolean.
        builder.assert_bool(local.is_real);

        let a_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 32, local.a_ptr, local.is_real.into());
        let b_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 256, local.b_ptr, local.is_real.into());
        let lo_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 256, local.lo_ptr, local.is_real.into());
        let hi_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 32, local.hi_ptr, local.is_real.into());

        // a_addrs[i] = a_ptr + 8 * i
        for i in 0..local.a_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([a_ptr[0].into(), a_ptr[1].into(), a_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.a_addrs[i],
                local.is_real.into(),
            );
        }

        // b_addrs[i] = b_ptr + 8 * i
        for i in 0..local.b_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([b_ptr[0].into(), b_ptr[1].into(), b_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.b_addrs[i],
                local.is_real.into(),
            );
        }

        // lo_addrs[i] = lo_ptr + 8 * i
        for i in 0..local.lo_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([lo_ptr[0].into(), lo_ptr[1].into(), lo_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.lo_addrs[i],
                local.is_real.into(),
            );
        }

        // hi_addrs[i] = hi_ptr + 8 * i
        for i in 0..local.hi_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([hi_ptr[0].into(), hi_ptr[1].into(), hi_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.hi_addrs[i],
                local.is_real.into(),
            );
        }

        // Receive the arguments.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::U256XU2048_MUL.syscall_id()),
            a_ptr.map(Into::into),
            b_ptr.map(Into::into),
            local.is_real,
            InteractionScope::Local,
        );

        // Evaluate that the lo_ptr and hi_ptr are read from the correct memory locations.
        builder.eval_memory_access_read(
            local.clk_high,
            local.clk_low.into(),
            &[AB::Expr::from_canonical_u64(LO_REGISTER), AB::Expr::zero(), AB::Expr::zero()],
            local.lo_ptr_memory,
            local.is_real,
        );

        builder.eval_memory_access_read(
            local.clk_high,
            local.clk_low.into(),
            &[AB::Expr::from_canonical_u64(HI_REGISTER), AB::Expr::zero(), AB::Expr::zero()],
            local.hi_ptr_memory,
            local.is_real,
        );

        // Evaluate the memory accesses for a_memory and b_memory.
        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low.into(),
            &local.a_addrs.map(|addr| addr.value.map(Into::into)),
            &local.a_memory.iter().map(|access| access.memory_access).collect_vec(),
            local.is_real,
        );

        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low.into() + AB::Expr::one(),
            &local.b_addrs.map(|addr| addr.value.map(Into::into)),
            &local.b_memory.iter().map(|access| access.memory_access).collect_vec(),
            local.is_real,
        );

        let a_limbs_vec = builder.generate_limbs(&local.a_memory, local.is_real.into());
        let a_limbs: Limbs<AB::Expr, <U256Field as NumLimbs>::Limbs> =
            Limbs(a_limbs_vec.try_into().expect("failed to convert limbs"));

        // Iterate through chunks of 8 for b_memory and convert each chunk to its limbs.
        let b_limb_array: Vec<Limbs<AB::Expr, <U256Field as NumLimbs>::Limbs>> = local
            .b_memory
            .chunks(4)
            .map(|access| {
                Limbs(
                    builder
                        .generate_limbs(access, local.is_real.into())
                        .try_into()
                        .expect("failed to convert limbs"),
                )
            })
            .collect::<Vec<_>>();

        let mut coeff_2_256 = Vec::new();
        coeff_2_256.resize(32, AB::Expr::zero());
        coeff_2_256.push(AB::Expr::one());
        let modulus_polynomial: Polynomial<AB::Expr> = Polynomial::from_coefficients(&coeff_2_256);

        // Evaluate that each of the mul and carry columns are valid.
        let outputs = [
            &local.a_mul_b1,
            &local.ab2_plus_carry,
            &local.ab3_plus_carry,
            &local.ab4_plus_carry,
            &local.ab5_plus_carry,
            &local.ab6_plus_carry,
            &local.ab7_plus_carry,
            &local.ab8_plus_carry,
        ];

        outputs[0].eval_mul_and_carry(
            builder,
            &a_limbs,
            &b_limb_array[0],
            &Polynomial::from_coefficients(&[AB::Expr::zero()]),
            &modulus_polynomial,
            local.is_real,
        );

        for i in 1..outputs.len() {
            outputs[i].eval_mul_and_carry(
                builder,
                &a_limbs,
                &b_limb_array[i],
                &outputs[i - 1].carry,
                &modulus_polynomial,
                local.is_real,
            );
        }

        // Evaluate the memory accesses for lo_memory and hi_memory.
        let mut result_words = Vec::new();
        for i in 0..8 {
            let output_words = limbs_to_words::<AB>(outputs[i].result.0.to_vec());
            result_words.extend(output_words);
        }

        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::from_canonical_u8(2),
            &local.lo_addrs.map(|addr| addr.value.map(Into::into)),
            &local.lo_memory,
            result_words,
            local.is_real,
        );

        let output_carry_words = limbs_to_words::<AB>(outputs[outputs.len() - 1].carry.0.to_vec());
        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::from_canonical_u8(3),
            &local.hi_addrs.map(|addr| addr.value.map(Into::into)),
            &local.hi_memory,
            output_carry_words,
            local.is_real,
        );

        // Constrain that the lo_ptr is the value of lo_ptr_memory.
        for i in 0..3 {
            builder
                .when(local.is_real)
                .assert_eq(local.lo_ptr.addr[i], local.lo_ptr_memory.prev_value[i]);
        }
        builder.assert_eq(local.lo_ptr_memory.prev_value[3], AB::Expr::zero());

        // Constrain that the hi_ptr is the value of hi_ptr_memory.
        for i in 0..3 {
            builder
                .when(local.is_real)
                .assert_eq(local.hi_ptr.addr[i], local.hi_ptr_memory.prev_value[i]);
        }
        builder.assert_eq(local.hi_ptr_memory.prev_value[3], AB::Expr::zero());
    }
}
