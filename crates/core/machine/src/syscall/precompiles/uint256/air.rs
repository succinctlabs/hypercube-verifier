use crate::{
    air::SP1Operation,
    memory::MemoryAccessColsU8,
    operations::{field::field_op::FieldOpCols, AddrAddOperation, IsZeroOperationInput},
};

use crate::{
    air::SP1CoreAirBuilder,
    operations::{field::range::FieldLtCols, IsZeroOperation, SyscallAddrOperation},
    utils::{limbs_to_words, next_multiple_of_32, words_to_bytes_le, words_to_bytes_le_vec},
};
use generic_array::GenericArray;
use itertools::Itertools;
use num::{BigUint, One, Zero};
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteRecord, FieldOperation, MemoryRecordEnum, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
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

/// The number of columns in the Uint256MulCols.
const NUM_COLS: usize = size_of::<Uint256MulCols<u8>>();

#[derive(Default)]
pub struct Uint256MulChip;

impl Uint256MulChip {
    pub const fn new() -> Self {
        Self
    }
}

type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

/// A set of columns for the Uint256Mul operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Uint256MulCols<T> {
    /// The high bits of the clk of the syscall.
    pub clk_high: T,

    /// The low bits of the clk of the syscall.
    pub clk_low: T,

    /// The pointer to the first input.
    pub x_ptr: SyscallAddrOperation<T>,

    /// The pointer to the second input, which contains the y value and the modulus.
    pub y_ptr: SyscallAddrOperation<T>,

    pub x_addrs: [AddrAddOperation<T>; WORDS_FIELD_ELEMENT],
    pub y_and_modulus_addrs: [AddrAddOperation<T>; 2 * WORDS_FIELD_ELEMENT],

    // Memory columns.
    // x_memory is written to with the result, which is why it is of type MemoryWriteCols.
    pub x_memory: GenericArray<MemoryAccessColsU8<T>, WordsFieldElement>,
    pub y_memory: GenericArray<MemoryAccessColsU8<T>, WordsFieldElement>,
    pub modulus_memory: GenericArray<MemoryAccessColsU8<T>, WordsFieldElement>,

    /// Columns for checking if modulus is zero.
    /// If it's zero, then use 2^256 as the effective modulus.
    pub modulus_is_zero: IsZeroOperation<T>,

    /// Column that is equal to is_real * (1 - modulus_is_zero.result).
    pub modulus_is_not_zero: T,

    // Output values. We compute (x * y) % modulus.
    pub output: FieldOpCols<T, U256Field>,

    pub output_range_check: FieldLtCols<T, U256Field>,

    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for Uint256MulChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Uint256MulMod".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.get_precompile_events(SyscallCode::UINT256_MUL).len();
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
        let padded_nb_rows = <Uint256MulChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::UINT256_MUL);
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
                        let event = if let PrecompileEvent::Uint256Mul(event) = event {
                            event
                        } else {
                            unreachable!()
                        };

                        unsafe {
                            core::ptr::write_bytes(row.as_mut_ptr(), 0, NUM_COLS);
                        }

                        let cols: &mut Uint256MulCols<F> = row.borrow_mut();

                        // Decode uint256 points
                        let x = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.x));
                        let y = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.y));
                        let modulus =
                            BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.modulus));

                        // Assign basic values to the columns.
                        cols.is_real = F::one();

                        cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
                        cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

                        cols.x_ptr.populate(&mut new_byte_lookup_events, event.x_ptr, 32);
                        cols.y_ptr.populate(&mut new_byte_lookup_events, event.y_ptr, 64);

                        let modulus_ptr = event.y_ptr + WORDS_FIELD_ELEMENT as u64 * 8;

                        // Populate memory columns.
                        for i in 0..WORDS_FIELD_ELEMENT {
                            let x_memory_record =
                                MemoryRecordEnum::Write(event.x_memory_records[i]);
                            let y_memory_record = MemoryRecordEnum::Read(event.y_memory_records[i]);
                            let modulus_memory_record =
                                MemoryRecordEnum::Read(event.modulus_memory_records[i]);
                            cols.x_memory[i].populate(x_memory_record, &mut new_byte_lookup_events);
                            cols.y_memory[i].populate(y_memory_record, &mut new_byte_lookup_events);
                            cols.modulus_memory[i]
                                .populate(modulus_memory_record, &mut new_byte_lookup_events);

                            cols.x_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.x_ptr,
                                8 * i as u64,
                            );

                            cols.y_and_modulus_addrs[i].populate(
                                &mut new_byte_lookup_events,
                                event.y_ptr,
                                8 * i as u64,
                            );

                            cols.y_and_modulus_addrs[i + WORDS_FIELD_ELEMENT].populate(
                                &mut new_byte_lookup_events,
                                modulus_ptr,
                                8 * i as u64,
                            );
                        }

                        let modulus_bytes = words_to_bytes_le_vec(&event.modulus);
                        let modulus_byte_sum = modulus_bytes.iter().map(|b| *b as u64).sum::<u64>();
                        IsZeroOperation::populate(&mut cols.modulus_is_zero, modulus_byte_sum);

                        // Populate the output column.
                        let effective_modulus =
                            if modulus.is_zero() { BigUint::one() << 256 } else { modulus.clone() };
                        let result = cols.output.populate_with_modulus(
                            &mut new_byte_lookup_events,
                            &x,
                            &y,
                            &effective_modulus,
                            FieldOperation::Mul,
                        );

                        cols.modulus_is_not_zero = F::one() - cols.modulus_is_zero.result;
                        if cols.modulus_is_not_zero == F::one() {
                            cols.output_range_check.populate(
                                &mut new_byte_lookup_events,
                                &result,
                                &effective_modulus,
                            );
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

            let cols: &mut Uint256MulCols<F> = row.borrow_mut();

            let x = BigUint::zero();
            let y = BigUint::zero();
            cols.output.populate(&mut vec![], &x, &y, FieldOperation::Mul);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::UINT256_MUL).is_empty()
        }
    }
}

impl<F> BaseAir<F> for Uint256MulChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB> Air<AB> for Uint256MulChip
where
    AB: SP1CoreAirBuilder,
    Limbs<AB::Var, <U256Field as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Uint256MulCols<AB::Var> = (*local).borrow();

        // We are computing (x * y) % modulus. The value of x is stored in the "prev_value" of
        // the x_memory, since we write to it later.
        let x_limb_vec = builder.generate_limbs(&local.x_memory, local.is_real.into());
        let x_limbs: Limbs<AB::Expr, <U256Field as NumLimbs>::Limbs> =
            Limbs(x_limb_vec.try_into().expect("failed to convert limbs"));
        let y_limb_vec = builder.generate_limbs(&local.y_memory, local.is_real.into());
        let y_limbs: Limbs<AB::Expr, <U256Field as NumLimbs>::Limbs> =
            Limbs(y_limb_vec.try_into().expect("failed to convert limbs"));
        let modulus_limb_vec = builder.generate_limbs(&local.modulus_memory, local.is_real.into());
        let modulus_limbs: Limbs<AB::Expr, <U256Field as NumLimbs>::Limbs> =
            Limbs(modulus_limb_vec.try_into().expect("failed to convert limbs"));

        // If the modulus is zero, then we don't perform the modulus operation.
        // Evaluate the modulus_is_zero operation by summing each byte of the modulus.
        // The sum will not overflow because we are summing 32 bytes.
        let modulus_byte_sum =
            modulus_limbs.clone().0.iter().fold(AB::Expr::zero(), |acc, limb| acc + limb.clone());
        IsZeroOperation::<AB::F>::eval(
            builder,
            IsZeroOperationInput::new(
                modulus_byte_sum,
                local.modulus_is_zero,
                local.is_real.into(),
            ),
        );

        // If the modulus is zero, we'll actually use 2^256 as the modulus, so nothing happens.
        // Otherwise, we use the modulus passed in.
        let modulus_is_zero = local.modulus_is_zero.result;
        let mut coeff_2_256 = Vec::new();
        coeff_2_256.resize(32, AB::Expr::zero());
        coeff_2_256.push(AB::Expr::one());
        let modulus_polynomial: Polynomial<AB::Expr> = modulus_limbs.clone().into();
        let p_modulus: Polynomial<AB::Expr> = modulus_polynomial
            * (AB::Expr::one() - modulus_is_zero.into())
            + Polynomial::from_coefficients(&coeff_2_256) * modulus_is_zero.into();

        // Evaluate the uint256 multiplication
        local.output.eval_with_modulus(
            builder,
            &x_limbs,
            &y_limbs,
            &p_modulus,
            FieldOperation::Mul,
            local.is_real,
        );

        // Verify the range of the output if the modulus is not zero.
        // Also, check the value of modulus_is_not_zero.
        // If `is_real` is false, then `modulus_is_not_zero = 0`.
        // If `is_real` is true, then `modulus_is_zero` will be correctly constrained.
        local.output_range_check.eval(
            builder,
            &local.output.result,
            &modulus_limbs.clone(),
            local.modulus_is_not_zero,
        );
        builder.assert_eq(
            local.modulus_is_not_zero,
            local.is_real * (AB::Expr::one() - modulus_is_zero.into()),
        );

        let result_words = limbs_to_words::<AB>(local.output.result.0.to_vec());

        let x_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 32, local.x_ptr, local.is_real.into());
        let y_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 64, local.y_ptr, local.is_real.into());

        // x_addrs[i] = x_ptr + 8 * i
        for i in 0..local.x_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([x_ptr[0].into(), x_ptr[1].into(), x_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.x_addrs[i],
                local.is_real.into(),
            );
        }

        // y_and_modulus_addrs[i] = y_ptr + 8 * i
        for i in 0..local.y_and_modulus_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([y_ptr[0].into(), y_ptr[1].into(), y_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.y_and_modulus_addrs[i],
                local.is_real.into(),
            );
        }

        // Read and write x.
        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::one(),
            &local.x_addrs.map(|addr| addr.value.map(Into::into)),
            &local.x_memory.iter().map(|access| access.memory_access).collect_vec(),
            result_words,
            local.is_real,
        );

        // Evaluate the y_ptr memory access. We concatenate y and modulus into a single array since
        // we read it contiguously from the y_ptr memory location.
        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low.into(),
            &local.y_and_modulus_addrs.map(|addr| addr.value.map(Into::into)),
            &[local.y_memory, local.modulus_memory]
                .concat()
                .iter()
                .map(|access| access.memory_access)
                .collect_vec(),
            local.is_real,
        );

        // Receive the arguments.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low.into(),
            AB::F::from_canonical_u32(SyscallCode::UINT256_MUL.syscall_id()),
            x_ptr.map(Into::into),
            y_ptr.map(Into::into),
            local.is_real,
            InteractionScope::Local,
        );
    }
}
