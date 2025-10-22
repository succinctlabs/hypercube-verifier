use crate::{
    air::SP1Operation,
    memory::MemoryAccessColsU8,
    operations::{
        field::field_op::FieldOpCols, AddrAddOperation, AddressSlicePageProtOperation,
        IsZeroOperationInput,
    },
};

use crate::{
    air::SP1CoreAirBuilder,
    operations::{field::range::FieldLtCols, IsZeroOperation, SyscallAddrOperation},
    utils::{
        limbs_to_words, next_multiple_of_32, pad_rows_fixed, words_to_bytes_le,
        words_to_bytes_le_vec,
    },
};
use generic_array::GenericArray;
use itertools::Itertools;
use num::{BigUint, One, Zero};
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::{dense::RowMajorMatrix, Matrix};
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
    MachineRecord, Word,
};
use sp1_primitives::{
    consts::{PROT_READ, PROT_WRITE},
    polynomial::Polynomial,
};
use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
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

    pub address_slice_page_prot_access_x: AddressSlicePageProtOperation<T>,
    pub address_slice_page_prot_access_y: AddressSlicePageProtOperation<T>,
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

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows & corresponding records for each chunk of events concurrently.
        let rows_and_records = input
            .get_precompile_events(SyscallCode::UINT256_MUL)
            .chunks(1)
            .map(|events| {
                let mut records = ExecutionRecord::default();
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|(_, event)| {
                        let event = if let PrecompileEvent::Uint256Mul(event) = event {
                            event
                        } else {
                            unreachable!()
                        };
                        let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                        let cols: &mut Uint256MulCols<F> = row.as_mut_slice().borrow_mut();

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
                            // &modulus,
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
                        if input.public_values.is_untrusted_programs_enabled == 1 {
                            // Populate page protection operations (once per event, not per word)
                            cols.address_slice_page_prot_access_y.populate(
                                &mut new_byte_lookup_events,
                                event.y_ptr,
                                event.y_ptr + ((WORDS_FIELD_ELEMENT * 2 - 1) * 8) as u64,
                                event.clk,
                                PROT_READ,
                                &event.page_prot_records.read_y_modulus_page_prot_records[0],
                                &event
                                    .page_prot_records
                                    .read_y_modulus_page_prot_records
                                    .get(1)
                                    .copied(),
                                input.public_values.is_untrusted_programs_enabled,
                            );

                            cols.address_slice_page_prot_access_x.populate(
                                &mut new_byte_lookup_events,
                                event.x_ptr,
                                event.x_ptr + ((WORDS_FIELD_ELEMENT - 1) * 8) as u64,
                                event.clk + 1,
                                PROT_READ | PROT_WRITE,
                                &event.page_prot_records.write_x_page_prot_records[0],
                                &event.page_prot_records.write_x_page_prot_records.get(1).copied(),
                                input.public_values.is_untrusted_programs_enabled,
                            );
                        }
                        row
                    })
                    .collect::<Vec<_>>();
                records.add_byte_lookup_events(new_byte_lookup_events);
                (rows, records)
            })
            .collect::<Vec<_>>();

        //  Generate the trace rows for each event.
        let mut rows = Vec::new();
        for (row, mut record) in rows_and_records {
            rows.extend(row);
            output.append(&mut record);
        }

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                let cols: &mut Uint256MulCols<F> = row.as_mut_slice().borrow_mut();

                let x = BigUint::zero();
                let y = BigUint::zero();
                cols.output.populate(&mut vec![], &x, &y, FieldOperation::Mul);

                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_COLS)
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

        // Assert that is_real is a boolean.
        AddressSlicePageProtOperation::<AB::F>::eval(
            builder,
            local.clk_high.into(),
            local.clk_low.into(),
            &y_ptr.map(Into::into),
            &local.y_and_modulus_addrs[local.y_and_modulus_addrs.len() - 1].value.map(Into::into),
            AB::Expr::from_canonical_u8(PROT_READ),
            &local.address_slice_page_prot_access_y,
            local.is_real.into(),
        );

        AddressSlicePageProtOperation::<AB::F>::eval(
            builder,
            local.clk_high.into(),
            local.clk_low.into() + AB::Expr::one(),
            &x_ptr.map(Into::into),
            &local.x_addrs[local.x_addrs.len() - 1].value.map(Into::into),
            AB::Expr::from_canonical_u8(PROT_READ | PROT_WRITE),
            &local.address_slice_page_prot_access_x,
            local.is_real.into(),
        );
    }
}
