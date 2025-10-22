use crate::{
    air::SP1CoreAirBuilder,
    memory::MemoryAccessColsU8,
    operations::{AddrAddOperation, AddressSlicePageProtOperation, SyscallAddrOperation},
    utils::{limbs_to_words, next_multiple_of_32, zeroed_f_vec},
};
use generic_array::GenericArray;
use itertools::Itertools;
use num::{BigUint, Zero};
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, FieldOperation, MemoryRecordEnum, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_curves::{
    params::{Limbs, NumLimbs},
    weierstrass::{FieldType, FpOpField},
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    Word,
};
use sp1_primitives::{
    consts::{PROT_READ, PROT_WRITE},
    polynomial::Polynomial,
};
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::size_of,
};
use typenum::Unsigned;

use crate::{
    operations::field::{field_op::FieldOpCols, range::FieldLtCols},
    utils::{pad_rows_fixed, words_to_bytes_le_vec},
};

pub const fn num_fp2_addsub_cols<P: FpOpField>() -> usize {
    size_of::<Fp2AddSubAssignCols<u8, P>>()
}

/// A set of columns for the Fp2AddSub operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp2AddSubAssignCols<T, P: FpOpField> {
    pub is_real: T,
    pub clk_high: T,
    pub clk_low: T,
    pub is_add: T,
    pub x_ptr: SyscallAddrOperation<T>,
    pub y_ptr: SyscallAddrOperation<T>,
    pub x_addrs: GenericArray<AddrAddOperation<T>, P::WordsCurvePoint>,
    pub y_addrs: GenericArray<AddrAddOperation<T>, P::WordsCurvePoint>,
    pub x_access: GenericArray<MemoryAccessColsU8<T>, P::WordsCurvePoint>,
    pub y_access: GenericArray<MemoryAccessColsU8<T>, P::WordsCurvePoint>,
    pub read_slice_page_prot_access: AddressSlicePageProtOperation<T>,
    pub write_slice_page_prot_access: AddressSlicePageProtOperation<T>,
    pub(crate) c0: FieldOpCols<T, P>,
    pub(crate) c1: FieldOpCols<T, P>,
    pub(crate) c0_range: FieldLtCols<T, P>,
    pub(crate) c1_range: FieldLtCols<T, P>,
}

pub struct Fp2AddSubAssignChip<P> {
    _marker: PhantomData<P>,
}

impl<P: FpOpField> Fp2AddSubAssignChip<P> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        cols: &mut Fp2AddSubAssignCols<F, P>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
        op: FieldOperation,
    ) {
        let modulus_bytes = P::MODULUS;
        let modulus = BigUint::from_bytes_le(modulus_bytes);
        let c0 = cols.c0.populate_with_modulus(blu_events, &p_x, &q_x, &modulus, op);
        let c1 = cols.c1.populate_with_modulus(blu_events, &p_y, &q_y, &modulus, op);
        cols.c0_range.populate(blu_events, &c0, &modulus);
        cols.c1_range.populate(blu_events, &c1, &modulus);
    }
}

impl<F: PrimeField32, P: FpOpField> MachineAir<F> for Fp2AddSubAssignChip<P> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        match P::FIELD_TYPE {
            FieldType::Bn254 => "Bn254Fp2AddSubAssign".to_string(),
            FieldType::Bls12381 => "Bls12381Fp2AddSubAssign".to_string(),
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = match P::FIELD_TYPE {
            FieldType::Bn254 => input.get_precompile_events(SyscallCode::BN254_FP2_ADD).len(),
            FieldType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_FP2_ADD).len(),
        };
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        // All the fp2 sub and add events for a given curve are coalesce to the curve's Add
        // operation.  Only retrieve precompile events for that operation.
        // TODO:  Fix this.

        let events = match P::FIELD_TYPE {
            FieldType::Bn254 => input.get_precompile_events(SyscallCode::BN254_FP2_ADD).iter(),
            FieldType::Bls12381 => {
                input.get_precompile_events(SyscallCode::BLS12381_FP2_ADD).iter()
            }
        };

        let mut rows = Vec::new();
        let mut new_byte_lookup_events = Vec::new();

        for (_, event) in events {
            let event = match (P::FIELD_TYPE, event) {
                (FieldType::Bn254, PrecompileEvent::Bn254Fp2AddSub(event)) => event,
                (FieldType::Bls12381, PrecompileEvent::Bls12381Fp2AddSub(event)) => event,
                _ => unreachable!(),
            };

            let mut row = zeroed_f_vec(num_fp2_addsub_cols::<P>());
            let cols: &mut Fp2AddSubAssignCols<F, P> = row.as_mut_slice().borrow_mut();

            let p = &event.x;
            let q = &event.y;
            let p_x = BigUint::from_bytes_le(&words_to_bytes_le_vec(&p[..p.len() / 2]));
            let p_y = BigUint::from_bytes_le(&words_to_bytes_le_vec(&p[p.len() / 2..]));
            let q_x = BigUint::from_bytes_le(&words_to_bytes_le_vec(&q[..q.len() / 2]));
            let q_y = BigUint::from_bytes_le(&words_to_bytes_le_vec(&q[q.len() / 2..]));

            cols.is_real = F::one();
            cols.is_add = F::from_bool(event.op == FieldOperation::Add);

            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
            cols.x_ptr.populate(&mut new_byte_lookup_events, event.x_ptr, P::NB_LIMBS as u64 * 2);
            cols.y_ptr.populate(&mut new_byte_lookup_events, event.y_ptr, P::NB_LIMBS as u64 * 2);

            Self::populate_field_ops(
                &mut new_byte_lookup_events,
                cols,
                p_x,
                p_y,
                q_x,
                q_y,
                event.op,
            );

            // Populate the memory access columns.
            for i in 0..cols.y_access.len() {
                let record = MemoryRecordEnum::Read(event.y_memory_records[i]);
                cols.y_access[i].populate(record, &mut new_byte_lookup_events);
                cols.y_addrs[i].populate(&mut new_byte_lookup_events, event.y_ptr, i as u64 * 8);
            }
            for i in 0..cols.x_access.len() {
                let record = MemoryRecordEnum::Write(event.x_memory_records[i]);
                cols.x_access[i].populate(record, &mut new_byte_lookup_events);
                cols.x_addrs[i].populate(&mut new_byte_lookup_events, event.x_ptr, i as u64 * 8);
            }
            if input.public_values.is_untrusted_programs_enabled == 1 {
                cols.read_slice_page_prot_access.populate(
                    &mut new_byte_lookup_events,
                    event.y_ptr,
                    event.y_ptr + 8 * (cols.y_addrs.len() - 1) as u64,
                    event.clk,
                    PROT_READ,
                    &event.page_prot_records.read_page_prot_records[0],
                    &event.page_prot_records.read_page_prot_records.get(1).copied(),
                    input.public_values.is_untrusted_programs_enabled,
                );

                cols.write_slice_page_prot_access.populate(
                    &mut new_byte_lookup_events,
                    event.x_ptr,
                    event.x_ptr + 8 * (cols.x_addrs.len() - 1) as u64,
                    event.clk + 1,
                    PROT_READ | PROT_WRITE,
                    &event.page_prot_records.write_page_prot_records[0],
                    &event.page_prot_records.write_page_prot_records.get(1).copied(),
                    input.public_values.is_untrusted_programs_enabled,
                );
            }

            rows.push(row);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = zeroed_f_vec(num_fp2_addsub_cols::<P>());
                let cols: &mut Fp2AddSubAssignCols<F, P> = row.as_mut_slice().borrow_mut();
                cols.is_add = F::one();
                let zero = BigUint::zero();
                Self::populate_field_ops(
                    &mut vec![],
                    cols,
                    zero.clone(),
                    zero.clone(),
                    zero.clone(),
                    zero,
                    FieldOperation::Add,
                );
                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_fp2_addsub_cols::<P>(),
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        // All the fp2 sub and add events for a given curve are coalesce to the curve's Add
        // operation.  Only retrieve precompile events for that operation.
        // TODO:  Fix this.

        assert!(
            shard.get_precompile_events(SyscallCode::BN254_FP_SUB).is_empty()
                && shard.get_precompile_events(SyscallCode::BLS12381_FP_SUB).is_empty()
        );

        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match P::FIELD_TYPE {
                FieldType::Bn254 => {
                    !shard.get_precompile_events(SyscallCode::BN254_FP2_ADD).is_empty()
                }
                FieldType::Bls12381 => {
                    !shard.get_precompile_events(SyscallCode::BLS12381_FP2_ADD).is_empty()
                }
            }
        }
    }
}

impl<F, P: FpOpField> BaseAir<F> for Fp2AddSubAssignChip<P> {
    fn width(&self) -> usize {
        num_fp2_addsub_cols::<P>()
    }
}

impl<AB, P: FpOpField> Air<AB> for Fp2AddSubAssignChip<P>
where
    AB: SP1CoreAirBuilder,
    Limbs<AB::Var, <P as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Fp2AddSubAssignCols<AB::Var, P> = (*local).borrow();

        // Constrain the `is_add` flag to be boolean.
        builder.assert_bool(local.is_add);

        let num_words_field_element = <P as NumLimbs>::Limbs::USIZE / 8;

        let p_x_limbs = builder
            .generate_limbs(&local.x_access[0..num_words_field_element], local.is_real.into());
        let p_x: Limbs<AB::Expr, <P as NumLimbs>::Limbs> =
            Limbs(p_x_limbs.try_into().expect("failed to convert limbs"));
        let q_x_limbs = builder
            .generate_limbs(&local.y_access[0..num_words_field_element], local.is_real.into());
        let q_x: Limbs<AB::Expr, <P as NumLimbs>::Limbs> =
            Limbs(q_x_limbs.try_into().expect("failed to convert limbs"));
        let p_y_limbs = builder
            .generate_limbs(&local.x_access[num_words_field_element..], local.is_real.into());
        let p_y: Limbs<AB::Expr, <P as NumLimbs>::Limbs> =
            Limbs(p_y_limbs.try_into().expect("failed to convert limbs"));
        let q_y_limbs = builder
            .generate_limbs(&local.y_access[num_words_field_element..], local.is_real.into());
        let q_y: Limbs<AB::Expr, <P as NumLimbs>::Limbs> =
            Limbs(q_y_limbs.try_into().expect("failed to convert limbs"));

        let modulus_coeffs =
            P::MODULUS.iter().map(|&limbs| AB::Expr::from_canonical_u8(limbs)).collect_vec();
        let p_modulus = Polynomial::from_coefficients(&modulus_coeffs);

        {
            local.c0.eval_variable(
                builder,
                &p_x,
                &q_x,
                &p_modulus,
                local.is_add,
                AB::Expr::one() - local.is_add,
                AB::F::zero(),
                AB::F::zero(),
                local.is_real,
            );

            local.c1.eval_variable(
                builder,
                &p_y,
                &q_y,
                &p_modulus,
                local.is_add,
                AB::Expr::one() - local.is_add,
                AB::F::zero(),
                AB::F::zero(),
                local.is_real,
            );
        }

        let c0_result_words = limbs_to_words::<AB>(local.c0.result.0.to_vec());
        let c1_result_words = limbs_to_words::<AB>(local.c1.result.0.to_vec());

        let result_words = c0_result_words.into_iter().chain(c1_result_words).collect_vec();

        local.c0_range.eval(builder, &local.c0.result, &p_modulus, local.is_real);
        local.c1_range.eval(builder, &local.c1.result, &p_modulus, local.is_real);

        let x_ptr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            P::NB_LIMBS as u32 * 2,
            local.x_ptr,
            local.is_real.into(),
        );
        let y_ptr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            P::NB_LIMBS as u32 * 2,
            local.y_ptr,
            local.is_real.into(),
        );

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

        // y_addrs[i] = y_ptr + 8 * i
        for i in 0..local.y_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([y_ptr[0].into(), y_ptr[1].into(), y_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.y_addrs[i],
                local.is_real.into(),
            );
        }

        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low,
            &local.y_addrs.iter().map(|addr| addr.value.map(Into::into)).collect_vec(),
            &local.y_access.iter().map(|access| access.memory_access).collect_vec(),
            local.is_real,
        );

        // We read p at +1 since p, q could be the same.
        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::one(),
            &local.x_addrs.iter().map(|addr| addr.value.map(Into::into)).collect_vec(),
            &local.x_access.iter().map(|access| access.memory_access).collect_vec(),
            result_words,
            local.is_real,
        );

        let (add_syscall_id, sub_syscall_id) = match P::FIELD_TYPE {
            FieldType::Bn254 => (
                AB::F::from_canonical_u32(SyscallCode::BN254_FP2_ADD.syscall_id()),
                AB::F::from_canonical_u32(SyscallCode::BN254_FP2_SUB.syscall_id()),
            ),
            FieldType::Bls12381 => (
                AB::F::from_canonical_u32(SyscallCode::BLS12381_FP2_ADD.syscall_id()),
                AB::F::from_canonical_u32(SyscallCode::BLS12381_FP2_SUB.syscall_id()),
            ),
        };

        let syscall_id_felt =
            local.is_add * add_syscall_id + (AB::Expr::one() - local.is_add) * sub_syscall_id;

        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            syscall_id_felt,
            x_ptr.map(Into::into),
            y_ptr.map(Into::into),
            local.is_real,
            InteractionScope::Local,
        );

        AddressSlicePageProtOperation::<AB::F>::eval(
            builder,
            local.clk_high.into(),
            local.clk_low.into(),
            &local.y_ptr.addr.map(Into::into),
            &local.y_addrs[local.y_addrs.len() - 1].value.map(Into::into),
            AB::Expr::from_canonical_u8(PROT_READ),
            &local.read_slice_page_prot_access,
            local.is_real.into(),
        );

        AddressSlicePageProtOperation::<AB::F>::eval(
            builder,
            local.clk_high.into(),
            local.clk_low.into() + AB::Expr::one(),
            &local.x_ptr.addr.map(Into::into),
            &local.x_addrs[local.x_addrs.len() - 1].value.map(Into::into),
            AB::Expr::from_canonical_u8(PROT_READ | PROT_WRITE),
            &local.write_slice_page_prot_access,
            local.is_real.into(),
        );
    }
}
