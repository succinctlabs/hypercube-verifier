use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, PageProtRecord},
    ByteOpcode,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::{BaseAirBuilder, SP1AirBuilder};
use sp1_primitives::consts::{split_page_idx, PAGE_SIZE};

use crate::{air::MemoryAirBuilder, memory::PageProtAccessCols};

/// A set of columns needed to compute the page_idx from an address.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct PageOperation<T> {
    /// Split that least significant limb into a 4 bit limb and a 12 bit limb.
    pub addr_4_bits: T,
    pub addr_12_bits: T,
}

impl<F: Field> PageOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, addr: u64) {
        let addr_12_bits: u16 = (addr & 0xFFF).try_into().unwrap();
        let addr_4_bits: u16 = ((addr >> 12) & 0xF).try_into().unwrap();

        self.addr_12_bits = F::from_canonical_u16(addr_12_bits);
        self.addr_4_bits = F::from_canonical_u16(addr_4_bits);

        record.add_bit_range_check(addr_12_bits, 12);
        record.add_bit_range_check(addr_4_bits, 4);
    }

    /// Evaluate the calculation of the page idx from the address.
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        addr: &[AB::Expr; 3],
        cols: PageOperation<AB::Var>,
        is_real: AB::Expr,
    ) -> [AB::Expr; 3] {
        builder.assert_bool(is_real.clone());

        // Check that the least significant address limb is correctly decomposed to the 4 bit limb
        // and the 12 bit limb.
        builder.when(is_real.clone()).assert_eq(
            addr[0].clone(),
            cols.addr_12_bits + cols.addr_4_bits * (AB::Expr::from_canonical_u32(1 << 12)),
        );
        // Range check the limbs.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            cols.addr_4_bits.into(),
            AB::Expr::from_canonical_u32(4),
            AB::Expr::zero(),
            is_real.clone(),
        );
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            cols.addr_12_bits.into(),
            AB::Expr::from_canonical_u32(12),
            AB::Expr::zero(),
            is_real.clone(),
        );

        [cols.addr_4_bits.into(), addr[1].clone(), addr[2].clone()]
    }
}

/// A set of columns needed to retrieve the page permissions from an address.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct PageProtOperation<T> {
    /// The page operation to calculate page idx from address.
    pub page_op: PageOperation<T>,

    /// The page prot access columns.
    pub page_prot_access: PageProtAccessCols<T>,
}

impl<F: PrimeField32> PageProtOperation<F> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        addr: u64,
        clk: u64,
        previous_page_prot_access: &PageProtRecord,
    ) {
        self.page_op.populate(record, addr);

        assert!(previous_page_prot_access.timestamp < clk);
        self.page_prot_access.populate(previous_page_prot_access, clk, record);
    }
}

impl<F: Field> PageProtOperation<F> {
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        addr: &[AB::Expr; 3],
        cols: PageProtOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        let page_idx = PageOperation::<AB::F>::eval(builder, addr, cols.page_op, is_real.clone());

        builder.eval_page_prot_access_read(
            clk_high,
            clk_low,
            &page_idx,
            cols.page_prot_access,
            is_real.clone(),
        );
    }
}

/// A set of columns needed to check if two page indices are equal or adjacent.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct PageIsEqualOrAdjacentOperation<T> {
    pub is_overflow: T,

    // Bool flag that is set to 0 if equal, 1 if adjacent.
    pub is_adjacent: T,
}

impl<F: Field> PageIsEqualOrAdjacentOperation<F> {
    pub fn populate(&mut self, curr_page_idx: u64, next_page_idx: u64) {
        if curr_page_idx == next_page_idx {
            self.is_adjacent = F::zero();
        } else if curr_page_idx + 1 == next_page_idx {
            self.is_adjacent = F::one();
        } else {
            panic!("curr_page_idx and next_page_idx are not equal or adjacent");
        }

        // Check that the bottom 20 bits of the next page are 0, if so we know there's an overflow
        // into the third limb
        let next_page_limbs = split_page_idx(next_page_idx);
        let next_page_20_bits = next_page_limbs[0] as u64 + ((next_page_limbs[1] as u64) << 4);

        // Check for overflow.
        self.is_overflow = F::from_bool(next_page_20_bits == 0);
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        curr_page_idx: [AB::Expr; 3],
        next_page_idx: [AB::Expr; 3],
        cols: PageIsEqualOrAdjacentOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());
        builder.assert_bool(cols.is_adjacent);
        builder.assert_bool(cols.is_overflow);

        // Combine the 1st and 2nd limbs.  The 1st limb is 4 bits and the 2nd limb is 16 bits.
        let curr_page_20_bits = curr_page_idx[0].clone()
            + curr_page_idx[1].clone() * (AB::Expr::from_canonical_u32(1 << 4));
        let next_page_20_bits = next_page_idx[0].clone()
            + next_page_idx[1].clone() * (AB::Expr::from_canonical_u32(1 << 4));

        // First check for the case when they are equal.
        builder
            .when(is_real.clone())
            .when_not(cols.is_adjacent)
            .assert_eq(curr_page_20_bits.clone(), next_page_20_bits.clone());
        builder
            .when(is_real.clone())
            .when_not(cols.is_adjacent)
            .assert_eq(curr_page_idx[2].clone(), next_page_idx[2].clone());

        // Now check if they are adjacent.

        // First check to see is_adjacent == 1, then is_real == 1.
        // This is so that we don't need to check for is_real when is_adjacent == 1.
        builder.when(cols.is_adjacent).assert_one(is_real.clone());

        let mut is_adjacent_builder = builder.when(cols.is_adjacent);

        // Find out what each limb's relationship should be.
        // If !is_overflow -> (20bit limbs are adjacent, 3rd limb is equal).
        // if is_overflow -> (20bit limbs are at boundary, 3rd limb is adjacent).

        // Check that first page bottom 20 bits are adjacent to second page bottom 20 bits
        is_adjacent_builder
            .when_not(cols.is_overflow)
            .assert_eq(curr_page_20_bits.clone() + AB::Expr::one(), next_page_20_bits.clone());

        // Check that top limbs are equal
        is_adjacent_builder
            .when_not(cols.is_overflow)
            .assert_eq(curr_page_idx[2].clone(), next_page_idx[2].clone());

        // Check that first page bottom 20 bits are maxed out
        is_adjacent_builder
            .when(cols.is_overflow)
            .assert_eq(curr_page_20_bits, AB::Expr::from_canonical_u32((1 << 20) - 1));

        // Check that second page bottom 20 bits are 0
        is_adjacent_builder.when(cols.is_overflow).assert_eq(next_page_20_bits, AB::Expr::zero());

        // Check that top limb (top 16 bits) of second page is 1 more than top limb of first page
        is_adjacent_builder
            .when(cols.is_overflow)
            .assert_eq(curr_page_idx[2].clone() + AB::Expr::one(), next_page_idx[2].clone());
    }
}

/// A set of columns needed to check the page prot permissions for a range of addrs.
/// This operation only supports an addr range that spans at most 2 pages.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddressSlicePageProtOperation<T> {
    pub page_is_equal_or_adjacent: PageIsEqualOrAdjacentOperation<T>,

    pub page_operations: [PageOperation<T>; 2],
    pub page_prot_accesses: [PageProtAccessCols<T>; 2],

    pub is_page_protect_active: T,
}

#[allow(clippy::too_many_arguments)]
impl<F: PrimeField32> AddressSlicePageProtOperation<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        start_addr: u64,
        end_addr: u64,
        clk: u64,
        permissions: u8,
        first_page_prot_access: &PageProtRecord,
        second_page_prot_access: &Option<PageProtRecord>,
        is_page_protect_active: u32,
    ) {
        let start_page_idx = start_addr / (PAGE_SIZE as u64);
        let end_page_idx = end_addr / (PAGE_SIZE as u64);
        assert!(start_page_idx == end_page_idx || start_page_idx + 1 == end_page_idx);

        self.page_operations[0].populate(record, start_addr);
        self.page_operations[1].populate(record, end_addr);

        self.page_is_equal_or_adjacent.populate(start_page_idx, end_page_idx);

        self.page_prot_accesses[0].populate(first_page_prot_access, clk, record);
        record.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a: permissions as u16,
            b: permissions,
            c: first_page_prot_access.page_prot,
        });

        if let Some(second_page_prot_access) = second_page_prot_access {
            assert!(start_page_idx + 1 == end_page_idx);
            self.page_prot_accesses[1].populate(second_page_prot_access, clk, record);
            record.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::AND,
                a: permissions as u16,
                b: permissions,
                c: second_page_prot_access.page_prot,
            });
        }

        self.is_page_protect_active = F::from_canonical_u32(is_page_protect_active);
    }
}

impl<F: Field> AddressSlicePageProtOperation<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        clk_high: AB::Expr,
        clk_low: AB::Expr,
        start_addr: &[AB::Expr; 3],
        end_addr: &[AB::Expr; 3],
        permissions: AB::Expr,
        cols: &AddressSlicePageProtOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        // Check page protect active is set correctly based on public value and is_real
        builder.assert_bool(is_real.clone());
        let public_values = builder.extract_public_values();
        let expected_page_protect_active =
            public_values.is_untrusted_programs_enabled.into() * is_real.clone();
        builder.assert_eq(cols.is_page_protect_active, expected_page_protect_active);

        let start_page_idx = PageOperation::<AB::F>::eval(
            builder,
            start_addr,
            cols.page_operations[0],
            cols.is_page_protect_active.into(),
        );

        let end_page_idx = PageOperation::<AB::F>::eval(
            builder,
            &end_addr.clone(),
            cols.page_operations[1],
            cols.is_page_protect_active.into(),
        );

        builder.eval_page_prot_access_read(
            clk_high.clone(),
            clk_low.clone(),
            &start_page_idx.clone(),
            cols.page_prot_accesses[0],
            cols.is_page_protect_active.into(),
        );

        // Ensure requested permission matches the set permission.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::AND as u8),
            permissions.clone(),
            permissions.clone(),
            cols.page_prot_accesses[0].prev_prot_bitmap,
            cols.is_page_protect_active.into(),
        );

        PageIsEqualOrAdjacentOperation::<AB::F>::eval(
            builder,
            start_page_idx.map(Into::into),
            end_page_idx.clone().map(Into::into),
            cols.page_is_equal_or_adjacent,
            cols.is_page_protect_active.into(),
        );

        // Ensure that if adjacent is true, then page protect is active
        builder
            .when(cols.page_is_equal_or_adjacent.is_adjacent)
            .assert_one(cols.is_page_protect_active);

        builder.eval_page_prot_access_read(
            clk_high.clone(),
            clk_low.clone(),
            &end_page_idx.clone(),
            cols.page_prot_accesses[1],
            cols.page_is_equal_or_adjacent.is_adjacent,
        );

        // Ensure requested permission matches the set permission.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::AND as u8),
            permissions.clone(),
            permissions.clone(),
            cols.page_prot_accesses[1].prev_prot_bitmap,
            cols.page_is_equal_or_adjacent.is_adjacent,
        );
    }
}
