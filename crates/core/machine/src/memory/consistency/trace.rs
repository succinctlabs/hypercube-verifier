use slop_algebra::PrimeField32;
use sp1_core_executor::events::{ByteRecord, MemoryRecordEnum, PageProtRecord};

use super::{
    MemoryAccessCols, MemoryAccessColsU8, MemoryAccessTimestamp, PageProtAccessCols,
    RegisterAccessCols, RegisterAccessTimestamp,
};

impl<F: PrimeField32> MemoryAccessCols<F> {
    pub fn populate(&mut self, record: MemoryRecordEnum, output: &mut impl ByteRecord) {
        let prev_record = record.previous_record();
        let current_record = record.current_record();
        self.prev_value = prev_record.value.into();
        self.access_timestamp.populate_timestamp(
            prev_record.timestamp,
            current_record.timestamp,
            output,
        );
    }
}

impl<F: PrimeField32> RegisterAccessCols<F> {
    pub fn populate(&mut self, record: MemoryRecordEnum, output: &mut impl ByteRecord) {
        let prev_record = record.previous_record();
        let current_record = record.current_record();
        self.prev_value = prev_record.value.into();
        self.access_timestamp.populate_timestamp(
            prev_record.timestamp,
            current_record.timestamp,
            output,
        );
    }
}

impl<F: PrimeField32> MemoryAccessColsU8<F> {
    pub fn populate(&mut self, record: MemoryRecordEnum, output: &mut impl ByteRecord) {
        let prev_record = record.previous_record();
        let current_record = record.current_record();
        self.memory_access.prev_value = prev_record.value.into();
        self.prev_value_u8.populate_u16_to_u8_safe(output, prev_record.value);
        self.memory_access.access_timestamp.populate_timestamp(
            prev_record.timestamp,
            current_record.timestamp,
            output,
        );
    }
}

impl<F: PrimeField32> PageProtAccessCols<F> {
    pub fn populate(
        &mut self,
        prev_page_prot: &PageProtRecord,
        current_timestamp: u64,
        output: &mut impl ByteRecord,
    ) {
        self.prev_prot_bitmap = F::from_canonical_u8(prev_page_prot.page_prot);
        self.access_timestamp.populate_timestamp(
            prev_page_prot.timestamp,
            current_timestamp,
            output,
        );
    }
}

impl<F: PrimeField32> MemoryAccessTimestamp<F> {
    pub fn populate_timestamp(
        &mut self,
        prev_timestamp: u64,
        current_timestamp: u64,
        output: &mut impl ByteRecord,
    ) {
        assert!(
            prev_timestamp < current_timestamp,
            "prev_timestamp: {prev_timestamp}, current_timestamp: {current_timestamp}"
        );
        let prev_high = (prev_timestamp >> 24) as u32;
        let prev_low = (prev_timestamp & 0xFFFFFF) as u32;
        let current_high = (current_timestamp >> 24) as u32;
        let current_low = (current_timestamp & 0xFFFFFF) as u32;
        self.prev_high = F::from_canonical_u32(prev_high);
        self.prev_low = F::from_canonical_u32(prev_low);

        // Fill columns used for verifying memory access time is increasing.
        let use_low_comparison = prev_high == current_high;
        self.compare_low = F::from_bool(use_low_comparison);
        let prev_time_value = if use_low_comparison { prev_low } else { prev_high };
        let current_time_value = if use_low_comparison { current_low } else { current_high };

        let diff_minus_one = current_time_value - prev_time_value - 1;
        let diff_low_limb = (diff_minus_one & 0xFFFF) as u16;
        self.diff_low_limb = F::from_canonical_u16(diff_low_limb);
        let diff_high_limb = (diff_minus_one >> 16) as u8;
        self.diff_high_limb = F::from_canonical_u8(diff_high_limb);

        // Add a byte table lookup with the u16 range check.
        output.add_bit_range_check(diff_low_limb, 16);
        output.add_u8_range_check(diff_high_limb, 0);
    }
}

impl<F: PrimeField32> RegisterAccessTimestamp<F> {
    pub fn populate_timestamp(
        &mut self,
        prev_timestamp: u64,
        current_timestamp: u64,
        output: &mut impl ByteRecord,
    ) {
        let prev_high = (prev_timestamp >> 24) as u32;
        let prev_low = (prev_timestamp & 0xFFFFFF) as u32;
        let current_high = (current_timestamp >> 24) as u32;
        let current_low = (current_timestamp & 0xFFFFFF) as u32;

        let old_timestamp = if prev_high == current_high { prev_low } else { 0 };
        self.prev_low = F::from_canonical_u32(old_timestamp);
        let diff_minus_one = current_low - old_timestamp - 1;
        let diff_low_limb = (diff_minus_one & 0xFFFF) as u16;
        self.diff_low_limb = F::from_canonical_u16(diff_low_limb);
        let diff_high_limb = (diff_minus_one >> 16) as u8;

        // Add a byte table lookup with the u16 range check.
        output.add_bit_range_check(diff_low_limb, 16);
        output.add_u8_range_check(diff_high_limb, 0);
    }
}
