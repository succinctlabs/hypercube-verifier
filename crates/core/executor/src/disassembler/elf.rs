use elf::{
    abi::{EM_RISCV, ET_EXEC, PF_W, PF_X, PT_LOAD, PT_NOTE},
    endian::LittleEndian,
    file::Class,
    segment::ProgramHeader,
    ElfBytes,
};
use eyre::OptionExt;
use hashbrown::HashMap;
use sp1_primitives::consts::{
    INSTRUCTION_WORD_SIZE, MAXIMUM_MEMORY_SIZE, NOTE_UNTRUSTED_PROGRAM_ENABLED, PAGE_SIZE,
    STACK_TOP,
};

/// RISC-V 64IM ELF (Executable and Linkable Format) File.
use std::sync::Arc;
/// RISC-V 32IM ELF (Executable and Linkable Format) File.
///
/// This file represents a binary in the ELF format, specifically the RISC-V 64IM architecture
/// with the following extensions:
///
/// - Base Integer Instruction Set (I)
/// - Integer Multiplication and Division (M)
///
/// This format is commonly used in embedded systems and is supported by many compilers.
#[derive(Debug, Clone)]
pub(crate) struct Elf {
    /// The instructions of the program encoded as 32-bits.
    pub(crate) instructions: Vec<u32>,
    /// The start address of the program.
    pub(crate) pc_start: u64,
    /// The base address of the program.
    pub(crate) pc_base: u64,
    /// The initial page protection image, mapping page indices to protection flags.
    pub(crate) page_prot_image: HashMap<u64, u8>,
    /// Flag indicating if untrusted programs are enabled.
    pub(crate) enable_untrusted_programs: bool,
    /// The initial memory image, useful for global constants.
    pub(crate) memory_image: Arc<HashMap<u64, u64>>,
}

impl Elf {
    /// Create a new [Elf].
    #[must_use]
    pub(crate) fn new(
        instructions: Vec<u32>,
        pc_start: u64,
        pc_base: u64,
        memory_image: HashMap<u64, u64>,
        page_prot_image: HashMap<u64, u8>,
        enable_untrusted_programs: bool,
    ) -> Self {
        Self {
            instructions,
            pc_start,
            pc_base,
            memory_image: Arc::new(memory_image),
            page_prot_image,
            enable_untrusted_programs,
        }
    }

    /// Parse the ELF file into a vector of 32-bit encoded instructions and the first memory
    /// address.
    ///
    /// # Errors
    ///
    /// This function may return an error if the ELF is not valid.
    ///
    /// Reference: [Executable and Linkable Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
    #[allow(clippy::too_many_lines)]
    pub(crate) fn decode(input: &[u8]) -> eyre::Result<Self> {
        let mut image: HashMap<u64, u64> = HashMap::new();
        let mut page_prot_image = HashMap::new();

        // Parse the ELF file assuming that it is little-endian..
        let elf = ElfBytes::<LittleEndian>::minimal_parse(input)?;

        // Some sanity checks to make sure that the ELF file is valid.
        if elf.ehdr.class != Class::ELF32 && elf.ehdr.class != Class::ELF64 {
            eyre::bail!("must be a 32-bit or 64-bit elf");
        } else if elf.ehdr.e_machine != EM_RISCV {
            eyre::bail!("must be a riscv machine");
        } else if elf.ehdr.e_type != ET_EXEC {
            eyre::bail!("must be executable");
        }

        // Get the entrypoint of the ELF file as an u64.
        let entry = elf.ehdr.e_entry;

        // Make sure the entrypoint is valid.
        if entry == MAXIMUM_MEMORY_SIZE || !entry.is_multiple_of(4) {
            eyre::bail!("invalid entrypoint, entry: {}", entry);
        }

        // Get the segments of the ELF file.
        let segments = elf.segments().ok_or_else(|| eyre::eyre!("failed to get segments"))?;
        if segments.len() > 256 {
            eyre::bail!("too many program headers");
        }

        let mut instructions: Vec<u32> = Vec::new();
        let mut base_address = None;

        // Data about the last segment.
        let mut prev_segment_end_addr = None;

        // Toggle for enabling untrusted programs.
        let mut enable_untrusted_programs = false;

        // Check that the segments are sorted and disjoint.
        // Only read segments that are executable instructions that are also PT_LOAD.
        for segment in segments.iter() {
            if segment.p_type == PT_LOAD {
                prev_segment_end_addr = Self::process_load_segment(
                    &segment,
                    input,
                    &mut instructions,
                    &mut base_address,
                    &mut image,
                    &mut page_prot_image,
                    prev_segment_end_addr,
                )?;
            }

            if (segment.p_type == PT_NOTE) && !enable_untrusted_programs {
                enable_untrusted_programs = Self::process_note_segment(&segment, input)?;
            }
        }

        if base_address.is_none() {
            eyre::bail!("no executable (PF_X) segments found");
        }

        Ok(Elf::new(
            instructions,
            entry,
            base_address.unwrap(),
            image,
            page_prot_image,
            enable_untrusted_programs,
        ))
    }

    fn process_load_segment(
        segment: &ProgramHeader,
        input: &[u8],
        instructions: &mut Vec<u32>,
        base_address: &mut Option<u64>,
        image: &mut HashMap<u64, u64>,
        page_prot_image: &mut HashMap<u64, u8>,
        prev_segment_end_addr: Option<u64>,
    ) -> eyre::Result<Option<u64>> {
        // Get the file size of the segment as an u32.
        let file_size = segment.p_filesz;
        if file_size == MAXIMUM_MEMORY_SIZE {
            eyre::bail!("invalid segment file_size");
        }

        // Get the memory size of the segment as an u32.
        let mem_size = segment.p_memsz;
        if mem_size == MAXIMUM_MEMORY_SIZE {
            eyre::bail!("Invalid segment mem_size");
        }

        let vaddr = segment.p_vaddr;
        let offset = segment.p_offset;

        let is_execute = (segment.p_flags & PF_X) != 0;

        if is_execute && base_address.is_none() {
            *base_address = Some(vaddr);
        }

        // If there are sections below the STACK_TOP, we want to error, this could cause
        // collisions with static values.
        if vaddr < STACK_TOP {
            eyre::bail!("ELF has a segment that is below the STACK_TOP");
        }

        if (segment.p_flags & PF_X) != 0 && (segment.p_flags & PF_W) != 0 {
            eyre::bail!("ELF has a segment that is both writable and executable");
        }

        let step_size = INSTRUCTION_WORD_SIZE;

        // Check that the ELF structure is supported.
        if let Some(prev_last_addr) = prev_segment_end_addr {
            eyre::ensure!(prev_last_addr <= vaddr, "unsupported elf structure");
        }

        let end = vaddr
            .checked_add(mem_size)
            .ok_or_else(|| eyre::eyre!("address overflow in segment"))?;

        // Make sure the virtual address is aligned.
        if !vaddr.is_multiple_of(step_size as u64) {
            eyre::bail!("segment vaddr is not aligned");
        }

        let last_addr = Some(vaddr.checked_add(mem_size).ok_or_eyre("last addr overflow")?);

        if (segment.p_flags & PF_X) != 0 {
            if base_address.is_none() {
                *base_address = Some(vaddr);
                eyre::ensure!(
                    base_address.unwrap() > 0x20,
                    "base address {} should be greater than 0x20",
                    base_address.unwrap()
                );
            } else {
                let instr_len: u64 = INSTRUCTION_WORD_SIZE
                    .checked_mul(instructions.len())
                    .ok_or_eyre("instructions length overflow")?
                    .try_into()?;
                let last_instruction_addr = base_address
                    .unwrap()
                    .checked_add(instr_len)
                    .ok_or_eyre("instruction addr overflow")?;
                eyre::ensure!(vaddr == last_instruction_addr, "unsupported elf structure");
            }
        }

        for addr in (vaddr..end).step_by(step_size) {
            if addr >= vaddr + file_size {
                image.insert(addr - addr % 8, 0);
                continue;
            }
            let mut word = 0u64;
            let offset_in_file = offset + (addr - vaddr);
            let bytes_to_read = (step_size as u64).min(file_size - (addr - vaddr));
            for i in 0..bytes_to_read {
                let file_idx = (offset_in_file + i) as usize;
                let byte = input
                    .get(file_idx)
                    .ok_or_else(|| eyre::eyre!("failed to read segment offset"))?;
                word |= u64::from(*byte) << (8 * i);
            }
            if addr.is_multiple_of(8) {
                image
                    .entry(addr)
                    .and_modify(|value| {
                        *value += word;
                    })
                    .or_insert_with(|| word);
            } else {
                assert!(addr % 8 == 4);
                image
                    .entry(addr - 4)
                    .and_modify(|value| {
                        *value += word << 32;
                    })
                    .or_insert_with(|| word << 32);
            }
            if is_execute {
                instructions.push(word as u32);
            }
        }

        // Fill in the segment's page prot image.
        let page_start_addr = vaddr - vaddr % PAGE_SIZE as u64;

        for page_start_addr in (page_start_addr..end).step_by(PAGE_SIZE) {
            let page_idx = page_start_addr / PAGE_SIZE as u64;
            page_prot_image.insert(page_idx, segment.p_flags.try_into().unwrap());
        }

        Ok(last_addr)
    }

    fn process_note_segment(segment: &ProgramHeader, input: &[u8]) -> eyre::Result<bool> {
        let note_segment_offset: usize = segment.p_offset.try_into()?;
        let note_segment_size: usize = segment.p_filesz.try_into()?;
        let note_segment =
            input[note_segment_offset..note_segment_offset + note_segment_size].to_vec();
        let mut note_offset: usize = 0;

        while note_offset < note_segment_size {
            let name_size: usize =
                u32::from_le_bytes(note_segment[note_offset..note_offset + 4].try_into()?)
                    .try_into()?;
            note_offset += 4;

            let desc_size: usize =
                u32::from_le_bytes(note_segment[note_offset..note_offset + 4].try_into()?)
                    .try_into()?;
            note_offset += 4;

            let note_type: u32 =
                u32::from_le_bytes(note_segment[note_offset..note_offset + 4].try_into()?);
            note_offset += 4;

            let name =
                String::from_utf8(note_segment[note_offset..note_offset + name_size].to_vec())?;
            // Need to increment offset by the padded size of the name.
            note_offset += name_size + (name_size % 4);

            let desc =
                String::from_utf8(note_segment[note_offset..note_offset + desc_size].to_vec())?;
            // Need to increment offset by the padded size of the desc.
            note_offset += desc_size + (desc_size % 4);

            if name == "SUCCINCT" && note_type == NOTE_UNTRUSTED_PROGRAM_ENABLED && desc == "1" {
                return Ok(true);
            }
        }

        Ok(false)
    }
}
