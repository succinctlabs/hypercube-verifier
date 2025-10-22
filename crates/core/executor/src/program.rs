//! Programs that can be executed by the SP1 zkVM.

use std::{fs::File, io::Read, str::FromStr};

use crate::{
    disassembler::{transpile, Elf},
    instruction::Instruction,
    RiscvAirId,
};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use slop_algebra::{Field, PrimeField32};
use slop_maybe_rayon::prelude::{IntoParallelIterator, ParallelBridge, ParallelIterator};
use sp1_hypercube::{
    air::{MachineAir, MachineProgram},
    septic_curve::{SepticCurve, SepticCurveComplete},
    septic_digest::SepticDigest,
    shape::Shape,
    InteractionKind,
};
use sp1_primitives::consts::split_page_idx;
use std::sync::Arc;

/// A program that can be executed by the SP1 zkVM.
///
/// Contains a series of instructions along with the initial memory image. It also contains the
/// start address and base address of the program.
#[derive(Debug, Clone, Default, Serialize, Deserialize, deepsize2::DeepSizeOf)]
pub struct Program {
    /// The instructions of the program.
    pub instructions: Vec<Instruction>,
    /// The encoded instructions of the program. Only used if program is untrusted
    pub instructions_encoded: Option<Vec<u32>>,
    /// The start address of the program. It is absolute, meaning not relative to `pc_base`.
    pub pc_start_abs: u64,
    /// The base address of the program.
    pub pc_base: u64,
    /// The initial page protection image, mapping page indices to protection flags.
    pub page_prot_image: HashMap<u64, u8>,
    /// The initial memory image, useful for global constants
    pub memory_image: Arc<HashMap<u64, u64>>,
    /// The shape for the preprocessed tables.
    pub preprocessed_shape: Option<Shape<RiscvAirId>>,
    /// Flag indicating if untrusted programs are allowed.
    pub enable_untrusted_programs: bool,
}

impl Program {
    /// Create a new [Program].
    #[must_use]
    pub fn new(instructions: Vec<Instruction>, pc_start_abs: u64, pc_base: u64) -> Self {
        Self {
            instructions,
            instructions_encoded: None,
            pc_start_abs,
            pc_base,
            page_prot_image: HashMap::new(),
            memory_image: Arc::new(HashMap::new()),
            preprocessed_shape: None,
            enable_untrusted_programs: false,
        }
    }

    /// Disassemble a RV64IM ELF to a program that be executed by the VM.
    ///
    /// # Errors
    ///
    /// This function may return an error if the ELF is not valid.
    pub fn from(input: &[u8]) -> eyre::Result<Self> {
        // Decode the bytes as an ELF.
        let elf = Elf::decode(input)?;

        assert!(elf.pc_base != 0, "elf with pc_base == 0 is not supported");
        assert!(elf.pc_base % 4 == 0, "elf with pc_base not a multiple of 4 is not supported");

        // Transpile the RV64IM instructions.
        let instruction_pair = transpile(&elf.instructions);
        let (instructions, instructions_encoded) = instruction_pair.into_iter().unzip();

        // Return the program.
        Ok(Program {
            instructions,
            instructions_encoded: Some(instructions_encoded),
            pc_start_abs: elf.pc_start,
            pc_base: elf.pc_base,
            memory_image: elf.memory_image,
            page_prot_image: elf.page_prot_image,
            preprocessed_shape: None,
            enable_untrusted_programs: elf.enable_untrusted_programs,
        })
    }

    /// Disassemble a RV64IM ELF to a program that be executed by the VM from a file path.
    ///
    /// # Errors
    ///
    /// This function will return an error if the file cannot be opened or read.
    pub fn from_elf(path: &str) -> eyre::Result<Self> {
        let mut elf_code = Vec::new();
        File::open(path)?.read_to_end(&mut elf_code)?;
        Program::from(&elf_code)
    }

    /// Custom logic for padding the trace to a power of two according to the proof shape.
    pub fn fixed_log2_rows<F: Field, A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        let id = RiscvAirId::from_str(&air.name()).unwrap();
        self.preprocessed_shape.as_ref().map(|shape| {
            shape
                .log2_height(&id)
                .unwrap_or_else(|| panic!("Chip {} not found in specified shape", air.name()))
        })
    }

    #[must_use]
    /// Fetch the instruction at the given program counter.
    pub fn fetch(&self, pc: u64) -> Option<&Instruction> {
        let idx = ((pc - self.pc_base) / 4) as usize;
        self.instructions.get(idx)
    }

    // /// Returns `self.pc_start - self.pc_base`, that is, the relative `pc_start`.
    // #[must_use]
    // pub fn pc_start_rel_u32(&self) -> u32 {
    //     self.pc_start_abs
    //         .checked_sub(self.pc_base)
    //         .expect("expected pc_base <= pc_start")
    //         .try_into()
    //         .expect("pc_start_rel should fit in `u32")
    // }
}

impl<F: PrimeField32> MachineProgram<F> for Program {
    fn pc_start(&self) -> [F; 3] {
        [
            F::from_canonical_u16((self.pc_start_abs & 0xFFFF) as u16),
            F::from_canonical_u16(((self.pc_start_abs >> 16) & 0xFFFF) as u16),
            F::from_canonical_u16(((self.pc_start_abs >> 32) & 0xFFFF) as u16),
        ]
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<F> {
        let mut memory_digests: Vec<SepticCurveComplete<F>> = self
            .memory_image
            .iter()
            .par_bridge()
            .map(|(&addr, &word)| {
                let limb_1 = (word & 0xFFFF) as u32 + (1 << 16) * ((word >> 32) & 0xFF) as u32;
                let limb_2 =
                    ((word >> 16) & 0xFFFF) as u32 + (1 << 16) * ((word >> 40) & 0xFF) as u32;
                let values = [
                    (InteractionKind::Memory as u32) << 24,
                    0,
                    (addr & 0xFFFF) as u32,
                    ((addr >> 16) & 0xFFFF) as u32,
                    ((addr >> 32) & 0xFFFF) as u32,
                    limb_1,
                    limb_2,
                    ((word >> 48) & 0xFFFF) as u32,
                ];
                let (point, _, _, _) =
                    SepticCurve::<F>::lift_x(values.map(|x| F::from_canonical_u32(x)));
                SepticCurveComplete::Affine(point.neg())
            })
            .collect();

        if self.enable_untrusted_programs {
            let page_prot_digests: Vec<SepticCurveComplete<F>> = self
                .page_prot_image
                .iter()
                .par_bridge()
                .map(|(&page_idx, &page_prot)| {
                    // Use exact same encoding as PageProtGlobalChip Initialize events
                    let page_idx_limbs = split_page_idx(page_idx);
                    let values = [
                        (InteractionKind::PageProtAccess as u32) << 24,
                        0,
                        page_idx_limbs[0].into(),
                        page_idx_limbs[1].into(),
                        page_idx_limbs[2].into(),
                        page_prot.into(),
                        0,
                        0,
                    ];
                    let (point, _, _, _) =
                        SepticCurve::<F>::lift_x(values.map(|x| F::from_canonical_u32(x)));
                    SepticCurveComplete::Affine(point.neg())
                })
                .collect();

            // Combine both memory and page protection contributions.
            memory_digests.extend(page_prot_digests);
        }

        memory_digests.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
        SepticDigest(
            memory_digests
                .into_par_iter()
                .reduce(|| SepticCurveComplete::Infinity, |a, b| a + b)
                .point(),
        )
    }

    fn enable_untrusted_programs(&self) -> F {
        F::from_bool(self.enable_untrusted_programs)
    }
}
