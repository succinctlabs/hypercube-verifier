// use std::{
//     array,
//     cell::UnsafeCell,
//     mem::MaybeUninit,
//     ops::{Add, AddAssign},
//     sync::Arc,
// };

// use p3_field::{AbstractField, Field, PrimeField32};
// use serde::{Deserialize, Serialize};
// use hypercube_stark::{air::SP1AirBuilder, MachineRecord, PROOF_MAX_NUM_PVS};

// use crate::{
//     instruction::{HintBitsInstr, HintExt2FeltsInstr, HintInstr},
//     public_values::RecursionPublicValues,
//     ExpReverseBitsInstr, Instruction, PrefixSumChecksEvent,
// };

// use super::{
//     BaseAluEvent, BatchFRIEvent, CommitPublicValuesEvent, ExpReverseBitsEvent, ExtAluEvent,
//     FriFoldEvent, MemEvent, Poseidon2Event, RecursionProgram, SelectEvent,
// };

// #[derive(Clone, Default, Debug)]
// pub struct ExecutionRecord<F> {
//     pub program: Arc<RecursionProgram<F>>,
//     /// The index of the shard.
//     pub index: u32,

//     pub base_alu_events: Vec<BaseAluEvent<F>>,
//     pub ext_alu_events: Vec<ExtAluEvent<F>>,
//     pub mem_const_count: usize,
//     pub mem_var_events: Vec<MemEvent<F>>,
//     /// The public values.
//     pub public_values: RecursionPublicValues<F>,

//     pub poseidon2_events: Vec<Poseidon2Event<F>>,
//     pub select_events: Vec<SelectEvent<F>>,
//     pub exp_reverse_bits_len_events: Vec<ExpReverseBitsEvent<F>>,
//     pub fri_fold_events: Vec<FriFoldEvent<F>>,
//     pub batch_fri_events: Vec<BatchFRIEvent<F>>,
//     pub prefix_sum_checks_events: Vec<PrefixSumChecksEvent<F>>,
//     pub commit_pv_hash_events: Vec<CommitPublicValuesEvent<F>>,
// }

// #[derive(Debug)]
// pub struct UnsafeRecord<F> {
//     pub base_alu_events: Vec<MaybeUninit<UnsafeCell<BaseAluEvent<F>>>>,
//     pub ext_alu_events: Vec<MaybeUninit<UnsafeCell<ExtAluEvent<F>>>>,
//     // Can be computed by the analysis step.
//     pub mem_const_count: usize,
//     pub mem_var_events: Vec<MaybeUninit<UnsafeCell<MemEvent<F>>>>,
//     /// The public values.
//     pub public_values: MaybeUninit<UnsafeCell<RecursionPublicValues<F>>>,

//     pub poseidon2_events: Vec<MaybeUninit<UnsafeCell<Poseidon2Event<F>>>>,
//     pub select_events: Vec<MaybeUninit<UnsafeCell<SelectEvent<F>>>>,
//     pub exp_reverse_bits_len_events: Vec<MaybeUninit<UnsafeCell<ExpReverseBitsEvent<F>>>>,
//     pub fri_fold_events: Vec<MaybeUninit<UnsafeCell<FriFoldEvent<F>>>>,
//     pub batch_fri_events: Vec<MaybeUninit<UnsafeCell<BatchFRIEvent<F>>>>,
//     pub prefix_sum_checks_events: Vec<MaybeUninit<UnsafeCell<PrefixSumChecksEvent<F>>>>,
//     pub commit_pv_hash_events: Vec<MaybeUninit<UnsafeCell<CommitPublicValuesEvent<F>>>>,
// }

// impl<F> UnsafeRecord<F> {
//     /// # Safety
//     ///
//     /// The caller must ensure that the `UnsafeRecord` is fully initialized, this is
//     /// done by the runtime.
//     pub unsafe fn into_record(
//         self,
//         program: Arc<RecursionProgram<F>>,
//         index: u32,
//     ) -> ExecutionRecord<F> {
//         // SAFETY: `T` and `MaybeUninit<UnsafeCell<T>>` have the same memory layout.
//         #[allow(clippy::missing_transmute_annotations)]
//         ExecutionRecord {
//             program,
//             index,
//             base_alu_events: std::mem::transmute(self.base_alu_events),
//             ext_alu_events: std::mem::transmute(self.ext_alu_events),
//             mem_const_count: self.mem_const_count,
//             mem_var_events: std::mem::transmute(self.mem_var_events),
//             public_values: self.public_values.assume_init().into_inner(),
//             poseidon2_events: std::mem::transmute(self.poseidon2_events),
//             select_events: std::mem::transmute(self.select_events),
//             exp_reverse_bits_len_events: std::mem::transmute(self.exp_reverse_bits_len_events),
//             fri_fold_events: std::mem::transmute(self.fri_fold_events),
//             batch_fri_events: std::mem::transmute(self.batch_fri_events),
//             prefix_sum_checks_events: std::mem::transmute(self.prefix_sum_checks_events),
//             commit_pv_hash_events: std::mem::transmute(self.commit_pv_hash_events),
//         }
//     }

//     pub fn new(event_counts: RecursionAirEventCount) -> Self
//     where
//         F: Field,
//     {
//         #[inline]
//         fn create_uninit_vec<T>(len: usize) -> Vec<MaybeUninit<T>> {
//             let mut vec = Vec::with_capacity(len);
//             // SAFETY: The vector has enough capacity to hold the elements as we just allocated it,
//             // and the type `T` is `MaybeUninit` which implies that an "uninitialized" value is OK.
//             unsafe { vec.set_len(len) };
//             vec
//         }

//         Self {
//             base_alu_events: create_uninit_vec(event_counts.base_alu_events),
//             ext_alu_events: create_uninit_vec(event_counts.ext_alu_events),
//             mem_const_count: event_counts.mem_const_events,
//             mem_var_events: create_uninit_vec(event_counts.mem_var_events),
//             public_values: MaybeUninit::uninit(),
//             poseidon2_events: create_uninit_vec(event_counts.poseidon2_wide_events),
//             select_events: create_uninit_vec(event_counts.select_events),
//             exp_reverse_bits_len_events: create_uninit_vec(
//                 event_counts.exp_reverse_bits_len_events,
//             ),
//             fri_fold_events: create_uninit_vec(event_counts.fri_fold_events),
//             batch_fri_events: create_uninit_vec(event_counts.batch_fri_events),
//             prefix_sum_checks_events: create_uninit_vec(event_counts.prefix_sum_checks_events),
//             commit_pv_hash_events: create_uninit_vec(event_counts.commit_pv_hash_events),
//         }
//     }
// }

// unsafe impl<F> Sync for UnsafeRecord<F> {}

// impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
//     // type Config = SP1CoreOpts;

//     fn stats(&self) -> hashbrown::HashMap<String, usize> {
//         [
//             ("base_alu_events", self.base_alu_events.len()),
//             ("ext_alu_events", self.ext_alu_events.len()),
//             ("mem_const_count", self.mem_const_count),
//             ("mem_var_events", self.mem_var_events.len()),
//             ("poseidon2_events", self.poseidon2_events.len()),
//             ("select_events", self.select_events.len()),
//             ("exp_reverse_bits_len_events", self.exp_reverse_bits_len_events.len()),
//             ("fri_fold_events", self.fri_fold_events.len()),
//             ("batch_fri_events", self.batch_fri_events.len()),
//             ("prefix_sum_checks_events", self.prefix_sum_checks_events.len()),
//             ("commit_pv_hash_events", self.commit_pv_hash_events.len()),
//         ]
//         .into_iter()
//         .map(|(k, v)| (k.to_owned(), v))
//         .collect()
//     }

//     fn append(&mut self, other: &mut Self) {
//         // Exhaustive destructuring for refactoring purposes.
//         let Self {
//             program: _,
//             index: _,
//             base_alu_events,
//             ext_alu_events,
//             mem_const_count,
//             mem_var_events,
//             public_values: _,
//             poseidon2_events,
//             select_events,
//             exp_reverse_bits_len_events,
//             fri_fold_events,
//             batch_fri_events,
//             prefix_sum_checks_events,
//             commit_pv_hash_events,
//         } = self;
//         base_alu_events.append(&mut other.base_alu_events);
//         ext_alu_events.append(&mut other.ext_alu_events);
//         *mem_const_count += other.mem_const_count;
//         mem_var_events.append(&mut other.mem_var_events);
//         poseidon2_events.append(&mut other.poseidon2_events);
//         select_events.append(&mut other.select_events);
//         exp_reverse_bits_len_events.append(&mut other.exp_reverse_bits_len_events);
//         fri_fold_events.append(&mut other.fri_fold_events);
//         batch_fri_events.append(&mut other.batch_fri_events);
//         prefix_sum_checks_events.append(&mut other.prefix_sum_checks_events);
//         commit_pv_hash_events.append(&mut other.commit_pv_hash_events);
//     }

//     fn public_values<T: AbstractField>(&self) -> Vec<T> {
//         let pv_elms = self.public_values.as_array();

//         let ret: [T; PROOF_MAX_NUM_PVS] = array::from_fn(|i| {
//             if i < pv_elms.len() {
//                 T::from_canonical_u32(pv_elms[i].as_canonical_u32())
//             } else {
//                 T::zero()
//             }
//         });

//         ret.to_vec()
//     }

//     // No public value constraints for recursion public values.
//     fn eval_public_values<AB: SP1AirBuilder>(_builder: &mut AB) {}
// }

// impl<F: Field> ExecutionRecord<F> {
//     pub fn preallocate(&mut self, event_counts: RecursionAirEventCount) {
//         self.poseidon2_events.reserve(event_counts.poseidon2_wide_events);
//         self.mem_var_events.reserve(event_counts.mem_var_events);
//         self.base_alu_events.reserve(event_counts.base_alu_events);
//         self.ext_alu_events.reserve(event_counts.ext_alu_events);
//         self.exp_reverse_bits_len_events.reserve(event_counts.exp_reverse_bits_len_events);
//         self.select_events.reserve(event_counts.select_events);
//         self.prefix_sum_checks_events.reserve(event_counts.prefix_sum_checks_events);
//         self.mem_const_count = event_counts.mem_const_events;
//     }

//     pub fn compute_event_counts<'a>(
//         instrs: impl Iterator<Item = &'a Instruction<F>> + 'a,
//     ) -> RecursionAirEventCount {
//         instrs.fold(RecursionAirEventCount::default(), Add::add)
//     }
// }

// #[derive(Default, Debug, Clone, Copy, Serialize, Deserialize)]
// pub struct RecursionAirEventCount {
//     pub mem_const_events: usize,
//     pub mem_var_events: usize,
//     pub base_alu_events: usize,
//     pub ext_alu_events: usize,
//     pub poseidon2_wide_events: usize,
//     pub fri_fold_events: usize,
//     pub batch_fri_events: usize,
//     pub select_events: usize,
//     pub exp_reverse_bits_len_events: usize,
//     pub prefix_sum_checks_events: usize,
//     pub commit_pv_hash_events: usize,
// }

// impl<F> AddAssign<&Instruction<F>> for RecursionAirEventCount {
//     #[inline]
//     fn add_assign(&mut self, rhs: &Instruction<F>) {
//         match rhs {
//             Instruction::BaseAlu(_) => self.base_alu_events += 1,
//             Instruction::ExtAlu(_) => self.ext_alu_events += 1,
//             Instruction::Mem(_) => self.mem_const_events += 1,
//             Instruction::Poseidon2(_) => self.poseidon2_wide_events += 1,
//             Instruction::Select(_) => self.select_events += 1,
//             Instruction::ExpReverseBitsLen(ExpReverseBitsInstr { addrs, .. }) => {
//                 self.exp_reverse_bits_len_events += addrs.exp.len()
//             }
//             Instruction::Hint(HintInstr { output_addrs_mults })
//             | Instruction::HintBits(HintBitsInstr {
//                 output_addrs_mults,
//                 input_addr: _, // No receive interaction for the hint operation
//             }) => self.mem_var_events += output_addrs_mults.len(),
//             Instruction::HintExt2Felts(HintExt2FeltsInstr {
//                 output_addrs_mults,
//                 input_addr: _, // No receive interaction for the hint operation
//             }) => self.mem_var_events += output_addrs_mults.len(),
//             Instruction::FriFold(_) => self.fri_fold_events += 1,
//             Instruction::BatchFRI(instr) => {
//                 self.batch_fri_events += instr.base_vec_addrs.p_at_x.len()
//             }
//             Instruction::PrefixSumChecks(instr) => {
//                 self.prefix_sum_checks_events += instr.addrs.x1.len()
//             }
//             Instruction::HintAddCurve(instr) => {
//                 self.mem_var_events += instr.output_x_addrs_mults.len();
//                 self.mem_var_events += instr.output_y_addrs_mults.len();
//             }
//             Instruction::CommitPublicValues(_) => self.commit_pv_hash_events += 1,
//             Instruction::Print(_) | Instruction::DebugBacktrace(_) => {}
//         }
//     }
// }

// impl<F> Add<&Instruction<F>> for RecursionAirEventCount {
//     type Output = Self;

//     #[inline]
//     fn add(mut self, rhs: &Instruction<F>) -> Self::Output {
//         self += rhs;
//         self
//     }
// }
