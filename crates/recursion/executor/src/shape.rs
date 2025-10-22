use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};
use slop_algebra::{Field, PrimeField32};
use sp1_hypercube::{air::MachineAir, ChipDimensions};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecursionShape<F> {
    heights: BTreeMap<String, usize>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField32> RecursionShape<F> {
    pub const fn new(heights: BTreeMap<String, usize>) -> Self {
        Self { heights, _marker: PhantomData }
    }

    pub fn height<A>(&self, air: &A) -> Option<usize>
    where
        F: Field,
        A: MachineAir<F>,
    {
        self.heights.get(&air.name()).copied()
    }

    pub fn height_of_name(&self, name: &str) -> Option<usize> {
        self.heights.get(name).copied()
    }

    pub fn insert<A>(&mut self, air: &A, height: usize)
    where
        F: Field,
        A: MachineAir<F>,
    {
        self.heights.insert(air.name(), height);
    }

    pub fn insert_with_name(&mut self, name: &str, height: usize) {
        self.heights.insert(name.to_string(), height);
    }

    pub const fn empty() -> Self {
        Self { heights: BTreeMap::new(), _marker: PhantomData }
    }

    pub fn preprocessed_chip_information<A>(
        &self,
        chips: &BTreeSet<A>,
    ) -> BTreeMap<String, ChipDimensions<F>>
    where
        F: Field,
        A: MachineAir<F>,
    {
        chips
            .iter()
            .filter_map(|chip| {
                self.height(chip).map(|height| {
                    (
                        chip.name(),
                        ChipDimensions {
                            height: F::from_canonical_u32(height as u32),
                            num_polynomials: F::from_canonical_u32(chip.preprocessed_width() as u32),
                        },
                    )
                })
            })
            .collect()
    }
}

impl<F: Field, A: MachineAir<F>> FromIterator<(A, usize)> for RecursionShape<F> {
    fn from_iter<T: IntoIterator<Item = (A, usize)>>(iter: T) -> Self {
        RecursionShape {
            heights: iter.into_iter().map(|(air, height)| (air.name(), height)).collect(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field> IntoIterator for RecursionShape<F> {
    type Item = (String, usize);
    type IntoIter = <BTreeMap<String, usize> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.heights.into_iter()
    }
}

impl<'a, F: Field> IntoIterator for &'a RecursionShape<F> {
    type Item = (&'a String, &'a usize);
    type IntoIter = <&'a BTreeMap<String, usize> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.heights.iter()
    }
}
