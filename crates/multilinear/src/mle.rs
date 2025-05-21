use std::{
    mem::ManuallyDrop,
    ops::{Add, Deref, DerefMut},
};

use rayon::prelude::*;

use derive_where::derive_where;
use hypercube_alloc::{Backend, Buffer, CpuBackend, HasBackend, GLOBAL_CPU_BACKEND};
use hypercube_tensor::Tensor;
use p3_field::{AbstractExtensionField, AbstractField, Field};
use rand::{distributions::Standard, prelude::Distribution, Rng};
use serde::{Deserialize, Serialize};

use crate::eval::{eval_mle_at_point_blocking, eval_mle_at_point_small_batch};
use crate::{partial_lagrange_blocking, MleBaseBackend, Point};

/// A bacth of multi-linear polynomials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive_where(PartialEq, Eq; Tensor<T, A>)]
#[serde(bound(
    serialize = "Tensor<T, A>: Serialize",
    deserialize = "Tensor<T, A>: Deserialize<'de>"
))]
pub struct Mle<T, A: Backend = CpuBackend> {
    guts: Tensor<T, A>,
}

impl<F, A: Backend> HasBackend for Mle<F, A> {
    type Backend = A;

    #[inline]
    fn backend(&self) -> &Self::Backend {
        self.guts.backend()
    }
}

impl<F, A: Backend> Mle<F, A> {
    /// Creates a new MLE from a tensor in the correct shape.
    ///
    /// The tensor must be in the correct shape for the given backend.
    #[inline]
    pub const fn new(guts: Tensor<F, A>) -> Self {
        Self { guts }
    }

    #[inline]
    pub fn backend(&self) -> &A {
        self.guts.backend()
    }

    #[inline]
    pub fn into_guts(self) -> Tensor<F, A> {
        self.guts
    }

    /// Creates a new uninitialized MLE batch of the given size and number of variables.
    #[inline]
    pub fn uninit(num_polynomials: usize, num_non_zero_entries: usize, scope: &A) -> Self
    where
        F: AbstractField,
        A: MleBaseBackend<F>,
    {
        // The tensor is initialized in the correct shape by the backend.
        Self::new(scope.uninit_mle(num_polynomials, num_non_zero_entries))
    }

    #[inline]
    pub fn zeros(num_polynomials: usize, num_non_zero_entries: usize, scope: &A) -> Self
    where
        F: AbstractField,
        A: MleBaseBackend<F>,
    {
        let mut mle = Self::uninit(num_polynomials, num_non_zero_entries, scope);
        let guts = mle.guts_mut();
        let total_len = guts.total_len();
        guts.storage.write_bytes(0, total_len * std::mem::size_of::<F>()).unwrap();
        mle
    }

    #[inline]
    pub const fn guts(&self) -> &Tensor<F, A> {
        &self.guts
    }

    /// Mutable access to the guts of the MLE.
    ///
    /// Changing the guts must preserve the layout that the MLE backend expects to have for a valid
    /// tensor to qualify as the guts of an MLE. For example, dimension matching the implementation
    /// of [Self::uninit].
    pub fn guts_mut(&mut self) -> &mut Tensor<F, A> {
        &mut self.guts
    }

    /// # Safety
    // #[inline]
    // pub unsafe fn assume_init(&mut self) {
    //     self.guts.assume_init();
    // }

    /// Returns the number of polynomials in the batch.
    #[inline]
    pub fn num_polynomials(&self) -> usize
    where
        F: AbstractField,
        A: MleBaseBackend<F>,
    {
        A::num_polynomials(&self.guts)
    }

    /// Returns the number of variables in the polynomials.
    #[inline]
    pub fn num_variables(&self) -> u32
    where
        F: AbstractField,
        A: MleBaseBackend<F>,
    {
        A::num_variables(&self.guts)
    }

    /// Returns the number of points on the hypercube that are non-zero, with respect to the
    /// canonical ordering.
    #[inline]
    pub fn num_non_zero_entries(&self) -> usize
    where
        F: AbstractField,
        A: MleBaseBackend<F>,
    {
        A::num_non_zero_entries(&self.guts)
    }

    // /// Evaluates the MLE at a given point.
    // #[inline]
    // pub async fn eval_at<EF: AbstractExtensionField<F>>(
    //     &self,
    //     point: &Point<EF, A>,
    // ) -> MleEval<EF, A>
    // where
    //     F: AbstractField,
    //     A: MleEvaluationBackend<F, EF>,
    // {
    //     let evaluations = A::eval_mle_at_point(&self.guts, point).await;
    //     MleEval::new(evaluations)
    // }

    // /// Evaluates the MLE at a given eq.
    // #[inline]
    // pub async fn eval_at_eq<EF: AbstractExtensionField<F>>(&self, eq: &Mle<EF, A>) -> MleEval<EF, A>
    // where
    //     F: AbstractField,
    //     A: MleEvaluationBackend<F, EF>,
    // {
    //     let evaluations = A::eval_mle_at_eq(&self.guts, &eq.guts).await;
    //     MleEval::new(evaluations)
    // }

    // /// Compute the random linear combination of the even and odd coefficients of `vals`.
    // ///
    // /// This is used in the `Basefold` PCS.
    // #[inline]
    // pub async fn fold(&self, beta: F) -> Mle<F, A>
    // where
    //     F: AbstractField,
    //     A: MleFoldBackend<F>,
    // {
    //     let guts = A::fold_mle(&self.guts, beta).await;
    //     Mle::new(guts)
    // }

    // #[inline]
    // pub async fn fix_last_variable<EF>(&self, alpha: EF) -> Mle<EF, A>
    // where
    //     F: AbstractField,
    //     EF: AbstractExtensionField<F>,
    //     A: MleFixLastVariableBackend<F, EF>,
    // {
    //     let guts = A::mle_fix_last_variable_constant_padding(&self.guts, alpha, F::zero()).await;
    //     Mle::new(guts)
    // }

    // #[inline]
    // pub async fn fix_last_variable_in_place(&mut self, alpha: F)
    // where
    //     F: AbstractField,
    //     A: MleFixLastVariableInPlaceBackend<F>,
    // {
    //     A::mle_fix_last_variable_in_place(&mut self.guts, alpha).await;
    // }

    // #[inline]
    // pub async fn fixed_at_zero<EF: AbstractExtensionField<F>>(
    //     &self,
    //     point: &Point<EF>,
    // ) -> MleEval<EF>
    // where
    //     F: AbstractField,
    //     A: MleFixedAtZeroBackend<F, EF>,
    // {
    //     MleEval::new(A::fixed_at_zero(&self.guts, point).await)
    // }

    /// # Safety
    ///
    /// This function is unsafe because it enables bypassing the lifetime of the mle.
    #[inline]
    pub unsafe fn owned_unchecked(&self) -> ManuallyDrop<Self> {
        self.owned_unchecked_in(self.guts.storage.allocator().clone())
    }

    /// # Safety
    ///
    /// This function is unsafe because it enables bypassing the lifetime of the mle.
    #[inline]
    pub unsafe fn owned_unchecked_in(&self, storage_allocator: A) -> ManuallyDrop<Self> {
        let guts = self.guts.owned_unchecked_in(storage_allocator);
        let guts = ManuallyDrop::into_inner(guts);
        ManuallyDrop::new(Self { guts })
    }
}

impl<T> Mle<T, CpuBackend> {
    pub fn rand<R: Rng>(rng: &mut R, num_polynomials: usize, num_variables: u32) -> Self
    where
        Standard: Distribution<T>,
    {
        Self::new(Tensor::rand(rng, [1 << num_variables, num_polynomials]))
    }

    /// Returns an iterator over the evaluations of the MLE on the Boolean hypercube.
    ///
    /// The iterator yields a slice for each index of the Boolean hypercube.
    pub fn hypercube_iter(&self) -> impl Iterator<Item = &[T]>
    where
        T: AbstractField,
    {
        let width = self.num_polynomials();
        let height = self.num_variables();
        (0..(1 << height)).map(move |i| &self.guts.as_slice()[i * width..(i + 1) * width])
    }

    /// Returns an iterator over the evaluations of the MLE on the Boolean hypercube.
    ///
    /// The iterator yields a slice for each index of the Boolean hypercube.
    pub fn hypercube_par_iter(&self) -> impl IndexedParallelIterator<Item = &[T]>
    where
        T: AbstractField + Sync,
    {
        let width = self.num_polynomials();
        let height = self.num_variables();
        (0..(1 << height))
            .into_par_iter()
            .map(move |i| &self.guts.as_slice()[i * width..(i + 1) * width])
    }

    /// # Safety
    pub unsafe fn from_raw_parts(ptr: *mut T, num_polynomials: usize, len: usize) -> Self {
        let total_len = num_polynomials * len;
        let buffer = Buffer::from_raw_parts(ptr, total_len, total_len, GLOBAL_CPU_BACKEND);
        Self::new(Tensor::from(buffer).reshape([len, num_polynomials]))
    }

    pub fn blocking_eval_at<E>(&self, point: &Point<E>) -> MleEval<E>
    where
        T: AbstractField + 'static + Send + Sync,
        E: AbstractExtensionField<T> + 'static + Send + Sync,
    {
        // Modify this line to use the optimized function when appropriate
        let result = if self.num_polynomials() < 4 {
            // For small batches, use the specialized implementation
            MleEval::new(eval_mle_at_point_small_batch(self.guts(), point))
        } else {
            // For larger batches, use the parallel implementation
            MleEval::new(eval_mle_at_point_blocking(self.guts(), point))
        };
        result
    }

    pub fn blocking_partial_lagrange(point: &Point<T>) -> Mle<T, CpuBackend>
    where
        T: 'static + AbstractField,
    {
        let guts = partial_lagrange_blocking(point);
        Mle::new(guts)
    }

    /// Evaluates the 2n-variate multilinear polynomial f(X,Y) = Prod_i (X_i * Y_i + (1-X_i) * (1-Y_i))
    /// at a given pair (X,Y) of n-dimenional BabyBearExtensionField points.
    ///
    /// This evaluation takes time linear in n to compute, so the verifier can easily compute it. Hence,
    /// even though
    /// ```full_lagrange_eval(point_1, point_2)==partial_lagrange_eval(point_1).eval_at_point(point_2)```,
    /// the RHS of the above equation runs in O(2^n) time, while the LHS runs in O(n).
    ///
    /// The polynomial f(X,Y) is an important building block in zerocheck and other protocols which use
    /// sumcheck.
        pub fn full_lagrange_eval<EF>(point_1: &Point<T>, point_2: &Point<EF>) -> EF
        where
            T: AbstractField,
            EF: AbstractExtensionField<T>,
        {
            assert_eq!(point_1.dimension(), point_2.dimension());
    
            // Iterate over all values in the n-variates X and Y.
            point_1
                .iter()
                .zip(point_2.iter())
                .map(|(x, y)| {
                    // Multiply by (x_i * y_i + (1-x_i) * (1-y_i)).
                    let prod = y.clone() * x.clone();
                    prod.clone() + prod + EF::one() - x.clone() - y.clone()
                })
                .product()
        }
    }


// pub fn blocking_eval_at<E>(&self, point: &Point<E>) -> MleEval<E>
// where
//     T: AbstractField + 'static + Send + Sync,
//     E: AbstractExtensionField<T> + 'static + Send + Sync,
// {
//     // Modify this line to use the optimized function when appropriate
//     let result = if self.num_polynomials() < 4 {
//         // For small batches, use the specialized implementation
//         MleEval::new(eval_mle_at_point_small_batch(self.guts(), point))
//     } else {
//         // For larger batches, use the parallel implementation
//         MleEval::new(eval_mle_at_point_blocking(self.guts(), point))
//     };
//     result
// }
// }

// impl<T: AbstractField + Send + Sync> TryInto<p3_matrix::dense::RowMajorMatrix<T>>
//     for Mle<T, CpuBackend>
// {
//     type Error = ();

//     fn try_into(self) -> Result<p3_matrix::dense::RowMajorMatrix<T>, Self::Error> {
//         let num_polys = self.num_polynomials();
//         let values = self.guts.into_buffer().to_vec();
//         Ok(p3_matrix::dense::RowMajorMatrix::new(values, num_polys))
//     }
// }

impl<T> From<Vec<T>> for Mle<T, CpuBackend> {
    fn from(values: Vec<T>) -> Self {
        let len = values.len();
        let tensor = Tensor::from(values).reshape([len, 1]);
        Self::new(tensor)
    }
}

impl<T: Clone + Send + Sync> From<p3_matrix::dense::RowMajorMatrix<T>> for Mle<T, CpuBackend> {
    fn from(values: p3_matrix::dense::RowMajorMatrix<T>) -> Self {
        Self::new(Tensor::from(values))
    }
}

impl<T> FromIterator<T> for Mle<T, CpuBackend> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::from(iter.into_iter().collect::<Vec<_>>())
    }
}

/// The multilinear polynomial whose evaluation on the Boolean hypercube performs outputs 1 if the
/// Boolean hypercube point is the bit-string representation of a number greater than or equal to
/// `threshold`, and 0 otherwise.
pub fn partial_geq<F: Field>(threshold: usize, num_variables: usize) -> Vec<F> {
    assert!(threshold <= 1 << num_variables);

    (0..(1 << num_variables)).map(|x| if x >= threshold { F::one() } else { F::zero() }).collect()
}

/// A succinct way to compute the evaluation of `partial_geq` at `eval_point`. The threshold is passed
/// as a `Point` on the Boolean hypercube.
///
/// # Panics
/// If the dimensions of `threshold` and `eval_point` do not match.
pub fn full_geq<F: AbstractField, EF: AbstractExtensionField<F>>(
    threshold: &Point<F>,
    eval_point: &Point<EF>,
) -> EF {
    assert_eq!(threshold.dimension(), eval_point.dimension());
    threshold.iter().rev().zip(eval_point.iter().rev()).fold(EF::one(), |acc, (x, y)| {
        ((EF::one() - y.clone()) * (F::one() - x.clone()) + y.clone() * x.clone()) * acc
            + y.clone() * (F::one() - x.clone())
    })
}

/// A bacth of multi-linear polynomial evaluations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive_where(PartialEq, Eq; Tensor<T, A>)]
#[serde(bound(
    serialize = "Tensor<T, A>: Serialize",
    deserialize = "Tensor<T, A>: Deserialize<'de>"
))]
pub struct MleEval<T, A: Backend = CpuBackend> {
    pub(crate) evaluations: Tensor<T, A>,
}

impl<T, A: Backend> MleEval<T, A> {
    /// Creates a new MLE evaluation from a tensor in the correct shape.
    #[inline]
    pub const fn new(evaluations: Tensor<T, A>) -> Self {
        Self { evaluations }
    }

    #[inline]
    pub fn evaluations(&self) -> &Tensor<T, A> {
        &self.evaluations
    }

    /// # Safety
    #[inline]
    pub unsafe fn evaluations_mut(&mut self) -> &mut Tensor<T, A> {
        &mut self.evaluations
    }

    #[inline]
    pub fn into_evaluations(self) -> Tensor<T, A> {
        self.evaluations
    }

    //. It is expected that `self.evaluations.sizes()` is one of the three options:
    /// `[1, num_polynomials]`, `[num_polynomials,1]`, or `[num_polynomials]`.
    #[inline]
    pub fn num_polynomials(&self) -> usize {
        self.evaluations.total_len()
    }

    /// # Safety
    ///
    /// This function is unsafe because it enables bypassing the lifetime of the mle.
    #[inline]
    pub unsafe fn owned_unchecked_in(&self, storage_allocator: A) -> ManuallyDrop<Self> {
        let evaluations = self.evaluations.owned_unchecked_in(storage_allocator);
        let evaluations = ManuallyDrop::into_inner(evaluations);
        ManuallyDrop::new(Self { evaluations })
    }

    /// # Safety
    ///
    /// This function is unsafe because it enables bypassing the lifetime of the mle.
    #[inline]
    pub unsafe fn owned_unchecked(&self) -> ManuallyDrop<Self> {
        self.owned_unchecked_in(self.evaluations.backend().clone())
    }
}

impl<T> MleEval<T, CpuBackend> {
    pub fn to_vec(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.evaluations.as_buffer().to_vec()
    }

    pub fn iter(&self) -> impl Iterator<Item = &[T]> + '_ {
        self.evaluations.split().map(|t| t.as_slice())
    }

    pub fn add_evals(self, other: Self) -> Self
    where
        T: Add<Output = T> + Clone,
    {
        self.to_vec().into_iter().zip(other.to_vec()).map(|(a, b)| a + b).collect::<Vec<_>>().into()
    }
}

impl<T> From<Vec<T>> for MleEval<T, CpuBackend> {
    fn from(evaluations: Vec<T>) -> Self {
        Self::new(evaluations.into())
    }
}

impl<T> Deref for MleEval<T, CpuBackend> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.evaluations.as_slice()
    }
}

impl<T> DerefMut for MleEval<T, CpuBackend> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.evaluations.as_mut_slice()
    }
}

impl<T, A: Backend> HasBackend for MleEval<T, A> {
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        self.evaluations.backend()
    }
}

impl<T> IntoIterator for MleEval<T, CpuBackend> {
    type Item = T;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.evaluations.into_buffer().into_vec().into_iter()
    }
}

impl<'a, T> IntoIterator for &'a MleEval<T, CpuBackend> {
    type Item = &'a T;
    type IntoIter = <&'a [T] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.evaluations.as_slice().iter()
    }
}

impl<T> FromIterator<T> for MleEval<T, CpuBackend> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::new(Tensor::from(iter.into_iter().collect::<Vec<_>>()))
    }
}

