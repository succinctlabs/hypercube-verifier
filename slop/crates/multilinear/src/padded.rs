use std::{mem::ManuallyDrop, sync::Arc};

use futures::future::OptionFuture;
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField};
use slop_alloc::{Backend, CpuBackend, HasBackend, ToHost, GLOBAL_CPU_BACKEND};
use slop_tensor::{AddAssignBackend, Tensor};

use crate::{
    full_geq, HostEvaluationBackend, Mle, MleBaseBackend, MleEval, MleEvaluationBackend,
    MleFixLastVariableBackend, PartialLagrangeBackend, Point, PointBackend,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "MleEval<F, A>: Serialize, F: Serialize, A: Serialize",
    deserialize = "MleEval<F, A>: Deserialize<'de>, F: Deserialize<'de>, A: Deserialize<'de>"
))]
pub enum Padding<F, A: Backend> {
    Constant((F, usize, A)),
    Generic(Arc<MleEval<F, A>>),
    Zero((usize, A)),
}

impl<F, A: Backend> HasBackend for Padding<F, A> {
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        match self {
            Padding::Constant((_, _, backend)) => backend,
            Padding::Generic(eval) => eval.backend(),
            Padding::Zero((_, backend)) => backend,
        }
    }
}

impl<F: Clone, A: Backend> Padding<F, A> {
    pub fn num_polynomials(&self) -> usize {
        match self {
            Padding::Constant((_, num_polynomials, _)) => *num_polynomials,
            Padding::Generic(ref eval) => eval.num_polynomials(),
            Padding::Zero((num_polynomials, _)) => *num_polynomials,
        }
    }
}

impl<F: AbstractField> From<Padding<F, CpuBackend>> for Vec<F> {
    fn from(padding: Padding<F, CpuBackend>) -> Self {
        match padding {
            Padding::Constant((value, num_polynomials, _)) => vec![value; num_polynomials],
            Padding::Generic(eval) => eval.evaluations().as_buffer().to_vec(),
            Padding::Zero((num_polynomials, _)) => vec![F::zero(); num_polynomials],
        }
    }
}

impl<F, A: Backend> From<MleEval<F, A>> for Padding<F, A> {
    fn from(eval: MleEval<F, A>) -> Self {
        Padding::Generic(Arc::new(eval))
    }
}

/// A bacth of multi-linear polynomials, potentially padded with additional variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Tensor<T, A>: Serialize, T: Serialize, A: Serialize",
    deserialize = "Tensor<T, A>: Deserialize<'de>, T: Deserialize<'de>, A: Deserialize<'de>"
))]
pub struct PaddedMle<T, A: Backend = CpuBackend> {
    inner: Option<Arc<Mle<T, A>>>,
    padding_values: Padding<T, A>,
    num_variables: u32,
}

impl<T: AbstractField, A: MleBaseBackend<T>> PaddedMle<T, A> {
    #[inline]
    pub const fn new(
        inner: Option<Arc<Mle<T, A>>>,
        num_variables: u32,
        padding_values: Padding<T, A>,
    ) -> Self {
        Self { inner, num_variables, padding_values }
    }

    pub fn padded(inner: Arc<Mle<T, A>>, num_variables: u32, padding_values: Padding<T, A>) -> Self
    where
        A: MleBaseBackend<T>,
    {
        assert!(inner.num_non_zero_entries() <= 1 << num_variables);
        assert_eq!(padding_values.num_polynomials(), inner.num_polynomials());
        Self { inner: Some(inner), num_variables, padding_values }
    }

    pub fn dummy(num_variables: u32, padding_values: Padding<T, A>) -> Self {
        Self { inner: None, num_variables, padding_values }
    }

    pub fn with_minimal_padding(inner: Arc<Mle<T, A>>, padding_values: Padding<T, A>) -> Self
    where
        A: MleBaseBackend<T>,
    {
        let num_padded_variables = inner.num_variables();
        Self::padded(inner, num_padded_variables, padding_values)
    }

    pub fn padded_with_zeros(inner: Arc<Mle<T, A>>, num_variables: u32) -> Self
    where
        A: MleBaseBackend<T>,
    {
        let num_polys = inner.num_polynomials();
        let backend = inner.backend().clone();
        Self::padded(inner, num_variables, Padding::Constant((T::zero(), num_polys, backend)))
    }

    pub fn zeros_in(num_polynomials: usize, num_variables: u32, backend: &A) -> Self
    where
        A: MleBaseBackend<T>,
    {
        Self::dummy(num_variables, Padding::Zero((num_polynomials, backend.clone())))
    }

    /// Returns the number of variables in the multi-linear polynomial.
    pub fn num_variables(&self) -> u32 {
        self.num_variables
    }

    pub fn into_inner(self) -> Option<Arc<Mle<T, A>>> {
        self.inner
    }

    /// Returns the padding value.
    pub fn padding_values(&self) -> &Padding<T, A> {
        &self.padding_values
    }

    pub fn num_real_entries(&self) -> usize {
        self.inner.as_ref().map(|mle| mle.num_non_zero_entries()).unwrap_or(0)
    }

    /// Returns the underlying tensor.
    pub fn inner(&self) -> &Option<Arc<Mle<T, A>>> {
        &self.inner
    }

    #[inline]
    pub fn num_polynomials(&self) -> usize
    where
        A: MleBaseBackend<T>,
    {
        self.padding_values.num_polynomials()
    }

    #[inline]
    pub async fn fix_last_variable<EF>(&self, alpha: EF) -> PaddedMle<EF, A>
    where
        T: AbstractField,
        EF: AbstractExtensionField<T>,
        A: MleFixLastVariableBackend<T, EF>
            + MleBaseBackend<EF>
            + HostEvaluationBackend<T, T>
            + HostEvaluationBackend<T, EF>,
    {
        assert!(self.num_variables > 0);
        match &self.padding_values {
            Padding::Generic(orig_padding_values) => {
                let backend = orig_padding_values.backend().clone();
                let new_padding_values: MleEval<EF> = orig_padding_values
                    .to_host()
                    .await
                    .unwrap()
                    .to_vec()
                    .iter()
                    .cloned()
                    .map(EF::from_base)
                    .collect::<Vec<_>>()
                    .into();
                let padding_values: MleEval<EF, A> =
                    backend.copy_to(&new_padding_values).await.unwrap();
                let inner = OptionFuture::from(self.inner.as_ref().map(|mle| async move {
                    let guts =
                        A::mle_fix_last_variable(mle.guts(), alpha, orig_padding_values.clone())
                            .await;
                    Mle::<EF, A>::new(guts)
                }))
                .await;
                let inner = inner.map(Arc::new);
                PaddedMle {
                    inner,
                    padding_values: Padding::Generic(Arc::new(padding_values)),
                    num_variables: self.num_variables - 1,
                }
            }

            Padding::Constant((padding_value, _, backend)) => {
                let padding_value_clone = padding_value.clone();
                let inner = OptionFuture::from(self.inner.as_ref().map(|mle| async move {
                    let guts = A::mle_fix_last_variable_constant_padding(
                        mle.guts(),
                        alpha,
                        padding_value.clone(),
                    )
                    .await;
                    Mle::<EF, A>::new(guts)
                }))
                .await;
                let inner = inner.map(Arc::new);
                PaddedMle {
                    inner,
                    padding_values: Padding::Constant((
                        EF::from_base(padding_value_clone),
                        self.num_polynomials(),
                        backend.clone(),
                    )),
                    num_variables: self.num_variables - 1,
                }
            }

            Padding::Zero((_, backend)) => {
                let inner = OptionFuture::from(self.inner.as_ref().map(|mle| async move {
                    let guts =
                        A::mle_fix_last_variable_constant_padding(mle.guts(), alpha, T::zero())
                            .await;
                    Mle::<EF, A>::new(guts)
                }))
                .await;
                let inner = inner.map(Arc::new);
                PaddedMle {
                    inner,
                    padding_values: Padding::Zero((self.num_polynomials(), backend.clone())),
                    num_variables: self.num_variables - 1,
                }
            }
        }
    }

    pub async fn eval_at_eq<ET: AbstractExtensionField<T> + Send + Sync + Eq + 'static>(
        &self,
        point: &Point<ET>,
        eq: &Mle<ET, A>,
    ) -> MleEval<ET, A>
    where
        A: MleEvaluationBackend<T, ET>
            + MleBaseBackend<ET>
            + HostEvaluationBackend<T, T>
            + HostEvaluationBackend<T, ET>
            + PointBackend<ET>
            + AddAssignBackend<ET>,
    {
        let num_real_entries =
            self.inner.as_ref().map(|mle| mle.num_non_zero_entries()).unwrap_or(0);
        match &self.padding_values {
            Padding::Generic(orig_padding_values) => {
                let geq_adjustments: MleEval<ET> = if num_real_entries < 1 << self.num_variables {
                    orig_padding_values
                        .to_host()
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|x| {
                            full_geq(
                                &Point::from_usize(num_real_entries, self.num_variables as usize),
                                point,
                            ) * x
                        })
                        .collect::<Vec<_>>()
                        .into()
                } else {
                    assert!(num_real_entries == 1 << self.num_variables);
                    vec![ET::zero(); self.num_polynomials()].into()
                };

                let final_evals = if let Some(inner) = self.inner.as_ref() {
                    let point = self.backend().copy_to(point).await.unwrap();
                    let evals = inner.eval_at(&point).await.to_host().await.unwrap();
                    evals.add_evals(geq_adjustments)
                } else {
                    geq_adjustments
                };

                self.backend().copy_to(&final_evals).await.unwrap()
            }
            Padding::Constant((padding_value, _, _)) => {
                let geq_adjustment = if num_real_entries < 1 << self.num_variables {
                    full_geq(
                        &Point::from_usize(num_real_entries, self.num_variables as usize),
                        point,
                    ) * padding_value.clone()
                } else {
                    assert!(num_real_entries == 1 << self.num_variables);
                    ET::zero()
                };

                let mut evals = if let Some(inner) = self.inner.as_ref() {
                    inner.eval_at_eq(eq).await
                } else {
                    MleEval::zeros_in(self.num_polynomials(), self.backend())
                };

                unsafe { A::add_assign(evals.evaluations_mut(), geq_adjustment).await };
                evals
            }

            Padding::Zero(_) => {
                if let Some(inner) = self.inner.as_ref() {
                    inner.eval_at_eq(eq).await
                } else {
                    MleEval::zeros_in(self.num_polynomials(), self.backend())
                }
            }
        }
    }

    pub async fn eval_at<ET: AbstractExtensionField<T> + Send + Sync + Eq + 'static>(
        &self,
        point: &Point<ET>,
    ) -> MleEval<ET, A>
    where
        A: MleEvaluationBackend<T, ET>
            + MleBaseBackend<ET>
            + HostEvaluationBackend<T, T>
            + HostEvaluationBackend<T, ET>
            + PointBackend<ET>
            + PartialLagrangeBackend<ET>
            + AddAssignBackend<ET>,
    {
        let point_a = self.backend().copy_to(point).await.unwrap();
        let eq = Mle::partial_lagrange(&point_a).await;
        self.eval_at_eq(point, &eq).await
    }

    /// # Safety
    ///
    /// The caller must ensure that the lifetime bounds are being respected, as this function
    /// completely breaks the lifetime bound of the padded mle.
    #[inline]
    pub unsafe fn owned_unchecked_in(&self, storage_allocator: A) -> ManuallyDrop<Self> {
        let inner = self.inner.as_ref().map(|mle| {
            let mle = mle.owned_unchecked_in(storage_allocator.clone());
            let mle = ManuallyDrop::into_inner(mle);
            Arc::new(mle)
        });

        let padding_values = match &self.padding_values {
            Padding::Constant((value, num_polynomials, _)) => {
                Padding::Constant((value.clone(), *num_polynomials, storage_allocator))
            }
            Padding::Zero((num_polynomials, _)) => {
                Padding::Zero((*num_polynomials, storage_allocator))
            }
            Padding::Generic(eval) => {
                let evaluations = eval.owned_unchecked_in(storage_allocator);
                let evaluations = ManuallyDrop::into_inner(evaluations);
                Padding::Generic(Arc::new(evaluations))
            }
        };

        let padded_mle = PaddedMle { inner, padding_values, num_variables: self.num_variables };
        ManuallyDrop::new(padded_mle)
    }
}

impl<T> PaddedMle<T, CpuBackend> {
    pub fn zeros(num_polynomials: usize, num_variables: u32) -> Self
    where
        T: AbstractField,
    {
        Self::zeros_in(num_polynomials, num_variables, &GLOBAL_CPU_BACKEND)
    }
}

impl<T, A: Backend> HasBackend for PaddedMle<T, A> {
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        match &self.padding_values {
            Padding::Generic(eval) => eval.backend(),
            Padding::Constant((_, _, backend)) => backend,
            Padding::Zero((_, backend)) => backend,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use slop_baby_bear::BabyBear;

    use crate::Mle;

    use super::*;

    #[tokio::test]
    async fn test_padded_eval_at() {
        let padded_guts = vec![1, 2, 3, 1, 1, 1, 1, 1]
            .into_iter()
            .map(BabyBear::from_canonical_usize)
            .collect::<Vec<_>>();

        let point = (0..3).map(|_| rand::thread_rng().gen::<BabyBear>()).collect::<Point<_>>();
        for i in 3..8 {
            let virtually_padded_mle = PaddedMle::padded(
                Arc::new(padded_guts[..i].to_vec().into()),
                3,
                Padding::Constant((BabyBear::one(), 1, CpuBackend)),
            );

            let other_virtually_padded_mle = PaddedMle::padded(
                Arc::new(padded_guts[..i].to_vec().into()),
                3,
                Padding::Generic(Arc::new(vec![BabyBear::one()].into())),
            );
            assert_eq!(
                Into::<Mle<_>>::into(padded_guts.clone()).eval_at(&point).await.to_vec()[0],
                virtually_padded_mle.eval_at(&point).await.to_vec()[0]
            );
            assert_eq!(
                Into::<Mle<_>>::into(padded_guts.clone()).eval_at(&point).await.to_vec()[0],
                other_virtually_padded_mle.eval_at(&point).await.to_vec()[0]
            );
        }
    }

    #[tokio::test]
    async fn test_pure_padded_mle() {
        let mut rng = rand::thread_rng();
        let padded_values = (0..1000).map(|_| rng.gen::<BabyBear>()).collect::<Vec<_>>();
        let padded_values = Arc::new(MleEval::<BabyBear, CpuBackend>::from(padded_values));
        let num_variables = 16;
        let padded_mle = PaddedMle::dummy(num_variables, Padding::Generic(padded_values.clone()));
        let point =
            (0..num_variables).map(|_| rand::thread_rng().gen::<BabyBear>()).collect::<Point<_>>();
        let evals = padded_mle.eval_at(&point).await;
        assert_eq!(evals.to_vec(), padded_values.to_vec());
    }

    #[tokio::test]
    async fn test_padded_fix_last_variable() {
        let padded_guts = vec![1, 2, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
            .into_iter()
            .map(BabyBear::from_canonical_usize)
            .collect::<Vec<_>>();

        for i in 3..16 {
            let virtually_padded_mle = PaddedMle::padded(
                Arc::new(padded_guts[..i].to_vec().into()),
                4,
                Padding::Constant((BabyBear::one(), 1, CpuBackend)),
            );
            let other_virtually_padded_mle = PaddedMle::padded(
                Arc::new(padded_guts[..i].to_vec().into()),
                4,
                Padding::Generic(Arc::new(vec![BabyBear::one()].into())),
            );
            let mut virtual_cursor = virtually_padded_mle.clone();
            let mut other_virtual_cursor = other_virtually_padded_mle.clone();
            let mut cursor: Mle<_> = padded_guts.clone().into();

            for j in 0..4 {
                let alpha = rand::thread_rng().gen::<BabyBear>();
                virtual_cursor = virtual_cursor.fix_last_variable(alpha).await;
                other_virtual_cursor = other_virtual_cursor.fix_last_variable(alpha).await;
                cursor = cursor.fix_last_variable(alpha).await;
                let beta = (0..(3 - j)).map(|_| rand::thread_rng().gen::<BabyBear>()).collect();
                assert_eq!(
                    virtual_cursor.eval_at(&beta).await.to_vec()[0],
                    cursor.eval_at(&beta).await.to_vec()[0]
                );
                assert_eq!(
                    other_virtual_cursor.eval_at(&beta).await.to_vec()[0],
                    cursor.eval_at(&beta).await.to_vec()[0]
                );
            }
        }
    }
}
