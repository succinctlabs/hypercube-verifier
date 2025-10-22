use futures::{future::join_all, prelude::*};
use rand::{distributions::Standard, prelude::Distribution, Rng};
use std::sync::Arc;

use slop_algebra::{AbstractExtensionField, AbstractField, ExtensionField, Field};
use slop_alloc::{Backend, CpuBackend, HasBackend, ToHost};
use slop_commit::Message;
use slop_multilinear::{
    Mle, MleBaseBackend, MleEvaluationBackend, MleFixLastVariableBackend,
    MleFixLastVariableInPlaceBackend, Point, PointBackend,
};
use slop_stacked::{FixedRateInterleave, FixedRateInterleaveBackend, InterleaveMultilinears};

#[derive(Clone, Debug)]
pub struct LongMle<F, A: Backend = CpuBackend> {
    components: Message<Mle<F, A>>,
    log_stacking_height: u32,
}

impl<F, A: Backend> LongMle<F, A> {
    pub const fn new(components: Message<Mle<F, A>>, log_stacking_height: u32) -> Self {
        Self { components, log_stacking_height }
    }

    pub fn from_components(components: Vec<Mle<F, A>>, log_stacking_height: u32) -> Self {
        Self { components: Message::from(components), log_stacking_height }
    }

    #[inline]
    pub const fn log_stacking_height(&self) -> u32 {
        self.log_stacking_height
    }

    #[inline]
    pub fn into_components(self) -> Message<Mle<F, A>> {
        self.components
    }

    pub fn from_message(message: Message<Mle<F, A>>, log_stacking_height: u32) -> Self {
        Self { components: message, log_stacking_height }
    }

    pub async fn eval_at<EF>(&self, point: &Point<EF>) -> EF
    where
        F: AbstractField,
        EF: AbstractExtensionField<F> + 'static + Send + Sync,
        A: MleEvaluationBackend<F, EF> + PointBackend<EF>,
    {
        // Split the point into the interleaved and batched parts.
        let (batch_point, stack_point) =
            point.split_at(point.dimension() - self.log_stacking_height as usize);
        let stack_point = self.backend().copy_to(&stack_point).await.unwrap();

        let component_evaluations = stream::iter(self.components.iter())
            .then(|mle| mle.eval_at(&stack_point))
            .collect::<Vec<_>>()
            .await;

        // We do the final evaluation in the host since this is supposed to be a small number of
        // variables. For example, this is an evaluation the verifier will have to do when the
        // long MLE arises from interleaving.
        let evaluations_mle = stream::iter(component_evaluations.into_iter())
            .then(|evals| async move {
                let evals = evals.to_host().await.unwrap();
                stream::iter(evals.into_evaluations().into_buffer().into_vec().into_iter())
            })
            .flatten()
            .collect::<Vec<_>>()
            .await;
        let evaluations_mle = Mle::from(evaluations_mle);
        evaluations_mle.eval_at(&batch_point).await[0].clone()
    }

    pub async fn fix_last_variable<EF>(self, alpha: EF) -> LongMle<EF, A>
    where
        F: Field,
        EF: ExtensionField<F> + Copy,
        A: MleFixLastVariableBackend<F, EF> + FixedRateInterleaveBackend<F>,
    {
        if self.log_stacking_height <= 2 {
            let total_num_of_variables = self
                .components
                .iter()
                .map(|mle| mle.num_polynomials() << mle.num_variables())
                .sum::<usize>()
                .next_power_of_two()
                .ilog2();
            let stacker = FixedRateInterleave::<F, A>::new(1);
            let new_components =
                stacker.interleave_multilinears(self.components, total_num_of_variables).await;
            let restacked_mle =
                LongMle { components: new_components, log_stacking_height: total_num_of_variables };
            let components =
                join_all(restacked_mle.components.iter().map(|mle| mle.fix_last_variable(alpha)))
                    .await;
            return LongMle {
                components: Message::from(components),
                log_stacking_height: restacked_mle.log_stacking_height - 1,
            };
        }
        let components = join_all(
            self.components
                .into_iter()
                .map(|mle| async move { mle.fix_last_variable(alpha).await }),
        )
        .await;
        LongMle {
            components: Message::from(components),
            log_stacking_height: self.log_stacking_height - 1,
        }
    }

    pub async fn fix_last_variable_in_place(self, alpha: F) -> Self
    where
        F: Field,
        A: MleFixLastVariableInPlaceBackend<F>
            + MleFixLastVariableBackend<F, F>
            + FixedRateInterleaveBackend<F>,
    {
        if self.log_stacking_height == 0 {
            let total_num_of_variables = self
                .components
                .iter()
                .map(|mle| mle.num_polynomials())
                .sum::<usize>()
                .next_power_of_two()
                .ilog2();
            let stacker = FixedRateInterleave::<F, A>::new(1);
            let new_components = stacker
                .interleave_multilinears(self.components.clone(), total_num_of_variables)
                .await;
            let restacked_mle =
                LongMle { components: new_components, log_stacking_height: total_num_of_variables };
            let components = stream::iter(restacked_mle.components.iter())
                .then(move |mle| mle.fix_last_variable(alpha))
                .collect::<Message<_>>()
                .await;
            return LongMle {
                components,
                log_stacking_height: restacked_mle.log_stacking_height - 1,
            };
        }
        let components = stream::iter(self.components.into_iter())
            .then(move |mle| async move {
                let mut mle = Arc::into_inner(mle).unwrap();
                mle.fix_last_variable_in_place(alpha).await;
                mle
            })
            .collect::<Message<_>>()
            .await;
        LongMle { components, log_stacking_height: self.log_stacking_height - 1 }
    }

    #[inline]
    pub fn num_variables(&self) -> u32
    where
        F: AbstractField,
        A: MleBaseBackend<F>,
    {
        self.components
            .iter()
            .map(|mle| mle.num_polynomials() << mle.num_variables())
            .sum::<usize>()
            .ilog2()
    }

    #[inline]
    pub fn get_component_mle(&self, index: usize) -> &Mle<F, A> {
        &self.components[index]
    }

    #[inline]
    pub fn first_component_mle(&self) -> &Arc<Mle<F, A>> {
        &self.components[0]
    }

    #[inline]
    pub fn num_components(&self) -> usize {
        self.components.len()
    }

    #[inline]
    pub fn components(&self) -> &Message<Mle<F, A>> {
        &self.components
    }
}

impl<F, A: Backend> HasBackend for LongMle<F, A> {
    type Backend = A;
    #[inline]
    fn backend(&self) -> &Self::Backend {
        self.components[0].backend()
    }
}

impl<F> LongMle<F, CpuBackend> {
    pub fn rand<R: Rng>(
        rng: &mut R,
        num_variables: u32,
        batch_size: usize,
        log_stacking_height: u32,
    ) -> Self
    where
        Standard: Distribution<F>,
    {
        let num_polynomials: usize = 1 << (num_variables - log_stacking_height);
        assert!(num_polynomials.is_multiple_of(batch_size));
        assert!(num_polynomials > batch_size);
        let num_components = num_polynomials / batch_size;
        let components = (0..num_components)
            .map(|_| Mle::rand(rng, batch_size, log_stacking_height))
            .collect::<Vec<_>>();
        Self::from_components(components, log_stacking_height)
    }
}

#[cfg(test)]
mod tests {
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::BabyBear;

    use super::*;

    #[tokio::test]
    async fn test_long_mle_evaluation() {
        let num_variables = 16;
        let log_stacking_height = 8;
        let batch_size = 4;

        type EF = BinomialExtensionField<BabyBear, 4>;

        let mut rng = rand::thread_rng();
        let mle = LongMle::<EF>::rand(&mut rng, num_variables, batch_size, log_stacking_height);
        let point = Point::<EF>::rand(&mut rng, num_variables);
        let long_mle_eval = mle.eval_at(&point).await;

        let long_mle_as_one = Mle::from(
            mle.components
                .iter()
                .flat_map(|mle| mle.guts().transpose().into_buffer().into_vec())
                .collect::<Vec<_>>(),
        );
        let long_mle_as_one_eval = long_mle_as_one.eval_at(&point).await[0];
        assert_eq!(long_mle_eval, long_mle_as_one_eval);
    }

    #[tokio::test]
    async fn test_long_mle_fix_last_variable() {
        let num_variables = 16;
        let log_stacking_height = 8;
        let batch_size = 4;

        type EF = BinomialExtensionField<BabyBear, 4>;

        let mut rng = rand::thread_rng();
        let mle = LongMle::<EF>::rand(&mut rng, num_variables, batch_size, log_stacking_height);
        let point = Point::<EF>::rand(&mut rng, num_variables);
        let long_mle_eval = mle.eval_at(&point).await;

        let mut fixed_mle = mle;
        for alpha in point.values().as_slice().iter().rev() {
            fixed_mle = fixed_mle.fix_last_variable(*alpha).await;
        }

        assert_eq!(fixed_mle.num_variables(), 0);
        assert_eq!(fixed_mle.num_components(), 1);

        let fixed_mle_value = fixed_mle.components()[0].guts().as_buffer().as_slice()[0];

        assert_eq!(long_mle_eval, fixed_mle_value);
    }
}
