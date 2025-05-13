use std::error::Error;
use std::ops::{Deref, DerefMut};

use crate::{MleEval, Point};
use derive_where::derive_where;
use p3_challenger::FieldChallenger;
use p3_field::{ExtensionField, Field};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use slop_alloc::{Backend, CpuBackend, HasBackend};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive_where(PartialEq, Eq; MleEval<F, A>)]
#[serde(bound(
    serialize = "MleEval<F, A>: Serialize",
    deserialize = "MleEval<F, A>: Deserialize<'de>"
))]
pub struct Evaluations<F, A: Backend = CpuBackend> {
    pub round_evaluations: Vec<MleEval<F, A>>,
}

/// A verifier of a multilinear commitment scheme.
///
/// A verifier for a multilinear commitment scheme (or PCS) is a protocol that enables getting
/// succinct commitments representing multiplinear polynomials and later making query checks for
/// their evaluation.
///
/// The verifier described by this trait supports compiling a multi-stage multilinear polynomial
/// IOP. In each round of the protocol, the prover is allowed to send a commitment of type
/// [MultilinearPcsVerifier::Commitment] which represents a batch of multilinear polynomials. After
/// all the rounds are complete, the verifier can check an evaluation claim for all the polynomials
/// in all rounds, evaluated at same [Point].
pub trait MultilinearPcsVerifier: 'static + Send + Sync + Clone {
    /// The base field.
    ///
    /// This is the field on which the MLEs committed to are defined over.
    type F: Field;
    /// The field of random elements.
    ///
    /// This is an extension field of the base field which is of cryptographically secure size. The
    /// random evaluation points of the protocol are drawn from `EF`.
    type EF: ExtensionField<Self::F>;

    /// The compressed message that represents a batch of multilinear polynomials.
    type Commitment: 'static + Clone + Serialize + DeserializeOwned + Send + Sync;

    /// The proof of a multilinear PCS evaluation.
    type Proof: 'static + Clone + Serialize + DeserializeOwned + Send + Sync;

    /// The challenger type that creates the random challenges via Fiat-Shamir.
    ///
    /// The challenger is observing all the messages sent throughout the protocol and uses this
    /// to create the verifier messages of the IOP.
    type Challenger: FieldChallenger<Self::F>;

    /// The error type of the verifier.
    type VerifierError: Error;

    /// A default challenger for Fiat-Shamir.
    ///
    /// The challenger returned by this method is un-seeded and it's state can be determinstic.
    fn default_challenger(&self) -> Self::Challenger;

    /// Verify an evaluation proofs for multilinear polynomials sent.
    ///
    /// All inputs are assumed to "trusted" in the sense of Fiat-Shamir. Namely, it is assumed that
    /// the inputs have already been absorbed into the Fiat-Shamir randomness represented by the
    /// challenger.
    ///
    /// ### Arguments
    ///
    /// * `commitments` - The commitments to the multilinear polynomials sent by the prover. A
    ///   commitment is sent for each round of the protocol.
    /// * `point` - The evaluation point at which the multilinear polynomials are evaluated.
    /// * `evaluation_claims` - The evaluation claims for the multilinear polynomials. the slice
    ///   contains one [MleEval] for each round of the protocol.
    /// * `proof` - The proof of the evaluation claims.
    /// * `challenger` - The challenger that creates the verifier messages of the IOP.
    fn verify_trusted_evaluations(
        &self,
        commitments: &[Self::Commitment],
        point: Point<Self::EF>,
        evaluation_claims: &[Evaluations<Self::EF>],
        proof: &Self::Proof,
        challenger: &mut Self::Challenger,
    ) -> Result<(), Self::VerifierError>;

    /// Verify an evaluation proof for a multilinear polynomial.
    ///
    /// This is a variant of [MultilinearPcsVerifier::verify_trusted_evaluations] that allows the
    /// evaluations to be "untrusted" in the sense of Fiat-Shamir. Namely, the verifier will first
    /// absorb the evaluation claims into the Fiat-Shamir randomness represented by the challenger.
    fn verify_untrusted_evaluations(
        &self,
        commitments: &[Self::Commitment],
        point: Point<Self::EF>,
        evaluation_claims: &[Evaluations<Self::EF>],
        proof: &Self::Proof,
        challenger: &mut Self::Challenger,
    ) -> Result<(), Self::VerifierError> {
        // Observe the evaluation claims.
        for round in evaluation_claims.iter() {
            for round_evaluations in round.iter() {
                for evaluations in round_evaluations.iter() {
                    for evaluation in evaluations.iter() {
                        challenger.observe_ext_element(*evaluation);
                    }
                }
            }
        }

        self.verify_trusted_evaluations(commitments, point, evaluation_claims, proof, challenger)
    }
}

impl<F, A: Backend> IntoIterator for Evaluations<F, A> {
    type Item = MleEval<F, A>;
    type IntoIter = <Vec<MleEval<F, A>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.round_evaluations.into_iter()
    }
}

impl<'a, F, A: Backend> IntoIterator for &'a Evaluations<F, A> {
    type Item = &'a MleEval<F, A>;
    type IntoIter = std::slice::Iter<'a, MleEval<F, A>>;

    fn into_iter(self) -> Self::IntoIter {
        self.round_evaluations.iter()
    }
}

impl<F, A: Backend> Evaluations<F, A> {
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<MleEval<F, A>> {
        self.round_evaluations.iter()
    }

    #[inline]
    pub const fn new(round_evaluations: Vec<MleEval<F, A>>) -> Self {
        Self { round_evaluations }
    }
}

impl<F, A: Backend> FromIterator<MleEval<F, A>> for Evaluations<F, A> {
    fn from_iter<T: IntoIterator<Item = MleEval<F, A>>>(iter: T) -> Self {
        Self { round_evaluations: iter.into_iter().collect() }
    }
}

impl<F, A: Backend> Extend<MleEval<F, A>> for Evaluations<F, A> {
    fn extend<T: IntoIterator<Item = MleEval<F, A>>>(&mut self, iter: T) {
        self.round_evaluations.extend(iter);
    }
}

impl<F, A> HasBackend for Evaluations<F, A>
where
    A: Backend,
{
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        assert!(!self.round_evaluations.is_empty(), "Evaluations must not be empty");
        self.round_evaluations.first().unwrap().backend()
    }
}

impl<F, A: Backend> Default for Evaluations<F, A> {
    fn default() -> Self {
        Self { round_evaluations: Vec::new() }
    }
}

impl<F, A: Backend> Deref for Evaluations<F, A> {
    type Target = Vec<MleEval<F, A>>;

    fn deref(&self) -> &Self::Target {
        &self.round_evaluations
    }
}

impl<F, A: Backend> DerefMut for Evaluations<F, A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.round_evaluations
    }
}

pub trait MultilinearPcsChallenger<F: Field>: FieldChallenger<F> {
    fn sample_point<EF: ExtensionField<F>>(&mut self, num_variables: u32) -> Point<EF> {
        (0..num_variables).map(|_| self.sample_ext_element::<EF>()).collect()
    }
}

impl<F: Field, C> MultilinearPcsChallenger<F> for C where C: FieldChallenger<F> {}
