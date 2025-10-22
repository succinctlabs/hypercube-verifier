//! # Network Prove
//!
//! This module provides a builder for creating a proof request to the network.

use std::time::Duration;

use alloy_primitives::Address;
use anyhow::Result;

use crate::prover::BaseProveRequest;

use crate::{prover::ProveRequest, utils::sp1_dump, NetworkProver, SP1ProofWithPublicValues};

use super::proto::types::FulfillmentStrategy;

use std::{
    future::{Future, IntoFuture},
    pin::Pin,
};

/// A builder for creating a proof request to the network.
pub struct NetworkProveBuilder<'a> {
    pub(crate) base: BaseProveRequest<'a, NetworkProver>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) strategy: FulfillmentStrategy,
    pub(crate) skip_simulation: bool,
    pub(crate) cycle_limit: Option<u64>,
    pub(crate) gas_limit: Option<u64>,
    pub(crate) tee_2fa: bool,
    pub(crate) min_auction_period: u64,
    pub(crate) whitelist: Option<Vec<Address>>,
    pub(crate) auctioneer: Option<Address>,
    pub(crate) executor: Option<Address>,
    pub(crate) verifier: Option<Address>,
    pub(crate) max_price_per_pgu: Option<u64>,
    pub(crate) auction_timeout: Option<Duration>,
}

impl NetworkProveBuilder<'_> {
    /// Set the timeout for the proof's generation.
    ///
    /// # Details
    /// This method sets the timeout for the proof's generation. If the proof is not generated
    /// within the timeout, the [`NetworkProveBuilder::run`] will return an error.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::time::Duration;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).timeout(Duration::from_secs(60)).await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set whether to skip the local execution simulation step.
    ///
    /// # Details
    /// This method sets whether to skip the local execution simulation step. If the simulation
    /// step is skipped, the request will sent to the network without verifying that the execution
    /// succeeds locally (without generating a proof). This feature is recommended for users who
    /// want to optimize the latency of the proof generation on the network.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).skip_simulation(true).await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn skip_simulation(mut self, skip_simulation: bool) -> Self {
        self.skip_simulation = skip_simulation;
        self
    }

    /// Sets the fulfillment strategy for the client.
    ///
    /// # Details
    /// The strategy determines how the client will fulfill requests.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{network::FulfillmentStrategy, Elf, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).strategy(FulfillmentStrategy::Hosted).await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn strategy(mut self, strategy: FulfillmentStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Sets the cycle limit for the proof request.
    ///
    /// # Details
    /// The cycle limit determines the maximum number of cycles that the program should take to
    /// execute. By default, the cycle limit is determined by simulating the program locally.
    /// However, you can manually set it if you know the exact cycle count needed and want to skip
    /// the simulation step locally.
    ///
    /// The cycle limit ensures that a prover on the network will stop generating a proof once the
    /// cycle limit is reached, which prevents denial of service attacks.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client
    ///         .prove(&pk, stdin)
    ///         .cycle_limit(1_000_000) // Set 1M cycle limit.
    ///         .skip_simulation(true) // Skip simulation since the limit is set manually.
    ///         .await
    ///         .unwrap();
    ///     });
    /// ```
    #[must_use]
    pub fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.cycle_limit = Some(cycle_limit);
        self
    }

    /// Sets the gas limit for the proof request.
    ///
    /// # Details
    /// The gas limit determines the maximum amount of gas that the program should consume. By
    /// default, the gas limit is determined by simulating the program locally. However, you can
    /// manually set it if you know the exact gas count needed and want to skip the simulation
    /// step locally.
    ///
    /// The gas limit ensures that a prover on the network will stop generating a proof once the
    /// gas limit is reached, which prevents denial of service attacks.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client
    ///         .prove(&pk, stdin)
    ///         .gas_limit(1_000_000) // Set 1M gas limit.
    ///         .skip_simulation(true) // Skip simulation since the limit is set manually.
    ///         .await
    ///         .unwrap();
    ///     });
    /// ```
    #[must_use]
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    /// Set the TEE proof type to use.
    ///
    /// # Details
    /// This method sets the TEE proof type to use.
    ///
    /// # Example
    /// ```rust,no_run
    /// async fn create_proof() {
    ///     use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    ///
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).tee_2fa().await.unwrap();
    /// }
    /// ```
    #[must_use]
    #[cfg(feature = "tee-2fa")]
    pub fn tee_2fa(mut self) -> Self {
        self.tee_2fa = true;
        self
    }

    /// Set the minimum auction period for the proof request in seconds.
    ///
    /// # Details
    /// This method sets the minimum auction period for the proof request. Only relevant if the
    /// strategy is set to [`FulfillmentStrategy::Auction`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::time::Duration;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let builder = client.prove(&pk, stdin).min_auction_period(60).await;
    /// });
    /// ```
    #[must_use]
    pub fn min_auction_period(mut self, min_auction_period: u64) -> Self {
        self.min_auction_period = min_auction_period;
        self
    }

    /// Set the whitelist for the proof request.
    ///
    /// # Details
    /// Only provers specified in the whitelist will be able to bid and prove on the request. Only
    /// relevant if the strategy is set to [`FulfillmentStrategy::Auction`].
    ///
    /// If whitelist is `None` when requesting a proof, a set of recently reliable provers will be
    /// used.
    ///
    /// # Example
    /// ```rust,no_run
    /// use alloy_primitives::Address;
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::str::FromStr;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let whitelist = vec![Address::from_str("0x123").unwrap(), Address::from_str("0x456").unwrap()];
    ///     let proof = client.prove(&pk, stdin).whitelist(Some(whitelist)).await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn whitelist(mut self, whitelist: Option<Vec<Address>>) -> Self {
        self.whitelist = whitelist;
        self
    }

    /// Run the prover with the built arguments asynchronously.
    ///
    /// # Details
    /// This method will run the prover with the built arguments asynchronously.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).await.unwrap();
    /// });
    /// ```
    pub async fn run_async(mut self) -> Result<SP1ProofWithPublicValues> {
        // Check for deprecated environment variable
        if let Ok(val) = std::env::var("SKIP_SIMULATION") {
            eprintln!(
                "Warning: SKIP_SIMULATION environment variable is deprecated. Please use .skip_simulation() instead."
            );
            self.skip_simulation = matches!(val.to_lowercase().as_str(), "true" | "1");
        }

        sp1_dump(&self.base.pk.elf, &self.base.stdin);

        self.base
            .prover
            .prove_impl(
                self.base.pk,
                self.base.stdin,
                self.base.mode,
                self.strategy,
                self.timeout,
                self.skip_simulation,
                self.cycle_limit,
                self.gas_limit,
                self.tee_2fa,
                self.min_auction_period,
                self.whitelist,
                self.auctioneer,
                self.executor,
                self.verifier,
                self.max_price_per_pgu,
                self.auction_timeout,
            )
            .await
    }
}

impl<'a> ProveRequest<'a, NetworkProver> for NetworkProveBuilder<'a> {
    fn base(&mut self) -> &mut BaseProveRequest<'a, NetworkProver> {
        &mut self.base
    }

    fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.cycle_limit = Some(cycle_limit);
        self
    }
}

impl<'a> IntoFuture for NetworkProveBuilder<'a> {
    type Output = Result<SP1ProofWithPublicValues>;

    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.run_async())
    }
}
