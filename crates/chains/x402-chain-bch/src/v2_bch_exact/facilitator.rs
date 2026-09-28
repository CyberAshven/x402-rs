//! Facilitator-side BCH exact verification and settlement.

use base64::Engine;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use x402_types::proto;
use x402_types::proto::v2;
use x402_types::scheme::{
    X402SchemeFacilitator, X402SchemeFacilitatorBuilder, X402SchemeFacilitatorError,
};

use crate::address::CashAddr;
use crate::provider::{
    BchChainProvider, BchOutpointStatus, BchProviderError, BchTransactionStatus,
};
use crate::settlement::{BchSettlementClaim, BchSettlementStore, InMemoryBchSettlementStore};
use crate::transaction::{
    BchPolicy, BchTransaction, VerifiedPayment, parse_canonical_satoshi_amount, verify_payment,
};
use crate::v2_bch_exact::V2BchExact;
use crate::v2_bch_exact::types::{BchExtra, ExactScheme, SettleRequest, VerifyRequest};

/// Settlement acceptance policy for unconfirmed BCH transactions.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "confirmations", rename_all = "camelCase")]
pub enum BchConfirmationStrategy {
    /// Accept a transaction once the provider reports it in the mempool.
    Mempool,
    /// Accept mempool transactions only while no BCH double-spend proof exists.
    NoDoubleSpendProof,
    /// Require the transaction to be mined with this many confirmations.
    Confirmations(u64),
}

impl Default for BchConfirmationStrategy {
    fn default() -> Self {
        Self::Confirmations(1)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BchFacilitatorConfig {
    pub settlement_strategy: BchConfirmationStrategy,
}

impl Default for BchFacilitatorConfig {
    fn default() -> Self {
        Self {
            settlement_strategy: BchConfirmationStrategy::default(),
        }
    }
}

pub struct V2BchExactFacilitator<P> {
    provider: P,
    policy: BchPolicy,
    config: BchFacilitatorConfig,
    settlement_store: Arc<dyn BchSettlementStore>,
}

impl<P> V2BchExactFacilitator<P> {
    pub fn new(provider: P, policy: BchPolicy, config: BchFacilitatorConfig) -> Self {
        Self {
            provider,
            policy,
            config,
            settlement_store: Arc::new(InMemoryBchSettlementStore::default()),
        }
    }

    pub fn with_settlement_store<S>(
        provider: P,
        policy: BchPolicy,
        config: BchFacilitatorConfig,
        settlement_store: Arc<S>,
    ) -> Self
    where
        S: BchSettlementStore + 'static,
    {
        Self {
            provider,
            policy,
            config,
            settlement_store,
        }
    }
}

impl<P> X402SchemeFacilitatorBuilder<P> for V2BchExact
where
    P: BchChainProvider + 'static,
{
    fn build(
        &self,
        provider: P,
        config: Option<serde_json::Value>,
    ) -> Result<Box<dyn X402SchemeFacilitator>, Box<dyn std::error::Error>> {
        let config = config
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();
        Ok(Box::new(V2BchExactFacilitator::new(
            provider,
            BchPolicy::default(),
            config,
        )))
    }
}

#[async_trait::async_trait]
impl<P> X402SchemeFacilitator for V2BchExactFacilitator<P>
where
    P: BchChainProvider + Send + Sync,
{
    async fn verify(
        &self,
        request: &proto::VerifyRequest,
    ) -> Result<proto::VerifyResponse, X402SchemeFacilitatorError> {
        let request = VerifyRequest::try_from(request)?;
        let verified = verify_transfer(&self.provider, &request, self.policy).await?;
        Ok(v2::VerifyResponse::valid(verified.payment.payer.to_string()).into())
    }

    async fn settle(
        &self,
        request: &proto::SettleRequest,
    ) -> Result<proto::SettleResponse, X402SchemeFacilitatorError> {
        let request = SettleRequest::try_from(request)?;
        let raw_transaction = base64::engine::general_purpose::STANDARD
            .decode(&request.payment_payload.payload.transaction)
            .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?;
        let candidate_transaction = BchTransaction::parse(&raw_transaction)
            .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?;
        let expected_txid = candidate_transaction.txid();
        let binding = serde_json::to_string(&(
            &request.payment_requirements,
            &request.payment_payload.resource,
        ))
        .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?;
        match self
            .settlement_store
            .claim(&expected_txid.to_string(), &binding)
            .await
        {
            BchSettlementClaim::Conflict => {
                return Err(X402SchemeFacilitatorError::OnchainFailure(
                    "transaction already claimed for another request".to_string(),
                ));
            }
            BchSettlementClaim::Same => {
                let status = self
                    .provider
                    .transaction_status(&expected_txid)
                    .await
                    .map_err(|error| {
                        X402SchemeFacilitatorError::OnchainFailure(error.to_string())
                    })?;
                if !self.settlement_accepted(&expected_txid, status).await? {
                    return Ok(v2::SettleResponse::Error {
                        reason: format!("settlement_pending:{}", expected_txid),
                        network: self.provider.chain_id().to_string(),
                    }
                    .into());
                }
                self.settlement_store
                    .mark_accepted(&expected_txid.to_string())
                    .await;
                let verified =
                    verify_transfer_with_spent(&self.provider, &request, self.policy, false)
                        .await?;
                return Ok(v2::SettleResponse::Success {
                    payer: verified.payment.payer.to_string(),
                    transaction: expected_txid.to_string(),
                    network: self.provider.chain_id().to_string(),
                }
                .into());
            }
            BchSettlementClaim::Acquired => {}
        }
        let verified = match verify_transfer(&self.provider, &request, self.policy).await {
            Ok(verified) => verified,
            Err(error) => {
                self.settlement_store
                    .release(&expected_txid.to_string())
                    .await;
                return Err(error.into());
            }
        };
        let raw_transaction = verified.transaction.serialize();
        let txid = match self.provider.broadcast(&raw_transaction).await {
            Ok(txid) => txid,
            Err(error) => match self.provider.transaction_status(&expected_txid).await {
                Ok(BchTransactionStatus::Mempool | BchTransactionStatus::Confirmed { .. }) => {
                    expected_txid
                }
                _ => {
                    self.settlement_store
                        .release(&expected_txid.to_string())
                        .await;
                    return Err(X402SchemeFacilitatorError::OnchainFailure(
                        error.to_string(),
                    ));
                }
            },
        };
        if txid != expected_txid {
            self.settlement_store
                .release(&expected_txid.to_string())
                .await;
            return Err(X402SchemeFacilitatorError::OnchainFailure(
                "provider returned a transaction ID different from the signed transaction"
                    .to_string(),
            ));
        }

        let status = self
            .provider
            .transaction_status(&txid)
            .await
            .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?;
        if self.settlement_accepted(&txid, status).await? {
            self.settlement_store.mark_accepted(&txid.to_string()).await;
            return Ok(v2::SettleResponse::Success {
                payer: verified.payment.payer.to_string(),
                transaction: txid.to_string(),
                network: self.provider.chain_id().to_string(),
            }
            .into());
        }
        Ok(v2::SettleResponse::Error {
            reason: format!("settlement_pending:{}", txid),
            network: self.provider.chain_id().to_string(),
        }
        .into())
    }

    async fn supported(&self) -> Result<proto::SupportedResponse, X402SchemeFacilitatorError> {
        let chain_id = self.provider.chain_id();
        let mut signers = HashMap::new();
        signers.insert(chain_id.clone(), self.provider.signer_addresses());
        Ok(proto::SupportedResponse {
            kinds: vec![proto::SupportedPaymentKind {
                x402_version: v2::X402Version2.into(),
                scheme: ExactScheme.to_string(),
                network: chain_id.to_string(),
                extra: Some(serde_json::to_value(BchExtra::default()).map_err(|error| {
                    X402SchemeFacilitatorError::OnchainFailure(error.to_string())
                })?),
            }],
            extensions: Vec::new(),
            signers,
        })
    }
}

impl<P> V2BchExactFacilitator<P>
where
    P: BchChainProvider + Send + Sync,
{
    async fn settlement_accepted(
        &self,
        txid: &crate::transaction::TxId,
        status: BchTransactionStatus,
    ) -> Result<bool, X402SchemeFacilitatorError> {
        match self.config.settlement_strategy {
            BchConfirmationStrategy::Mempool => Ok(matches!(
                status,
                BchTransactionStatus::Mempool | BchTransactionStatus::Confirmed { .. }
            )),
            BchConfirmationStrategy::NoDoubleSpendProof => match status {
                BchTransactionStatus::Confirmed { .. } => Ok(true),
                BchTransactionStatus::Mempool => Ok(!self
                    .provider
                    .has_double_spend_proof(txid)
                    .await
                    .map_err(|error| {
                        X402SchemeFacilitatorError::OnchainFailure(error.to_string())
                    })?),
                _ => Ok(false),
            },
            BchConfirmationStrategy::Confirmations(required) => match status {
                BchTransactionStatus::Confirmed { height } => {
                    let tip = self.provider.tip_height().await.map_err(|error| {
                        X402SchemeFacilitatorError::OnchainFailure(error.to_string())
                    })?;
                    let confirmations = tip.saturating_sub(height).saturating_add(1);
                    Ok(confirmations >= required)
                }
                _ => Ok(false),
            },
        }
    }
}

pub struct VerifiedBchPayment {
    pub transaction: BchTransaction,
    pub payment: VerifiedPayment,
}

pub async fn verify_transfer<P>(
    provider: &P,
    request: &VerifyRequest,
    policy: BchPolicy,
) -> Result<VerifiedBchPayment, proto::PaymentVerificationError>
where
    P: BchChainProvider + Send + Sync,
{
    verify_transfer_with_spent(provider, request, policy, true).await
}

async fn verify_transfer_with_spent<P>(
    provider: &P,
    request: &VerifyRequest,
    policy: BchPolicy,
    require_unspent: bool,
) -> Result<VerifiedBchPayment, proto::PaymentVerificationError>
where
    P: BchChainProvider + Send + Sync,
{
    let payload = &request.payment_payload;
    let requirements = &request.payment_requirements;
    if &payload.accepted != requirements {
        return Err(proto::PaymentVerificationError::AcceptedRequirementsMismatch);
    }
    if requirements.scheme.to_string() != "exact" {
        return Err(proto::PaymentVerificationError::UnsupportedScheme);
    }
    if requirements.network != provider.chain_id() {
        return Err(proto::PaymentVerificationError::UnsupportedChain);
    }
    if requirements.asset != "BCH" {
        return Err(proto::PaymentVerificationError::AssetMismatch);
    }
    if requirements.extra != BchExtra::default() {
        return Err(proto::PaymentVerificationError::InvalidFormat(
            "BCH exact requires native upfront payment flow".to_string(),
        ));
    }
    let network = crate::BchChainReference::try_from(requirements.network.clone())
        .map_err(|_| proto::PaymentVerificationError::UnsupportedChain)?;
    let pay_to = CashAddr::decode(&requirements.pay_to, network)
        .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?;
    let amount = parse_canonical_satoshi_amount(&requirements.amount)
        .map_err(|_| proto::PaymentVerificationError::InvalidPaymentAmount)?;
    let raw_transaction = base64::engine::general_purpose::STANDARD
        .decode(&payload.payload.transaction)
        .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?;
    let transaction = BchTransaction::parse(&raw_transaction)
        .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?;
    let mut source_outputs = Vec::with_capacity(transaction.inputs.len());
    for input in &transaction.inputs {
        let source_output = provider
            .source_output(&input.outpoint)
            .await
            .map_err(provider_error)?;
        if require_unspent
            && provider
                .outpoint_status(&input.outpoint, &source_output)
                .await
                .map_err(provider_error)?
                != BchOutpointStatus::Unspent
        {
            return Err(proto::PaymentVerificationError::TransactionSimulation(
                "source output is not unspent".to_string(),
            ));
        }
        source_outputs.push(source_output);
    }
    let payment = verify_payment(
        &transaction,
        &source_outputs,
        network,
        &pay_to.locking_script(),
        amount,
        policy,
    )
    .map_err(|error| proto::PaymentVerificationError::TransactionSimulation(error.to_string()))?;
    Ok(VerifiedBchPayment {
        transaction,
        payment,
    })
}

fn provider_error(error: BchProviderError) -> proto::PaymentVerificationError {
    match error {
        BchProviderError::NotFound => proto::PaymentVerificationError::InsufficientFunds,
        other => proto::PaymentVerificationError::TransactionSimulation(other.to_string()),
    }
}
