//! Client-side BCH transaction construction and signing.

use alloy_primitives::U256;
use async_trait::async_trait;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use x402_types::proto::v2::{ExtensionsJson, ResourceInfo, X402Version2};
use x402_types::proto::{OriginalJson, PaymentRequired};
use x402_types::scheme::X402SchemeId;
use x402_types::scheme::client::{
    PaymentCandidate, PaymentCandidateSigner, X402Error, X402SchemeClient,
};
use x402_types::util::Base64Bytes;

use crate::address::{CashAddr, hash160, p2pkh_script};
use crate::provider::{BchChainProvider, BchUtxo};
use crate::transaction::{
    BCH_SIGHASH_ALL_FORKID, BchPolicy, BchTransaction, TxInput, TxOutput, is_p2pkh_script,
    parse_canonical_satoshi_amount, push_data,
};
use crate::v2_bch_exact::V2BchExact;
use crate::v2_bch_exact::types::{ExactBchPayload, PaymentPayload, PaymentRequirements};

/// A signer capable of producing standard BCH ECDSA signatures.
pub trait BchSigner: Clone + Send + Sync + 'static {
    fn public_key(&self) -> Vec<u8>;
    fn sign_digest(&self, digest: [u8; 32]) -> Result<Vec<u8>, String>;
}

/// A local secp256k1 signer for P2PKH BCH payments.
#[derive(Clone)]
pub struct Secp256k1BchSigner {
    secret_key: SecretKey,
}

impl Secp256k1BchSigner {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, String> {
        SecretKey::from_byte_array(bytes)
            .map(|secret_key| Self { secret_key })
            .map_err(|error| error.to_string())
    }

    pub fn address(&self, network: crate::BchChainReference) -> CashAddr {
        CashAddr {
            network,
            hash160: hash160(&self.public_key()),
        }
    }
}

impl BchSigner for Secp256k1BchSigner {
    fn public_key(&self) -> Vec<u8> {
        PublicKey::from_secret_key(&Secp256k1::new(), &self.secret_key)
            .serialize()
            .to_vec()
    }

    fn sign_digest(&self, digest: [u8; 32]) -> Result<Vec<u8>, String> {
        let signature = Secp256k1::new().sign_ecdsa(Message::from_digest(digest), &self.secret_key);
        Ok(signature.serialize_der().to_vec())
    }
}

/// Client for the native BCH v2 exact scheme.
#[derive(Clone)]
pub struct V2BchExactClient<S, P> {
    signer: S,
    provider: P,
    policy: BchPolicy,
}

impl<S, P> V2BchExactClient<S, P> {
    pub fn new(signer: S, provider: P) -> Self {
        Self {
            signer,
            provider,
            policy: BchPolicy::default(),
        }
    }

    pub fn with_policy(mut self, policy: BchPolicy) -> Self {
        self.policy = policy;
        self
    }
}

impl<S, P> X402SchemeId for V2BchExactClient<S, P> {
    fn namespace(&self) -> &str {
        V2BchExact.namespace()
    }

    fn scheme(&self) -> &str {
        V2BchExact.scheme()
    }
}

impl<S, P> X402SchemeClient for V2BchExactClient<S, P>
where
    S: BchSigner,
    P: BchChainProvider + Clone + 'static,
{
    fn accept(&self, payment_required: &PaymentRequired) -> Vec<PaymentCandidate> {
        let payment_required = match payment_required {
            PaymentRequired::V2(payment_required) => payment_required,
            PaymentRequired::V1(_) => return Vec::new(),
        };
        payment_required
            .accepts
            .iter()
            .filter_map(|original| {
                let requirements = PaymentRequirements::try_from(original).ok()?;
                let network =
                    crate::BchChainReference::try_from(requirements.network.clone()).ok()?;
                if requirements.scheme.to_string() != "exact"
                    || requirements.asset != "BCH"
                    || requirements.extra != crate::v2_bch_exact::types::BchExtra::default()
                    || network != self.provider.chain_id().try_into().ok()?
                {
                    return None;
                }
                let amount = parse_canonical_satoshi_amount(&requirements.amount).ok()?;
                Some(PaymentCandidate {
                    chain_id: requirements.network.clone(),
                    asset: requirements.asset.clone(),
                    amount: U256::from_limbs([amount, 0, 0, 0]),
                    scheme: self.scheme().to_string(),
                    x402_version: self.x402_version(),
                    pay_to: requirements.pay_to.clone(),
                    signer: Box::new(BchPayloadSigner {
                        signer: self.signer.clone(),
                        provider: self.provider.clone(),
                        policy: self.policy,
                        resource: payment_required.resource.clone(),
                        extensions: payment_required.extensions.clone(),
                        requirements,
                        requirements_json: original.clone(),
                    }),
                })
            })
            .collect()
    }
}

struct BchPayloadSigner<S, P> {
    signer: S,
    provider: P,
    policy: BchPolicy,
    resource: Option<ResourceInfo>,
    extensions: ExtensionsJson,
    requirements: PaymentRequirements,
    requirements_json: OriginalJson,
}

#[async_trait]
impl<S, P> PaymentCandidateSigner for BchPayloadSigner<S, P>
where
    S: BchSigner,
    P: BchChainProvider + Sync + 'static,
{
    async fn sign_payment(&self) -> Result<String, X402Error> {
        let network = crate::BchChainReference::try_from(self.requirements.network.clone())
            .map_err(|error| X402Error::SigningError(error.to_string()))?;
        let pay_to = CashAddr::decode(&self.requirements.pay_to, network)
            .map_err(|error| X402Error::SigningError(error.to_string()))?;
        let amount = parse_canonical_satoshi_amount(&self.requirements.amount)
            .map_err(|error| X402Error::SigningError(error.to_string()))?;
        let signer_address = CashAddr {
            network,
            hash160: hash160(&self.signer.public_key()),
        };
        let mut utxos = self
            .provider
            .list_utxos(&signer_address)
            .await
            .map_err(|error| X402Error::SigningError(error.to_string()))?;
        utxos.sort_by_key(|utxo| std::cmp::Reverse(utxo.source_output.value));

        let mut selected = Vec::new();
        let mut selected_value = 0u64;
        for utxo in utxos {
            if utxo.source_output.script_pubkey != p2pkh_script(&signer_address.hash160) {
                continue;
            }
            selected_value = selected_value
                .checked_add(utxo.source_output.value)
                .ok_or_else(|| X402Error::SigningError("UTXO value overflow".to_string()))?;
            selected.push(utxo);
            let estimated_size = 10usize
                .saturating_add(selected.len().saturating_mul(180))
                .saturating_add(34 * 2);
            let required = amount
                .checked_add(estimated_size as u64 * self.policy.fee_rate_sat_per_byte)
                .ok_or_else(|| X402Error::SigningError("payment amount overflow".to_string()))?;
            if selected_value >= required {
                break;
            }
        }
        if selected_value < amount {
            return Err(X402Error::SigningError(
                "insufficient BCH UTXOs for payment and fee".to_string(),
            ));
        }

        let transaction = build_and_sign_transaction(
            &selected,
            pay_to.locking_script(),
            amount,
            &self.signer,
            network,
            self.policy,
        )
        .map_err(|error| X402Error::SigningError(error.to_string()))?;
        let payload = PaymentPayload::<OriginalJson> {
            accepted: self.requirements_json.clone(),
            payload: ExactBchPayload {
                transaction: Base64Bytes::encode(transaction.serialize()).to_string(),
            },
            resource: self.resource.clone(),
            x402_version: X402Version2,
            extensions: self.extensions.clone(),
        };
        Ok(Base64Bytes::encode(serde_json::to_vec(&payload)?).to_string())
    }
}

pub fn build_and_sign_transaction<S: BchSigner>(
    selected: &[BchUtxo],
    merchant_script: Vec<u8>,
    merchant_amount: u64,
    signer: &S,
    _network: crate::BchChainReference,
    policy: BchPolicy,
) -> Result<BchTransaction, crate::transaction::TransactionError> {
    if selected.is_empty() || selected.len() > policy.max_inputs {
        return Err(crate::transaction::TransactionError::ExcessiveCount);
    }
    if !is_p2pkh_script(&merchant_script) {
        return Err(crate::transaction::TransactionError::PolicyViolation(
            "BCH exact requires a P2PKH merchant output".to_string(),
        ));
    }
    if merchant_amount < policy.dust_threshold {
        return Err(crate::transaction::TransactionError::PolicyViolation(
            "merchant output is below dust".to_string(),
        ));
    }
    let input_value = selected
        .iter()
        .try_fold(0u64, |total, utxo| {
            total.checked_add(utxo.source_output.value)
        })
        .ok_or(crate::transaction::TransactionError::ArithmeticOverflow)?;
    if input_value < merchant_amount {
        return Err(crate::transaction::TransactionError::PolicyViolation(
            "selected BCH UTXOs do not cover payment".to_string(),
        ));
    }
    let change_script = p2pkh_script(&hash160(&signer.public_key()));
    let mut change = input_value - merchant_amount;

    for _ in 0..32 {
        let include_change = change >= policy.dust_threshold;
        let mut transaction = unsigned_transaction(
            selected,
            merchant_script.clone(),
            merchant_amount,
            if include_change {
                Some((change, change_script.clone()))
            } else {
                None
            },
        );
        sign_transaction(&mut transaction, selected, signer)?;
        let actual_size = transaction.serialize().len() as u64;
        let required_fee = actual_size
            .checked_mul(policy.fee_rate_sat_per_byte)
            .ok_or(crate::transaction::TransactionError::ArithmeticOverflow)?;
        let available = input_value - merchant_amount;
        if !include_change {
            if available < required_fee {
                return Err(crate::transaction::TransactionError::PolicyViolation(
                    "selected BCH UTXOs do not cover fee".to_string(),
                ));
            }
            if transaction.serialize().len() > policy.max_transaction_size {
                return Err(crate::transaction::TransactionError::PolicyViolation(
                    "transaction exceeds maximum size".to_string(),
                ));
            }
            return Ok(transaction);
        }

        let desired_change = available
            .checked_sub(required_fee)
            .ok_or(crate::transaction::TransactionError::ArithmeticOverflow)?;
        if desired_change < policy.dust_threshold {
            change = 0;
            continue;
        }
        if change > desired_change {
            change = desired_change;
            continue;
        }
        if transaction.serialize().len() > policy.max_transaction_size {
            return Err(crate::transaction::TransactionError::PolicyViolation(
                "transaction exceeds maximum size".to_string(),
            ));
        }
        return Ok(transaction);
    }
    Err(crate::transaction::TransactionError::PolicyViolation(
        "fee/change calculation did not converge".to_string(),
    ))
}

fn unsigned_transaction(
    selected: &[BchUtxo],
    merchant_script: Vec<u8>,
    merchant_amount: u64,
    change: Option<(u64, Vec<u8>)>,
) -> BchTransaction {
    let inputs = selected
        .iter()
        .map(|utxo| TxInput {
            outpoint: utxo.outpoint,
            script_sig: Vec::new(),
            sequence: u32::MAX,
        })
        .collect();
    let mut outputs = vec![TxOutput {
        value: merchant_amount,
        script_pubkey: merchant_script,
    }];
    if let Some((value, script_pubkey)) = change {
        outputs.push(TxOutput {
            value,
            script_pubkey,
        });
    }
    BchTransaction {
        version: 2,
        inputs,
        outputs,
        lock_time: 0,
    }
}

fn sign_transaction<S: BchSigner>(
    transaction: &mut BchTransaction,
    selected: &[BchUtxo],
    signer: &S,
) -> Result<(), crate::transaction::TransactionError> {
    let public_key = signer.public_key();
    for (index, utxo) in selected.iter().enumerate() {
        let digest =
            transaction.signing_hash(index, &utxo.source_output, BCH_SIGHASH_ALL_FORKID)?;
        let mut signature = signer
            .sign_digest(digest)
            .map_err(|_| crate::transaction::TransactionError::InvalidSignature)?;
        signature.push(BCH_SIGHASH_ALL_FORKID as u8);
        let mut script_sig = push_data(&signature)?;
        script_sig.extend_from_slice(&push_data(&public_key)?);
        transaction.inputs[index].script_sig = script_sig;
    }
    Ok(())
}
