//! Shipped-path regressions for BCH exact construction, validation, and settlement.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;
use x402_types::chain::{ChainId, ChainProviderOps};
use x402_types::proto::v2::{ExtensionsJson, ResourceInfo, X402Version2};
use x402_types::proto::{OriginalJson, PaymentRequired};
use x402_types::scheme::X402SchemeFacilitator;
use x402_types::scheme::client::{X402Error, X402SchemeClient};
use x402_types::util::Base64Bytes;

use crate::BchChainReference;
use crate::address::{CashAddr, hash160, p2pkh_script, p2sh20_script, p2sh32_script};
use crate::provider::{
    BchChainProvider, BchOutpointStatus, BchProviderError, BchTransactionStatus, BchUtxo,
};
use crate::transaction::{
    BchNft, BchPaymentTarget, BchPolicy, BchToken, BchTokenCapability, BchTransaction, OutPoint,
    SourceOutput, TxId, TxInput, TxOutput, is_p2sh20_script, is_p2sh32_script, payment_target,
    payment_target_with_nft, push_data, verify_payment,
};
use crate::v2_bch_exact::client::{
    BchSigner, BchWallet, Secp256k1BchSigner, V2BchExactClient, V2BchExactWalletClient,
    build_and_sign_transaction,
};
use crate::v2_bch_exact::facilitator::{
    BchConfirmationStrategy, BchFacilitatorConfig, V2BchExactFacilitator,
};
use crate::v2_bch_exact::types::{
    BchExtra, BchNftRequest, BchTokenRequest, BchTransactionNetwork, BchTransactionRequest,
    ExactBchPayload, ExactScheme, PaymentPayload, PaymentRequirements, VerifyRequest,
};

const MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const RESOURCE: &str = "https://merchant.example/item";
const NATIVE_PAY_TO: &str = "bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue";
const P2SH32_PAY_TO: &str =
    "bitcoincash:pv3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zy9u6qkr5a";
const TOKEN_P2SH32_PAY_TO: &str =
    "bitcoincash:rv3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyh0xp0zdk";
const CATEGORY: [u8; 32] = [0x11; 32];

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

fn signer() -> Secp256k1BchSigner {
    Secp256k1BchSigner::from_mnemonic(MNEMONIC, None).unwrap()
}

fn payer_script() -> Vec<u8> {
    p2pkh_script(&hash160(&signer().public_key()))
}

fn category_hex() -> String {
    hex::encode(CATEGORY)
}

fn utxo(marker: u8, value: u64, token: Option<BchToken>) -> BchUtxo {
    BchUtxo {
        outpoint: OutPoint {
            txid: TxId([marker; 32]),
            vout: 0,
        },
        source_output: SourceOutput {
            value,
            script_pubkey: payer_script(),
            token,
        },
        height: Some(10),
    }
}

fn fungible(amount: u64) -> BchToken {
    BchToken {
        category: CATEGORY,
        amount,
        nft: None,
    }
}

fn nft_token(amount: u64, capability: BchTokenCapability, commitment: &[u8]) -> BchToken {
    BchToken {
        category: CATEGORY,
        amount,
        nft: Some(BchNft {
            capability,
            commitment: commitment.to_vec(),
        }),
    }
}

struct FakeState {
    network: BchChainReference,
    utxos: Vec<BchUtxo>,
    status: Mutex<BchTransactionStatus>,
    status_error: Mutex<Option<String>>,
    tip: Mutex<u64>,
    outpoints: Mutex<BchOutpointStatus>,
    dsp: Mutex<bool>,
    broadcast_error: Mutex<Option<String>>,
    broadcasts: AtomicUsize,
}

#[derive(Clone)]
struct FakeProvider {
    state: Arc<FakeState>,
}

impl FakeProvider {
    fn new(utxos: Vec<BchUtxo>) -> Self {
        Self::with_network(BchChainReference::Mainnet, utxos)
    }

    fn with_network(network: BchChainReference, utxos: Vec<BchUtxo>) -> Self {
        Self {
            state: Arc::new(FakeState {
                network,
                utxos,
                status: Mutex::new(BchTransactionStatus::Mempool),
                status_error: Mutex::new(None),
                tip: Mutex::new(100),
                outpoints: Mutex::new(BchOutpointStatus::Unspent),
                dsp: Mutex::new(false),
                broadcast_error: Mutex::new(None),
                broadcasts: AtomicUsize::new(0),
            }),
        }
    }

    fn set_status(&self, status: BchTransactionStatus) {
        *self.state.status.lock().unwrap() = status;
    }

    fn set_status_error(&self, message: &str) {
        *self.state.status_error.lock().unwrap() = Some(message.to_string());
    }

    fn set_tip(&self, tip: u64) {
        *self.state.tip.lock().unwrap() = tip;
    }

    fn set_outpoints(&self, status: BchOutpointStatus) {
        *self.state.outpoints.lock().unwrap() = status;
    }

    fn set_dsp(&self, present: bool) {
        *self.state.dsp.lock().unwrap() = present;
    }

    fn set_broadcast_error(&self, message: &str) {
        *self.state.broadcast_error.lock().unwrap() = Some(message.to_string());
    }

    fn broadcasts(&self) -> usize {
        self.state.broadcasts.load(Ordering::SeqCst)
    }
}

impl ChainProviderOps for FakeProvider {
    fn signer_addresses(&self) -> Vec<String> {
        Vec::new()
    }

    fn chain_id(&self) -> ChainId {
        ChainId::from(self.state.network)
    }
}

#[async_trait]
impl BchChainProvider for FakeProvider {
    async fn source_output(&self, outpoint: &OutPoint) -> Result<SourceOutput, BchProviderError> {
        self.state
            .utxos
            .iter()
            .find(|utxo| utxo.outpoint == *outpoint)
            .map(|utxo| utxo.source_output.clone())
            .ok_or(BchProviderError::NotFound)
    }

    async fn outpoint_status(
        &self,
        _outpoint: &OutPoint,
        _source_output: &SourceOutput,
    ) -> Result<BchOutpointStatus, BchProviderError> {
        Ok(*self.state.outpoints.lock().unwrap())
    }

    async fn list_utxos(&self, _address: &CashAddr) -> Result<Vec<BchUtxo>, BchProviderError> {
        Ok(self.state.utxos.clone())
    }

    async fn broadcast(&self, transaction: &[u8]) -> Result<TxId, BchProviderError> {
        self.state.broadcasts.fetch_add(1, Ordering::SeqCst);
        let parsed = BchTransaction::parse(transaction)?;
        if let Some(message) = self.state.broadcast_error.lock().unwrap().clone() {
            return Err(BchProviderError::Transport(message));
        }
        Ok(parsed.txid())
    }

    async fn transaction_status(
        &self,
        _txid: &TxId,
    ) -> Result<BchTransactionStatus, BchProviderError> {
        if let Some(message) = self.state.status_error.lock().unwrap().clone() {
            return Err(BchProviderError::Transport(message));
        }
        Ok(self.state.status.lock().unwrap().clone())
    }

    async fn tip_height(&self) -> Result<u64, BchProviderError> {
        Ok(*self.state.tip.lock().unwrap())
    }

    async fn has_double_spend_proof(&self, _txid: &TxId) -> Result<bool, BchProviderError> {
        Ok(*self.state.dsp.lock().unwrap())
    }
}

fn native_requirements(pay_to: &str, amount: &str) -> PaymentRequirements {
    PaymentRequirements {
        scheme: ExactScheme,
        network: BchChainReference::Mainnet.into(),
        amount: amount.to_string(),
        pay_to: pay_to.to_string(),
        max_timeout_seconds: 300,
        asset: "BCH".to_string(),
        extra: BchExtra::default(),
    }
}

fn token_requirements(
    pay_to: &str,
    amount: &str,
    nft: Option<BchNftRequest>,
) -> PaymentRequirements {
    PaymentRequirements {
        scheme: ExactScheme,
        network: BchChainReference::Mainnet.into(),
        amount: amount.to_string(),
        pay_to: pay_to.to_string(),
        max_timeout_seconds: 300,
        asset: category_hex(),
        extra: BchExtra {
            asset_transfer_method: "cashtoken".to_string(),
            payment_flow: "upfront".to_string(),
            token_output_value: Some("1000".to_string()),
            token: nft.map(|nft| BchTokenRequest {
                category: category_hex(),
                amount: amount.to_string(),
                nft: Some(nft),
            }),
        },
    }
}

fn required(requirements: &PaymentRequirements) -> PaymentRequired {
    let raw = serde_json::value::to_raw_value(requirements).unwrap();
    PaymentRequired::V2(x402_types::proto::v2::PaymentRequired {
        x402_version: X402Version2,
        error: None,
        resource: Some(ResourceInfo {
            url: RESOURCE.to_string(),
            description: None,
            mime_type: None,
        }),
        accepts: vec![OriginalJson(raw)],
        extensions: ExtensionsJson::try_from(json!({"memo": {"ok": true}})).unwrap(),
    })
}

fn decode_payload(encoded: &str) -> PaymentPayload {
    let bytes = Base64Bytes::from(encoded.as_bytes()).decode().unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn decode_tx(payload: &PaymentPayload) -> BchTransaction {
    let raw = Base64Bytes::from(payload.payload.transaction.as_bytes())
        .decode()
        .unwrap();
    BchTransaction::parse(&raw).unwrap()
}

fn sign_with(
    provider: FakeProvider,
    requirements: &PaymentRequirements,
) -> Result<PaymentPayload, X402Error> {
    let client = V2BchExactClient::new(signer(), provider);
    let candidates = client.accept(&required(requirements));
    assert_eq!(candidates.len(), 1, "BCH candidate was not offered");
    Ok(decode_payload(&block_on(candidates[0].sign())?))
}

fn facilitator(
    provider: FakeProvider,
    strategy: BchConfirmationStrategy,
) -> V2BchExactFacilitator<FakeProvider> {
    V2BchExactFacilitator::new(
        provider,
        BchPolicy::default(),
        BchFacilitatorConfig {
            settlement_strategy: strategy,
        },
    )
}

fn proto_request(
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> x402_types::proto::VerifyRequest {
    let request = VerifyRequest {
        x402_version: X402Version2,
        payment_payload: payload.clone(),
        payment_requirements: requirements.clone(),
    };
    x402_types::proto::VerifyRequest::try_from(&request).unwrap()
}

fn extension_flag(payload: &PaymentPayload) -> bool {
    serde_json::Value::from(payload.extensions.clone())["memo"]["ok"]
        .as_bool()
        .unwrap_or(false)
}

fn sign_inputs(transaction: &mut BchTransaction, sources: &[SourceOutput]) {
    let signer = signer();
    for (index, source) in sources.iter().enumerate() {
        let digest = transaction
            .signing_hash(index, source, crate::transaction::BCH_SIGHASH_ALL_FORKID)
            .unwrap();
        let mut signature = signer.sign_digest(digest).unwrap();
        signature.push(crate::transaction::BCH_SIGHASH_ALL_FORKID as u8);
        let mut script_sig = push_data(&signature).unwrap();
        script_sig.extend_from_slice(&push_data(&signer.public_key()).unwrap());
        transaction.inputs[index].script_sig = script_sig;
    }
}

#[derive(Clone)]
struct RecordingWallet {
    utxos: Vec<BchUtxo>,
    captured: Arc<Mutex<Option<BchTransactionRequest>>>,
}

#[async_trait]
impl BchWallet for RecordingWallet {
    async fn create_payment(&self, request: BchTransactionRequest) -> Result<Vec<u8>, String> {
        *self.captured.lock().unwrap() = Some(request.clone());
        let network = match request.network {
            BchTransactionNetwork::Mainnet => BchChainReference::Mainnet,
            BchTransactionNetwork::Chipnet => BchChainReference::Chipnet,
        };
        let merchant = CashAddr::decode_script(&request.recipient, network)
            .map_err(|error| error.to_string())?;
        let target = if let Some(token) = &request.token {
            let nft = crate::transaction::parse_cash_token_nft(
                token.nft.as_ref().map(|nft| nft.capability.as_str()),
                token.nft.as_ref().map(|nft| nft.commitment.as_str()),
            )
            .map_err(|error| error.to_string())?;
            payment_target_with_nft(
                &token.category,
                &token.amount,
                "cashtoken",
                Some("1000"),
                nft,
                BchPolicy::default(),
            )
            .map_err(|error| error.to_string())?
        } else {
            payment_target("BCH", &request.amount, "native", None, BchPolicy::default())
                .map_err(|error| error.to_string())?
        };
        let transaction = build_and_sign_transaction(
            &self.utxos,
            merchant.locking_script(),
            target,
            &signer(),
            network,
            BchPolicy::default(),
        )
        .map_err(|error| error.to_string())?;
        Ok(transaction.serialize())
    }
}

fn wallet_outcome(
    provider: FakeProvider,
    utxos: Vec<BchUtxo>,
    requirements: &PaymentRequirements,
) -> (
    Option<BchTransactionRequest>,
    Result<PaymentPayload, X402Error>,
) {
    let captured = Arc::new(Mutex::new(None));
    let wallet = RecordingWallet {
        utxos,
        captured: captured.clone(),
    };
    let client = V2BchExactWalletClient::new(wallet, provider);
    let candidates = client.accept(&required(requirements));
    assert_eq!(candidates.len(), 1, "wallet candidate was not offered");
    let outcome = block_on(candidates[0].sign()).map(|encoded| decode_payload(&encoded));
    (captured.lock().unwrap().clone(), outcome)
}

#[derive(Clone)]
struct FixedSignatureSigner;

impl BchSigner for FixedSignatureSigner {
    fn public_key(&self) -> Vec<u8> {
        signer().public_key()
    }

    fn sign_digest(&self, _digest: [u8; 32]) -> Result<Vec<u8>, String> {
        Ok(vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00])
    }
}

#[test]
fn native_bch_one_input_payment() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).expect("one-input native payment");
    let transaction = decode_tx(&payload);
    let merchant = CashAddr::decode_script(NATIVE_PAY_TO, BchChainReference::Mainnet).unwrap();
    assert_eq!(transaction.inputs.len(), 1);
    assert_eq!(transaction.outputs[0].value, 3_000);
    assert_eq!(
        transaction.outputs[0].script_pubkey,
        merchant.locking_script()
    );
    assert!(extension_flag(&payload));
    assert_eq!(
        payload
            .resource
            .as_ref()
            .map(|resource| resource.url.as_str()),
        Some(RESOURCE)
    );
    block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .verify(&proto_request(&payload, &requirements)),
    )
    .expect("facilitator verifies the one-input payment");
}

#[test]
fn native_no_change_payment_uses_actual_fee_not_conservative_estimate() {
    let selected = vec![utxo(1, 1_250, None)];
    let requirements = native_requirements(NATIVE_PAY_TO, "1000");
    let merchant = CashAddr::decode_script(NATIVE_PAY_TO, BchChainReference::Mainnet).unwrap();
    let target = payment_target("BCH", "1000", "native", None, BchPolicy::default()).unwrap();
    let transaction = build_and_sign_transaction(
        &selected,
        merchant.locking_script(),
        target.clone(),
        &signer(),
        BchChainReference::Mainnet,
        BchPolicy::default(),
    )
    .expect("the selected input can fund a no-change transaction");
    assert_eq!(transaction.outputs.len(), 1);
    assert!(transaction.serialize().len() <= 250);
    verify_payment(
        &transaction,
        &[selected[0].source_output.clone()],
        BchChainReference::Mainnet,
        &merchant.locking_script(),
        &target,
        BchPolicy::default(),
    )
    .unwrap();
    sign_with(FakeProvider::new(selected), &requirements)
        .expect("the client must not reject a payment its builder and validator accept");
}

#[test]
fn native_bch_multi_input_payment() {
    let provider = FakeProvider::new(vec![utxo(1, 2_000, None), utxo(2, 2_000, None)]);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider, &requirements).expect("multi-input native payment");
    assert_eq!(decode_tx(&payload).inputs.len(), 2);
}

#[test]
fn fungible_token_json_omits_nft_and_accepts_typescript_shape() {
    let request = BchTokenRequest {
        category: category_hex(),
        amount: "4".to_string(),
        nft: None,
    };
    let value = serde_json::to_value(&request).unwrap();
    assert!(value.get("nft").is_none());
    let parsed: BchTokenRequest = serde_json::from_value(json!({
        "category": category_hex(),
        "amount": "4"
    }))
    .unwrap();
    assert!(parsed.nft.is_none());
}

#[test]
fn omitted_cashtoken_merchant_value_is_payable() {
    let tag = crate::v2_bch_exact::V2BchExact::cash_token_price_tag(
        TOKEN_P2SH32_PAY_TO,
        category_hex(),
        4,
        None,
        BchChainReference::Mainnet,
    );
    let advertised = tag.requirements.extra.as_ref().unwrap()["tokenOutputValue"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(advertised, "1000");
    let mut requirements = token_requirements(TOKEN_P2SH32_PAY_TO, "4", None);
    requirements.extra.token_output_value = Some(advertised);
    let provider = FakeProvider::new(vec![utxo(1, 100_000, Some(fungible(10)))]);
    let payload =
        sign_with(provider, &requirements).expect("omitted token output value is payable");
    assert_eq!(decode_tx(&payload).outputs[0].value, 1_000);
}

#[test]
fn cashtoken_fungible_payment() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, Some(fungible(10)))]);
    let requirements = token_requirements(TOKEN_P2SH32_PAY_TO, "4", None);
    let payload = sign_with(provider.clone(), &requirements).expect("fungible CashToken payment");
    let transaction = decode_tx(&payload);
    let merchant = transaction.outputs[0].token.as_ref().unwrap();
    assert_eq!(merchant.category, CATEGORY);
    assert_eq!(merchant.amount, 4);
    assert!(merchant.nft.is_none());
    assert_eq!(transaction.outputs[1].token.as_ref().unwrap().amount, 6);
    block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .verify(&proto_request(&payload, &requirements)),
    )
    .unwrap();
}

#[test]
fn cashtoken_payment_uses_ordinary_bch_fee_input() {
    let provider = FakeProvider::new(vec![
        utxo(1, 1_000, Some(fungible(5))),
        utxo(2, 50_000, None),
    ]);
    let requirements = token_requirements(TOKEN_P2SH32_PAY_TO, "2", None);
    let payload =
        sign_with(provider, &requirements).expect("CashToken payment funded by an ordinary input");
    let transaction = decode_tx(&payload);
    assert_eq!(transaction.inputs.len(), 2);
    assert_eq!(transaction.outputs[0].token.as_ref().unwrap().amount, 2);
    assert_eq!(transaction.outputs[1].token.as_ref().unwrap().amount, 3);
    assert!(transaction.outputs[1].token.as_ref().unwrap().nft.is_none());
}

#[test]
fn cashtoken_underestimated_fee_spends_another_bch_input() {
    let provider = FakeProvider::new(vec![
        utxo(1, 1_909, Some(fungible(5))),
        utxo(2, 50_000, None),
    ]);
    let requirements = token_requirements(TOKEN_P2SH32_PAY_TO, "2", None);
    let payload = sign_with(provider, &requirements)
        .expect("tight CashToken UTXO spends the ordinary BCH input");
    let transaction = decode_tx(&payload);
    assert_eq!(transaction.inputs.len(), 2);
    assert_eq!(transaction.inputs[1].outpoint.txid, TxId([2; 32]));
    assert_eq!(transaction.outputs[0].value, 1_000);
    assert_eq!(transaction.outputs[0].token.as_ref().unwrap().amount, 2);
    let change = transaction.outputs[1].token.as_ref().unwrap();
    assert_eq!(change.amount, 3);
    assert!(change.nft.is_none());
    assert!(transaction.outputs[1].value >= 651);
}

#[test]
fn nft_payment_preserves_capability_and_commitment() {
    let nft = BchNftRequest {
        capability: "none".to_string(),
        commitment: "aabb".to_string(),
    };
    let provider = FakeProvider::new(vec![utxo(
        1,
        100_000,
        Some(nft_token(5, BchTokenCapability::None, &[0xaa, 0xbb])),
    )]);
    let requirements = token_requirements(TOKEN_P2SH32_PAY_TO, "2", Some(nft));
    let payload = sign_with(provider.clone(), &requirements).expect("NFT payment");
    let transaction = decode_tx(&payload);
    let merchant = transaction.outputs[0].token.as_ref().unwrap();
    let merchant_nft = merchant
        .nft
        .as_ref()
        .expect("merchant output keeps the NFT");
    assert_eq!(merchant.amount, 2);
    assert_eq!(merchant_nft.capability, BchTokenCapability::None);
    assert_eq!(merchant_nft.commitment, vec![0xaa, 0xbb]);
    let change = transaction.outputs[1].token.as_ref().unwrap();
    assert_eq!(change.amount, 3);
    assert!(change.nft.is_none());
    block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .verify(&proto_request(&payload, &requirements)),
    )
    .expect("facilitator accepts the NFT payment");
}

#[test]
fn nft_only_payment_with_zero_fungible_amount() {
    let nft = BchNftRequest {
        capability: "mutable".to_string(),
        commitment: "cc".to_string(),
    };
    let provider = FakeProvider::new(vec![utxo(
        1,
        100_000,
        Some(nft_token(0, BchTokenCapability::Mutable, &[0xcc])),
    )]);
    let requirements = token_requirements(TOKEN_P2SH32_PAY_TO, "0", Some(nft));
    let payload = sign_with(provider.clone(), &requirements).expect("NFT-only payment");
    let transaction = decode_tx(&payload);
    let merchant = transaction.outputs[0].token.as_ref().unwrap();
    assert_eq!(merchant.amount, 0);
    assert_eq!(
        merchant.nft.as_ref().unwrap().capability,
        BchTokenCapability::Mutable
    );
    assert_eq!(merchant.nft.as_ref().unwrap().commitment, vec![0xcc]);
    block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .verify(&proto_request(&payload, &requirements)),
    )
    .expect("facilitator accepts an NFT with zero fungible amount");
}

#[test]
fn p2sh20_destination_payment() {
    let merchant = p2sh20_script(&[0x11; 20]);
    let selected = vec![utxo(1, 100_000, None)];
    let target = payment_target("BCH", "3000", "native", None, BchPolicy::default()).unwrap();
    let transaction = build_and_sign_transaction(
        &selected,
        merchant.clone(),
        target.clone(),
        &signer(),
        BchChainReference::Mainnet,
        BchPolicy::default(),
    )
    .unwrap();
    assert!(is_p2sh20_script(&transaction.outputs[0].script_pubkey));
    verify_payment(
        &transaction,
        &[selected[0].source_output.clone()],
        BchChainReference::Mainnet,
        &merchant,
        &target,
        BchPolicy::default(),
    )
    .unwrap();
}

#[test]
fn p2sh32_destination_payment() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    let requirements = native_requirements(P2SH32_PAY_TO, "3000");
    let payload = sign_with(provider, &requirements).expect("P2SH32 destination");
    let transaction = decode_tx(&payload);
    assert!(is_p2sh32_script(&transaction.outputs[0].script_pubkey));
    assert_eq!(
        transaction.outputs[0].script_pubkey,
        p2sh32_script(&[0x22; 32])
    );
}

#[test]
fn rejects_wrong_network() {
    let provider = FakeProvider::with_network(BchChainReference::Chipnet, vec![]);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    assert!(
        V2BchExactClient::new(signer(), provider.clone())
            .accept(&required(&requirements))
            .is_empty()
    );
    let payload = PaymentPayload {
        accepted: requirements.clone(),
        payload: ExactBchPayload {
            transaction: "AAAA".to_string(),
        },
        resource: None,
        x402_version: X402Version2,
        extensions: ExtensionsJson::default(),
    };
    let error = block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .verify(&proto_request(&payload, &requirements)),
    )
    .unwrap_err();
    assert!(error.to_string().contains("Unsupported chain"), "{error}");
}

#[test]
fn rejects_wrong_merchant() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    let other = Secp256k1BchSigner::from_mnemonic_with_path(MNEMONIC, None, 145, 0, 0, 1)
        .unwrap()
        .address(BchChainReference::Mainnet)
        .encode();
    let mut mismatched = requirements.clone();
    mismatched.pay_to = other;
    let mut payload = payload;
    payload.accepted = mismatched.clone();
    let error = block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .verify(&proto_request(&payload, &mismatched)),
    )
    .unwrap_err();
    assert!(error.to_string().contains("policy"), "{error}");
}

#[test]
fn rejects_wrong_amount() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let mut payload = sign_with(provider.clone(), &requirements).unwrap();
    let mut mismatched = requirements.clone();
    mismatched.amount = "4000".to_string();
    payload.accepted = mismatched.clone();
    let error = block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .verify(&proto_request(&payload, &mismatched)),
    )
    .unwrap_err();
    assert!(error.to_string().contains("policy"), "{error}");
}

#[test]
fn rejects_token_category_mismatch() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, Some(fungible(10)))]);
    let requirements = token_requirements(TOKEN_P2SH32_PAY_TO, "4", None);
    let mut payload = sign_with(provider.clone(), &requirements).unwrap();
    let mut mismatched = requirements.clone();
    mismatched.asset = hex::encode([0x22; 32]);
    payload.accepted = mismatched.clone();
    let error = block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .verify(&proto_request(&payload, &mismatched)),
    )
    .unwrap_err();
    assert!(error.to_string().contains("policy"), "{error}");
}

#[test]
fn rejects_nft_capability_mismatch() {
    let error = nft_mismatch(BchTokenCapability::Mutable, &[0xaa, 0xbb]);
    assert!(format!("{error:?}").contains("NFT"), "{error:?}");
}

#[test]
fn rejects_nft_commitment_mismatch() {
    let error = nft_mismatch(BchTokenCapability::None, &[0xff]);
    assert!(format!("{error:?}").contains("NFT"), "{error:?}");
}

fn nft_mismatch(
    capability: BchTokenCapability,
    commitment: &[u8],
) -> crate::transaction::TransactionError {
    let source = SourceOutput {
        value: 100_000,
        script_pubkey: payer_script(),
        token: Some(nft_token(2, BchTokenCapability::None, &[0xaa, 0xbb])),
    };
    let merchant = p2sh32_script(&[0x22; 32]);
    let mut transaction = BchTransaction {
        version: 2,
        inputs: vec![TxInput {
            outpoint: OutPoint {
                txid: TxId([4; 32]),
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![
            TxOutput {
                value: 2_000,
                script_pubkey: merchant.clone(),
                token: Some(nft_token(2, BchTokenCapability::None, &[0xaa, 0xbb])),
            },
            TxOutput {
                value: 90_000,
                script_pubkey: payer_script(),
                token: None,
            },
        ],
        lock_time: 0,
    };
    sign_inputs(&mut transaction, std::slice::from_ref(&source));
    let target = payment_target_with_nft(
        &category_hex(),
        "2",
        "cashtoken",
        Some("2000"),
        Some(BchNft {
            capability,
            commitment: commitment.to_vec(),
        }),
        BchPolicy::default(),
    )
    .unwrap();
    verify_payment(
        &transaction,
        &[source],
        BchChainReference::Mainnet,
        &merchant,
        &target,
        BchPolicy::default(),
    )
    .unwrap_err()
}

#[test]
fn rejects_token_conservation_failure() {
    let source = SourceOutput {
        value: 100_000,
        script_pubkey: payer_script(),
        token: Some(fungible(5)),
    };
    let merchant = p2sh32_script(&[0x22; 32]);
    let mut transaction = BchTransaction {
        version: 2,
        inputs: vec![TxInput {
            outpoint: OutPoint {
                txid: TxId([5; 32]),
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![
            TxOutput {
                value: 2_000,
                script_pubkey: merchant.clone(),
                token: Some(fungible(2)),
            },
            TxOutput {
                value: 2_000,
                script_pubkey: payer_script(),
                token: Some(fungible(2)),
            },
        ],
        lock_time: 0,
    };
    sign_inputs(&mut transaction, std::slice::from_ref(&source));
    let target = payment_target_with_nft(
        &category_hex(),
        "2",
        "cashtoken",
        Some("2000"),
        None,
        BchPolicy::default(),
    )
    .unwrap();
    let error = verify_payment(
        &transaction,
        &[source],
        BchChainReference::Mainnet,
        &merchant,
        &target,
        BchPolicy::default(),
    )
    .unwrap_err();
    assert!(format!("{error:?}").contains("conserved"), "{error:?}");
}

#[test]
fn rejects_invalid_signature() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    let mut transaction = decode_tx(&payload);
    transaction.inputs[0].script_sig[2] ^= 0x01;
    let mut payload = payload;
    payload.payload.transaction = Base64Bytes::encode(transaction.serialize()).to_string();
    let error = block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .verify(&proto_request(&payload, &requirements)),
    )
    .unwrap_err();
    assert!(
        error.to_string().to_ascii_lowercase().contains("signature"),
        "{error}"
    );
}

#[test]
fn signer_rejects_invalid_signature_before_return() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    let client = V2BchExactClient::new(FixedSignatureSigner, provider);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let candidates = client.accept(&required(&requirements));
    let error = block_on(candidates[0].sign()).expect_err("invalid signature must not be returned");
    assert!(
        error.to_string().to_ascii_lowercase().contains("signature"),
        "{error}"
    );
}

#[test]
fn rejects_cashtoken_output_below_standard_dust() {
    let source = SourceOutput {
        value: 100_000,
        script_pubkey: payer_script(),
        token: Some(fungible(4)),
    };
    let merchant = p2sh32_script(&[0x22; 32]);
    let mut transaction = BchTransaction {
        version: 2,
        inputs: vec![TxInput {
            outpoint: OutPoint {
                txid: TxId([7; 32]),
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![
            TxOutput {
                value: 546,
                script_pubkey: merchant.clone(),
                token: Some(fungible(4)),
            },
            TxOutput {
                value: 90_000,
                script_pubkey: payer_script(),
                token: None,
            },
        ],
        lock_time: 0,
    };
    sign_inputs(&mut transaction, std::slice::from_ref(&source));
    let target = payment_target_with_nft(
        &category_hex(),
        "4",
        "cashtoken",
        Some("546"),
        None,
        BchPolicy::default(),
    )
    .unwrap();
    let error = verify_payment(
        &transaction,
        &[source],
        BchChainReference::Mainnet,
        &merchant,
        &target,
        BchPolicy::default(),
    )
    .unwrap_err();
    assert!(format!("{error:?}").contains("dust"), "{error:?}");
}

#[test]
fn rejects_dust_merchant_output() {
    let selected = vec![utxo(1, 100_000, None)];
    let target = payment_target("BCH", "100", "native", None, BchPolicy::default()).unwrap();
    let error = build_and_sign_transaction(
        &selected,
        p2pkh_script(&[4; 20]),
        target,
        &signer(),
        BchChainReference::Mainnet,
        BchPolicy::default(),
    )
    .unwrap_err();
    assert!(format!("{error:?}").contains("dust"), "{error:?}");
}

#[test]
fn rejects_insufficient_fee() {
    let source = SourceOutput {
        value: 2_000,
        script_pubkey: payer_script(),
        token: None,
    };
    let merchant = p2pkh_script(&[4; 20]);
    let mut transaction = BchTransaction {
        version: 2,
        inputs: vec![TxInput {
            outpoint: OutPoint {
                txid: TxId([6; 32]),
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput {
            value: 2_000,
            script_pubkey: merchant.clone(),
            token: None,
        }],
        lock_time: 0,
    };
    sign_inputs(&mut transaction, std::slice::from_ref(&source));
    let target = payment_target("BCH", "2000", "native", None, BchPolicy::default()).unwrap();
    let error = verify_payment(
        &transaction,
        &[source],
        BchChainReference::Mainnet,
        &merchant,
        &target,
        BchPolicy::default(),
    )
    .unwrap_err();
    assert!(format!("{error:?}").contains("fee"), "{error:?}");
}

#[test]
fn rejects_spent_input() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    provider.set_outpoints(BchOutpointStatus::Spent);
    let error = block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .verify(&proto_request(&payload, &requirements)),
    )
    .unwrap_err();
    assert!(error.to_string().contains("not unspent"), "{error}");
}

#[test]
fn rejects_unknown_outpoint_status() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    provider.set_outpoints(BchOutpointStatus::Unknown);
    let error = block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .verify(&proto_request(&payload, &requirements)),
    )
    .unwrap_err();
    assert!(error.to_string().contains("not unspent"), "{error}");
}

#[test]
fn same_txid_retry_does_not_rebroadcast() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    let facilitator = facilitator(provider.clone(), BchConfirmationStrategy::Mempool);
    let request = proto_request(&payload, &requirements);
    assert_eq!(
        block_on(facilitator.settle(&request)).unwrap().0["success"],
        true
    );
    assert_eq!(
        block_on(facilitator.settle(&request)).unwrap().0["success"],
        true
    );
    assert_eq!(provider.broadcasts(), 1);
}

#[test]
fn cross_resource_replay_conflicts() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    let facilitator = facilitator(provider.clone(), BchConfirmationStrategy::Mempool);
    assert_eq!(
        block_on(facilitator.settle(&proto_request(&payload, &requirements)))
            .unwrap()
            .0["success"],
        true
    );
    let mut replay = payload;
    replay.resource = Some(ResourceInfo {
        url: "https://merchant.example/other".to_string(),
        description: None,
        mime_type: None,
    });
    let error = block_on(facilitator.settle(&proto_request(&replay, &requirements))).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("transaction already claimed for another request"),
        "{error}"
    );
    assert_eq!(provider.broadcasts(), 1);
}

#[test]
fn accepts_mempool_strategy() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    provider.set_status(BchTransactionStatus::Mempool);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    let response = block_on(
        facilitator(provider, BchConfirmationStrategy::Mempool)
            .settle(&proto_request(&payload, &requirements)),
    )
    .unwrap();
    assert_eq!(response.0["success"], true);
}

#[test]
fn double_spend_proof_strategy_rejects_mempool_with_proof() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    provider.set_status(BchTransactionStatus::Mempool);
    provider.set_dsp(true);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    let pending = block_on(
        facilitator(
            provider.clone(),
            BchConfirmationStrategy::NoDoubleSpendProof,
        )
        .settle(&proto_request(&payload, &requirements)),
    )
    .unwrap();
    assert_eq!(pending.0["success"], false);

    let clean = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    clean.set_status(BchTransactionStatus::Mempool);
    let accepted = block_on(
        facilitator(clean, BchConfirmationStrategy::NoDoubleSpendProof)
            .settle(&proto_request(&payload, &requirements)),
    )
    .unwrap();
    assert_eq!(accepted.0["success"], true);
}

#[test]
fn confirmation_strategy_requires_depth() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    provider.set_status(BchTransactionStatus::Confirmed { height: 100 });
    provider.set_tip(100);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    let one = block_on(
        facilitator(provider.clone(), BchConfirmationStrategy::Confirmations(1))
            .settle(&proto_request(&payload, &requirements)),
    )
    .unwrap();
    assert_eq!(one.0["success"], true);

    let shallow = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    shallow.set_status(BchTransactionStatus::Confirmed { height: 100 });
    shallow.set_tip(100);
    let two = block_on(
        facilitator(shallow, BchConfirmationStrategy::Confirmations(2))
            .settle(&proto_request(&payload, &requirements)),
    )
    .unwrap();
    assert_eq!(two.0["success"], false);
}

#[test]
fn inconsistent_tip_above_confirmation_is_not_final() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    provider.set_status(BchTransactionStatus::Confirmed { height: 101 });
    provider.set_tip(100);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    let facilitator = facilitator(provider.clone(), BchConfirmationStrategy::Confirmations(1));
    let request = proto_request(&payload, &requirements);
    let first = block_on(facilitator.settle(&request)).unwrap();
    assert_eq!(
        first.0["success"], false,
        "a confirmation above the reported tip must not settle"
    );
    let _ = block_on(facilitator.settle(&request)).unwrap();
    assert_eq!(provider.broadcasts(), 1);
}

#[test]
fn broadcast_lost_but_transaction_observed_reconciles() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    provider.set_broadcast_error("connection reset");
    provider.set_status(BchTransactionStatus::Mempool);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    let facilitator = facilitator(provider.clone(), BchConfirmationStrategy::Mempool);
    let request = proto_request(&payload, &requirements);
    assert_eq!(
        block_on(facilitator.settle(&request)).unwrap().0["success"],
        true
    );
    assert_eq!(
        block_on(facilitator.settle(&request)).unwrap().0["success"],
        true
    );
    assert_eq!(provider.broadcasts(), 1);
}

#[test]
fn broadcast_lost_and_state_unknown_keeps_claim() {
    assert_unknown_broadcast_keeps_claim(BchTransactionStatus::Unknown, false);
}

#[test]
fn broadcast_lost_and_provider_error_keeps_claim() {
    assert_unknown_broadcast_keeps_claim(BchTransactionStatus::NotFound, true);
}

#[test]
fn broadcast_lost_and_conflicted_keeps_claim() {
    assert_unknown_broadcast_keeps_claim(BchTransactionStatus::Conflicted, false);
}

fn assert_unknown_broadcast_keeps_claim(status: BchTransactionStatus, status_errors: bool) {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    provider.set_broadcast_error("connection reset");
    if status_errors {
        provider.set_status_error("status unavailable");
    } else {
        provider.set_status(status);
    }
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    let facilitator = facilitator(provider.clone(), BchConfirmationStrategy::Mempool);
    let request = proto_request(&payload, &requirements);
    let error = block_on(facilitator.settle(&request)).unwrap_err();
    assert!(
        error.to_string().contains("broadcast outcome unknown"),
        "{error}"
    );
    let _ = block_on(facilitator.settle(&request));
    assert_eq!(
        provider.broadcasts(),
        1,
        "unknown broadcast must not be spent again"
    );
}

#[test]
fn broadcast_lost_and_not_found_releases_claim() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    provider.set_broadcast_error("rejected");
    provider.set_status(BchTransactionStatus::NotFound);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider.clone(), &requirements).unwrap();
    let facilitator = facilitator(provider.clone(), BchConfirmationStrategy::Mempool);
    let request = proto_request(&payload, &requirements);
    let error = block_on(facilitator.settle(&request)).unwrap_err();
    assert!(
        !error.to_string().contains("broadcast outcome unknown"),
        "{error}"
    );
    let _ = block_on(facilitator.settle(&request)).unwrap_err();
    assert_eq!(provider.broadcasts(), 2);
}

#[test]
fn wallet_request_preserves_cashtoken_metadata() {
    let utxos = vec![utxo(1, 100_000, Some(fungible(10)))];
    let provider = FakeProvider::new(utxos.clone());
    let requirements = token_requirements(TOKEN_P2SH32_PAY_TO, "4", None);
    let (request, _) = wallet_outcome(provider, utxos, &requirements);
    let request = request.expect("wallet received a transaction request");
    let token = request
        .token
        .as_ref()
        .expect("wallet request keeps the CashToken encoded in asset");
    assert_eq!(token.category, category_hex());
    assert_eq!(token.amount, "4");
    assert!(token.nft.is_none());
}

#[test]
fn wallet_payload_preserves_resource_and_extensions() {
    let mut requirements = token_requirements(TOKEN_P2SH32_PAY_TO, "4", None);
    requirements.extra.token = Some(BchTokenRequest {
        category: category_hex(),
        amount: "4".to_string(),
        nft: None,
    });
    let utxos = vec![utxo(1, 100_000, Some(fungible(10)))];
    let provider = FakeProvider::new(utxos.clone());
    let (_, outcome) = wallet_outcome(provider, utxos, &requirements);
    let payload = outcome.expect("wallet payment verifies");
    assert_eq!(
        payload
            .resource
            .as_ref()
            .map(|resource| resource.url.as_str()),
        Some(RESOURCE),
        "wallet payload dropped the x402 resource"
    );
    assert!(
        extension_flag(&payload),
        "wallet payload dropped extensions"
    );
}

#[test]
fn wallet_nft_payment_preserves_commitment() {
    let nft = BchNftRequest {
        capability: "minting".to_string(),
        commitment: "abcd".to_string(),
    };
    let requirements = token_requirements(TOKEN_P2SH32_PAY_TO, "4", Some(nft));
    let utxos = vec![utxo(
        1,
        100_000,
        Some(nft_token(10, BchTokenCapability::Minting, &[0xab, 0xcd])),
    )];
    let provider = FakeProvider::new(utxos.clone());
    let (request, outcome) = wallet_outcome(provider, utxos, &requirements);
    let token = request.unwrap().token.expect("nft metadata");
    assert_eq!(token.nft.as_ref().unwrap().capability, "minting");
    assert_eq!(token.nft.as_ref().unwrap().commitment, "abcd");
    let payload = outcome.expect("wallet NFT payment verifies");
    let transaction = decode_tx(&payload);
    let merchant = transaction.outputs[0].token.as_ref().unwrap();
    assert_eq!(
        merchant.nft.as_ref().unwrap().capability,
        BchTokenCapability::Minting
    );
    assert_eq!(merchant.nft.as_ref().unwrap().commitment, vec![0xab, 0xcd]);
}

#[test]
fn signer_preserves_resource_and_extensions() {
    let provider = FakeProvider::new(vec![utxo(1, 100_000, None)]);
    let requirements = native_requirements(NATIVE_PAY_TO, "3000");
    let payload = sign_with(provider, &requirements).unwrap();
    assert_eq!(
        payload
            .resource
            .as_ref()
            .map(|resource| resource.url.as_str()),
        Some(RESOURCE)
    );
    assert!(extension_flag(&payload));
}

#[test]
fn payment_target_rejects_token_amount_above_i64() {
    let error = payment_target_with_nft(
        &category_hex(),
        "9223372036854775808",
        "cashtoken",
        Some("546"),
        None,
        BchPolicy::default(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        crate::transaction::TransactionError::PolicyViolation(_)
    ));
    let _native: BchPaymentTarget =
        payment_target("BCH", "3000", "native", None, BchPolicy::default()).unwrap();
}
