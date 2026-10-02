//! Thin browser bindings around the same BCH exact client used on native.
//!
//! The browser supplies a Fulcrum transport. Payment selection, signing, and
//! verification stay in this crate.

use async_trait::async_trait;
use serde_json::{Value, json};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};
use x402_types::proto::v2::{self, ExtensionsJson, ResourceInfo, X402Version2};
use x402_types::proto::{OriginalJson, PaymentRequired};
use x402_types::scheme::client::X402SchemeClient;
use x402_types::util::Base64Bytes;

use crate::BchProviderError;
use crate::chain::BchChainReference;
use crate::provider::{FulcrumProvider, FulcrumTransport};
use crate::transaction::BchTransaction;
use crate::v2_bch_exact::client::{Secp256k1BchSigner, V2BchExactClient};
use crate::v2_bch_exact::types::PaymentRequirements;

/// JavaScript Fulcrum transport.
///
/// `request_fn` is `async (method, paramsJson) => jsonString`. It must resolve
/// to the JSON-RPC `result` value, not the full JSON-RPC envelope.
#[wasm_bindgen]
pub struct JsFulcrumTransport {
    request_fn: js_sys::Function,
}

#[wasm_bindgen]
impl JsFulcrumTransport {
    #[wasm_bindgen(constructor)]
    pub fn new(request_fn: js_sys::Function) -> JsFulcrumTransport {
        Self { request_fn }
    }
}

impl Clone for JsFulcrumTransport {
    fn clone(&self) -> Self {
        Self {
            request_fn: self.request_fn.clone(),
        }
    }
}

#[async_trait]
impl FulcrumTransport for JsFulcrumTransport {
    async fn request(&self, method: &str, params: Value) -> Result<Value, BchProviderError> {
        let params_json = serde_json::to_string(&params)
            .map_err(|error| BchProviderError::InvalidResponse(error.to_string()))?;
        let request_fn = self.request_fn.clone();
        let method = method.to_owned();
        // `JsFuture` is `!Send`. The shared transport trait is `Send` because
        // native callers use it from worker threads, so the JavaScript promise
        // runs on this thread and only its result crosses the await.
        let (sender, receiver) = tokio::sync::oneshot::channel();
        spawn_local(async move {
            let outcome = invoke_transport(request_fn, method, params_json).await;
            let _ = sender.send(outcome);
        });
        receiver.await.map_err(|_| {
            BchProviderError::Transport("Fulcrum transport dropped the response".to_string())
        })?
    }
}

async fn invoke_transport(
    request_fn: js_sys::Function,
    method: String,
    params_json: String,
) -> Result<Value, BchProviderError> {
    let arguments = js_sys::Array::new();
    arguments.push(&JsValue::from_str(&method));
    arguments.push(&JsValue::from_str(&params_json));
    let returned = js_sys::Reflect::apply(&request_fn, &JsValue::UNDEFINED, &arguments)
        .map_err(|error| BchProviderError::Transport(js_error(&error)))?;
    let promise: js_sys::Promise = returned.dyn_into().map_err(|_| {
        BchProviderError::Transport("Fulcrum transport must return a Promise".to_string())
    })?;
    let resolved = JsFuture::from(promise)
        .await
        .map_err(|error| BchProviderError::Transport(js_error(&error)))?;
    let text = resolved.as_string().ok_or_else(|| {
        BchProviderError::InvalidResponse(
            "Fulcrum transport must resolve a JSON string".to_string(),
        )
    })?;
    serde_json::from_str(&text)
        .map_err(|error| BchProviderError::InvalidResponse(error.to_string()))
}

/// Browser client for one P2PKH signer and one JavaScript Fulcrum transport.
#[wasm_bindgen]
pub struct BchBrowserClient {
    client: V2BchExactClient<Secp256k1BchSigner, FulcrumProvider<JsFulcrumTransport>>,
    address: String,
}

#[wasm_bindgen]
impl BchBrowserClient {
    /// `network` is `mainnet`, `chipnet`, `bch:bitcoincash`, or `bch:bchtest`.
    /// The signer is `m/44'/145'/0'/0/0` on mainnet and `m/44'/1'/0'/0/0` on chipnet.
    #[wasm_bindgen(constructor)]
    pub fn new(
        mnemonic: &str,
        network: &str,
        transport: JsFulcrumTransport,
    ) -> Result<BchBrowserClient, JsValue> {
        let network = parse_network(network)?;
        let coin_type = if network.is_test_network() { 1 } else { 145 };
        let signer =
            Secp256k1BchSigner::from_mnemonic_with_path(mnemonic, None, coin_type, 0, 0, 0)
                .map_err(|error| JsValue::from_str(&error))?;
        let address = signer.address(network).encode();
        let provider = FulcrumProvider::new(transport, network);
        Ok(Self {
            client: V2BchExactClient::new(signer, provider),
            address,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    /// Sign one exact payment with the shared Rust client.
    ///
    /// `requirements_json` is one x402 v2 `PaymentRequirements` object.
    /// `resource_url` is bound into the signed payload. An omitted CashToken
    /// `tokenOutputValue` still defaults to 1,000 satoshis inside that client.
    pub async fn sign_exact(
        &self,
        requirements_json: &str,
        resource_url: &str,
    ) -> Result<String, JsValue> {
        if resource_url.is_empty() {
            return Err(JsValue::from_str("resource URL is required"));
        }
        let requirements: PaymentRequirements = serde_json::from_str(requirements_json)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let raw = serde_json::value::to_raw_value(&requirements)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let payment_required = PaymentRequired::V2(v2::PaymentRequired {
            x402_version: X402Version2,
            error: None,
            resource: Some(ResourceInfo {
                url: resource_url.to_string(),
                description: None,
                mime_type: None,
            }),
            accepts: vec![OriginalJson(raw)],
            extensions: ExtensionsJson::new(),
        });
        let candidates = self.client.accept(&payment_required);
        if candidates.len() != 1 {
            return Err(JsValue::from_str(
                "BCH exact client did not accept this payment requirement",
            ));
        }
        let encoded = candidates[0]
            .sign()
            .await
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let payload_bytes = Base64Bytes::from(encoded.as_bytes())
            .decode()
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let payload: crate::v2_bch_exact::PaymentPayload =
            serde_json::from_slice(&payload_bytes)
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let transaction_bytes = Base64Bytes::from(payload.payload.transaction.as_bytes())
            .decode()
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let transaction = BchTransaction::parse(&transaction_bytes)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let merchant_value = transaction
            .outputs
            .first()
            .map(|output| output.value)
            .unwrap_or(0);
        Ok(json!({
            "payload": encoded,
            "inputCount": transaction.inputs.len(),
            "outputCount": transaction.outputs.len(),
            "merchantValue": merchant_value,
            "byteLength": transaction_bytes.len(),
        })
        .to_string())
    }
}

fn parse_network(value: &str) -> Result<BchChainReference, JsValue> {
    match value {
        "mainnet" | "bch:bitcoincash" => Ok(BchChainReference::Mainnet),
        "chipnet" | "bch:bchtest" => Ok(BchChainReference::Chipnet),
        _ => Err(JsValue::from_str(
            "network must be mainnet, chipnet, bch:bitcoincash, or bch:bchtest",
        )),
    }
}

fn js_error(value: &JsValue) -> String {
    if let Some(text) = value.as_string() {
        return text;
    }
    js_sys::Reflect::get(value, &JsValue::from_str("message"))
        .ok()
        .and_then(|message| message.as_string())
        .unwrap_or_else(|| "JavaScript transport error".to_string())
}
