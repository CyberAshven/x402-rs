use serde::{Deserialize, Serialize};
use x402_types::lit_str;
use x402_types::proto::v2;

lit_str!(ExactScheme, "exact");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BchExtra {
    pub asset_transfer_method: String,
    pub payment_flow: String,
}

impl Default for BchExtra {
    fn default() -> Self {
        Self {
            asset_transfer_method: "native".to_string(),
            payment_flow: "upfront".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExactBchPayload {
    pub transaction: String,
}

pub type PaymentRequirements = v2::PaymentRequirements<ExactScheme, String, String, BchExtra>;
pub type PaymentPayload<TRequirements = PaymentRequirements> =
    v2::PaymentPayload<TRequirements, ExactBchPayload>;
pub type VerifyRequest = v2::VerifyRequest<PaymentPayload, PaymentRequirements>;
pub type SettleRequest = VerifyRequest;
