//! Server-side price requirements for native BCH exact payments.

use std::sync::Arc;
use x402_types::chain::ChainId;
use x402_types::proto;
use x402_types::proto::v2;

use crate::address::CashAddr;
use crate::chain::BchChainReference;
use crate::v2_bch_exact::V2BchExact;
use crate::v2_bch_exact::types::{BchExtra, ExactScheme};

pub type BchPaymentRequirements = v2::PaymentRequirements;

impl V2BchExact {
    pub fn price_tag(
        pay_to: impl Into<String>,
        amount: u64,
        network: BchChainReference,
    ) -> v2::PriceTag {
        v2::PriceTag {
            requirements: v2::PaymentRequirements {
                scheme: ExactScheme.to_string(),
                network: ChainId::from(network),
                amount: amount.to_string(),
                pay_to: pay_to.into(),
                max_timeout_seconds: 300,
                asset: "BCH".to_string(),
                extra: Some(
                    serde_json::to_value(BchExtra::default()).expect("BCH extra is serializable"),
                ),
            },
            enricher: Some(Arc::new(
                |price_tag: &mut v2::PriceTag, _supported: &proto::SupportedResponse| {
                    if price_tag.requirements.extra.is_none() {
                        price_tag.requirements.extra = Some(
                            serde_json::to_value(BchExtra::default())
                                .expect("BCH extra is serializable"),
                        );
                    }
                },
            )),
        }
    }

    pub fn validate_price_tag(
        requirements: &v2::PaymentRequirements,
    ) -> Result<(), crate::address::CashAddrError> {
        let network = BchChainReference::try_from(requirements.network.clone()).map_err(|_| {
            crate::address::CashAddrError::UnsupportedPrefix(requirements.network.to_string())
        })?;
        CashAddr::decode(&requirements.pay_to, network).map(|_| ())
    }
}
