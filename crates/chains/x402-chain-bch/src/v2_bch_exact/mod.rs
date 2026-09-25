//! x402 v2 `exact` support for native BCH.

pub mod client;
pub mod facilitator;
pub mod server;
pub mod types;

pub use client::{BchSigner, Secp256k1BchSigner, V2BchExactClient};
pub use facilitator::{BchConfirmationStrategy, BchFacilitatorConfig, V2BchExactFacilitator};
pub use server::BchPaymentRequirements;
pub use types::{BchExtra, ExactBchPayload, ExactScheme, PaymentPayload, PaymentRequirements};

use x402_types::scheme::X402SchemeId;

/// Marker for the native BCH v2 exact scheme.
#[derive(Debug, Clone, Copy, Default)]
pub struct V2BchExact;

impl X402SchemeId for V2BchExact {
    fn namespace(&self) -> &str {
        crate::BCH_NAMESPACE
    }

    fn scheme(&self) -> &str {
        "exact"
    }
}
