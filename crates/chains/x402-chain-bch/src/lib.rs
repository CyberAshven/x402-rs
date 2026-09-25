//! Bitcoin Cash network identity support for x402.
//!
//! BCH uses the `bch` namespace with the CashAddr network prefixes used by
//! BCH integrations: `bch:bitcoincash` for mainnet and `bch:bchtest` for
//! chipnet.
//!
//! This crate deliberately does not derive the network identity from a BCH
//! genesis hash or Bitcoin fork height. Those identifiers are useful for
//! chain-internal tooling, but they are not the network vocabulary used by BCH
//! WalletConnect integrations and would make x402 payments needlessly
//! incompatible with BCH applications.

pub mod chain;

pub use chain::{BCH_NAMESPACE, BchChainReference, BchChainReferenceFormatError};
