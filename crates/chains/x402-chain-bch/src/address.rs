//! BCH CashAddr parsing and standard P2PKH script handling.
//!
//! The x402 BCH POC deliberately accepts only network-qualified CashAddr
//! P2PKH addresses. Addresses are normalized to locking scripts before any
//! transaction policy is applied.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};

use crate::chain::BchChainReference;

const CASHADDR_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CASHADDR_GENERATORS: [u64; 5] = [
    0x98f2bc8e61,
    0x79b76d99e2,
    0xf33e5fb3c4,
    0xae2eabe2a8,
    0x1e4f43e470,
];

/// A decoded standard BCH P2PKH CashAddr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CashAddr {
    pub network: BchChainReference,
    pub hash160: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CashAddrError {
    #[error("CashAddr must contain a network prefix")]
    MissingPrefix,
    #[error("CashAddr contains mixed or uppercase characters")]
    NonCanonicalCase,
    #[error("unsupported CashAddr prefix {0:?}")]
    UnsupportedPrefix(String),
    #[error("invalid CashAddr character {0:?}")]
    InvalidCharacter(char),
    #[error("invalid CashAddr checksum")]
    InvalidChecksum,
    #[error("invalid CashAddr payload")]
    InvalidPayload,
    #[error("CashAddr is not a standard P2PKH address")]
    UnsupportedAddressType,
    #[error("CashAddr payload has the wrong length")]
    InvalidLength,
}

impl CashAddr {
    pub fn decode(value: &str, expected_network: BchChainReference) -> Result<Self, CashAddrError> {
        let (prefix, payload) = value.split_once(':').ok_or(CashAddrError::MissingPrefix)?;
        if prefix.is_empty() || payload.is_empty() {
            return Err(CashAddrError::InvalidPayload);
        }
        if value != value.to_ascii_lowercase() {
            return Err(CashAddrError::NonCanonicalCase);
        }
        let actual_network = match prefix {
            "bitcoincash" => BchChainReference::Mainnet,
            "bchtest" => BchChainReference::Chipnet,
            other => return Err(CashAddrError::UnsupportedPrefix(other.to_owned())),
        };
        if actual_network != expected_network {
            return Err(CashAddrError::UnsupportedPrefix(prefix.to_owned()));
        }

        let values = payload
            .bytes()
            .map(|byte| {
                CASHADDR_CHARSET
                    .iter()
                    .position(|candidate| *candidate == byte)
                    .map(|value| value as u8)
                    .ok_or(CashAddrError::InvalidCharacter(byte as char))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if values.len() < 9 || polymod(&[prefix_expand(prefix), values.clone()].concat()) != 1 {
            return Err(CashAddrError::InvalidChecksum);
        }

        let data = &values[..values.len() - 8];
        let decoded = convert_bits(data, 5, 8, false).ok_or(CashAddrError::InvalidPayload)?;
        if decoded.len() != 21 || decoded[0] != 0 {
            return Err(CashAddrError::UnsupportedAddressType);
        }
        let mut hash160 = [0u8; 20];
        hash160.copy_from_slice(&decoded[1..]);
        Ok(Self {
            network: actual_network,
            hash160,
        })
    }

    pub fn encode(self) -> String {
        let prefix = match self.network {
            BchChainReference::Mainnet => "bitcoincash",
            BchChainReference::Chipnet => "bchtest",
        };
        let mut payload = vec![0u8];
        payload.extend_from_slice(&self.hash160);
        let data = convert_bits(&payload, 8, 5, true).expect("fixed CashAddr payload converts");
        let mut checksum_input = prefix_expand(prefix);
        checksum_input.extend_from_slice(&data);
        checksum_input.extend_from_slice(&[0; 8]);
        let checksum = create_checksum(&checksum_input);
        let mut encoded = String::with_capacity(prefix.len() + 1 + data.len() + 8);
        encoded.push_str(prefix);
        encoded.push(':');
        for value in data.into_iter().chain(checksum) {
            encoded.push(CASHADDR_CHARSET[value as usize] as char);
        }
        encoded
    }

    pub fn locking_script(self) -> Vec<u8> {
        p2pkh_script(&self.hash160)
    }
}

impl Display for CashAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encode())
    }
}

pub fn p2pkh_script(hash160: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(hash160);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

pub fn hash160(value: &[u8]) -> [u8; 20] {
    let sha256 = Sha256::digest(value);
    let digest = Ripemd160::digest(sha256);
    let mut result = [0u8; 20];
    result.copy_from_slice(&digest);
    result
}

fn prefix_expand(prefix: &str) -> Vec<u8> {
    prefix
        .bytes()
        .map(|value| value & 0x1f)
        .chain(std::iter::once(0))
        .collect()
}

fn polymod(values: &[u8]) -> u64 {
    let mut checksum = 1u64;
    for value in values {
        let top = checksum >> 35;
        checksum = ((checksum & 0x07ffffffff) << 5) ^ u64::from(*value);
        for (index, generator) in CASHADDR_GENERATORS.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn create_checksum(values: &[u8]) -> [u8; 8] {
    let checksum = polymod(values) ^ 1;
    let mut result = [0u8; 8];
    for (index, value) in result.iter_mut().enumerate() {
        *value = ((checksum >> (5 * (7 - index))) & 0x1f) as u8;
    }
    result
}

fn convert_bits(data: &[u8], from: u8, to: u8, pad: bool) -> Option<Vec<u8>> {
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    let max_value = (1u32 << to) - 1;
    let max_accumulator = (1u32 << (from + to - 1)) - 1;
    let mut result = Vec::new();
    for value in data {
        if (*value as u32) >> from != 0 {
            return None;
        }
        accumulator = ((accumulator << from) | u32::from(*value)) & max_accumulator;
        bits = bits.saturating_add(from);
        while bits >= to {
            bits -= to;
            result.push(((accumulator >> bits) & max_value) as u8);
        }
    }
    if pad {
        if bits > 0 {
            result.push(((accumulator << (to - bits)) & max_value) as u8);
        }
    } else if bits >= from || ((accumulator << (to - bits)) & max_value) != 0 {
        return None;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_standard_cashaddr() {
        let address = CashAddr {
            network: BchChainReference::Mainnet,
            hash160: [0x11; 20],
        };
        let encoded = address.encode();
        assert_eq!(
            CashAddr::decode(&encoded, BchChainReference::Mainnet).unwrap(),
            address
        );
    }

    #[test]
    fn rejects_wrong_network() {
        let address = CashAddr {
            network: BchChainReference::Mainnet,
            hash160: [0x22; 20],
        }
        .encode();
        assert!(CashAddr::decode(&address, BchChainReference::Chipnet).is_err());
    }
}
