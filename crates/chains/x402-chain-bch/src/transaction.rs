//! Bitcoin Cash transaction parsing, serialization, and P2PKH validation.

use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};

use crate::address::{CashAddr, hash160, p2pkh_script};
use crate::chain::BchChainReference;

pub const BCH_SIGHASH_ALL_FORKID: u32 = 0x41;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxId(pub [u8; 32]);

impl TxId {
    pub fn from_hex(value: &str) -> Result<Self, TransactionError> {
        let bytes = hex::decode(value).map_err(|_| TransactionError::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(TransactionError::InvalidHex);
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes);
        Ok(Self(txid))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for TxId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: TxId,
    pub vout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    pub outpoint: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BchTransaction {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransactionError {
    #[error("transaction is truncated")]
    Truncated,
    #[error("transaction contains a non-canonical compact-size integer")]
    NonCanonicalVarInt,
    #[error("transaction contains an unsupported witness marker")]
    WitnessUnsupported,
    #[error("transaction contains too many inputs or outputs")]
    ExcessiveCount,
    #[error("transaction contains an invalid script")]
    InvalidScript,
    #[error("transaction contains an invalid signature")]
    InvalidSignature,
    #[error("transaction contains an unsupported sighash type")]
    UnsupportedSighash,
    #[error("transaction contains an invalid public key")]
    InvalidPublicKey,
    #[error("transaction contains an invalid hex value")]
    InvalidHex,
    #[error("transaction arithmetic overflowed")]
    ArithmeticOverflow,
    #[error("transaction has an invalid input or output policy")]
    PolicyViolation(String),
}

impl BchTransaction {
    pub fn parse(raw: &[u8]) -> Result<Self, TransactionError> {
        let mut reader = Reader::new(raw);
        let version = reader.i32()?;
        let input_count = reader.varint()? as usize;
        if input_count == 0 || input_count > 10_000 {
            return Err(TransactionError::ExcessiveCount);
        }
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let mut txid_wire = [0u8; 32];
            txid_wire.copy_from_slice(reader.take(32)?);
            txid_wire.reverse();
            let vout = reader.u32()?;
            let script_sig = reader.bytes()?;
            let sequence = reader.u32()?;
            inputs.push(TxInput {
                outpoint: OutPoint {
                    txid: TxId(txid_wire),
                    vout,
                },
                script_sig,
                sequence,
            });
        }
        let output_count = reader.varint()? as usize;
        if output_count == 0 || output_count > 10_000 {
            return Err(TransactionError::ExcessiveCount);
        }
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(TxOutput {
                value: reader.u64()?,
                script_pubkey: reader.bytes()?,
            });
        }
        let lock_time = reader.u32()?;
        if !reader.is_empty() {
            return Err(TransactionError::PolicyViolation(
                "trailing bytes after locktime".to_string(),
            ));
        }
        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.version.to_le_bytes());
        write_varint(self.inputs.len() as u64, &mut result);
        for input in &self.inputs {
            let mut txid_wire = input.outpoint.txid.0;
            txid_wire.reverse();
            result.extend_from_slice(&txid_wire);
            result.extend_from_slice(&input.outpoint.vout.to_le_bytes());
            write_bytes(&input.script_sig, &mut result);
            result.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_varint(self.outputs.len() as u64, &mut result);
        for output in &self.outputs {
            result.extend_from_slice(&output.value.to_le_bytes());
            write_bytes(&output.script_pubkey, &mut result);
        }
        result.extend_from_slice(&self.lock_time.to_le_bytes());
        result
    }

    pub fn txid(&self) -> TxId {
        let digest = double_sha256(&self.serialize());
        let mut txid = digest;
        txid.reverse();
        TxId(txid)
    }

    pub fn signing_hash(
        &self,
        input_index: usize,
        source_output: &SourceOutput,
        sighash_type: u32,
    ) -> Result<[u8; 32], TransactionError> {
        if sighash_type != BCH_SIGHASH_ALL_FORKID {
            return Err(TransactionError::UnsupportedSighash);
        }
        let input = self
            .inputs
            .get(input_index)
            .ok_or(TransactionError::Truncated)?;
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.version.to_le_bytes());

        let mut prevouts = Vec::with_capacity(self.inputs.len() * 36);
        for candidate in &self.inputs {
            let mut txid_wire = candidate.outpoint.txid.0;
            txid_wire.reverse();
            prevouts.extend_from_slice(&txid_wire);
            prevouts.extend_from_slice(&candidate.outpoint.vout.to_le_bytes());
        }
        preimage.extend_from_slice(&double_sha256(&prevouts));

        let mut sequences = Vec::with_capacity(self.inputs.len() * 4);
        for candidate in &self.inputs {
            sequences.extend_from_slice(&candidate.sequence.to_le_bytes());
        }
        preimage.extend_from_slice(&double_sha256(&sequences));

        let mut txid_wire = input.outpoint.txid.0;
        txid_wire.reverse();
        preimage.extend_from_slice(&txid_wire);
        preimage.extend_from_slice(&input.outpoint.vout.to_le_bytes());
        write_bytes(&source_output.script_pubkey, &mut preimage);
        preimage.extend_from_slice(&source_output.value.to_le_bytes());
        preimage.extend_from_slice(&input.sequence.to_le_bytes());

        let mut outputs = Vec::new();
        for output in &self.outputs {
            outputs.extend_from_slice(&output.value.to_le_bytes());
            write_bytes(&output.script_pubkey, &mut outputs);
        }
        preimage.extend_from_slice(&double_sha256(&outputs));
        preimage.extend_from_slice(&self.lock_time.to_le_bytes());
        preimage.extend_from_slice(&sighash_type.to_le_bytes());
        Ok(double_sha256(&preimage))
    }

    pub fn verify_p2pkh_input(
        &self,
        input_index: usize,
        source_output: &SourceOutput,
    ) -> Result<[u8; 20], TransactionError> {
        let input = self
            .inputs
            .get(input_index)
            .ok_or(TransactionError::Truncated)?;
        if !is_p2pkh_script(&source_output.script_pubkey) {
            return Err(TransactionError::PolicyViolation(
                "source output is not P2PKH".to_string(),
            ));
        }
        let pushes = parse_pushes(&input.script_sig)?;
        if pushes.len() != 2 || pushes[0].len() < 2 {
            return Err(TransactionError::InvalidScript);
        }
        let signature_bytes = pushes[0];
        let sighash_type = *signature_bytes
            .last()
            .ok_or(TransactionError::InvalidSignature)?;
        if u32::from(sighash_type) != BCH_SIGHASH_ALL_FORKID {
            return Err(TransactionError::UnsupportedSighash);
        }
        let signature = Signature::from_der(&signature_bytes[..signature_bytes.len() - 1])
            .map_err(|_| TransactionError::InvalidSignature)?;
        let public_key =
            PublicKey::from_slice(pushes[1]).map_err(|_| TransactionError::InvalidPublicKey)?;
        let public_key_bytes = public_key.serialize();
        let public_key_hash = hash160(&public_key_bytes);
        if source_output.script_pubkey[3..23] != public_key_hash[..] {
            return Err(TransactionError::InvalidSignature);
        }
        let digest = self.signing_hash(input_index, source_output, BCH_SIGHASH_ALL_FORKID)?;
        let message = Message::from_digest(digest);
        Secp256k1::verification_only()
            .verify_ecdsa(message, &signature, &public_key)
            .map_err(|_| TransactionError::InvalidSignature)?;
        Ok(public_key_hash)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BchPolicy {
    pub fee_rate_sat_per_byte: u64,
    pub dust_threshold: u64,
    pub max_transaction_size: usize,
    pub max_inputs: usize,
}

impl Default for BchPolicy {
    fn default() -> Self {
        Self {
            fee_rate_sat_per_byte: 1,
            dust_threshold: 546,
            max_transaction_size: 100_000,
            max_inputs: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    pub txid: TxId,
    pub payer: CashAddr,
    pub fee: u64,
    pub input_value: u64,
    pub output_value: u64,
}

pub fn verify_payment(
    transaction: &BchTransaction,
    source_outputs: &[SourceOutput],
    network: BchChainReference,
    merchant_script: &[u8],
    merchant_amount: u64,
    policy: BchPolicy,
) -> Result<VerifiedPayment, TransactionError> {
    let serialized_size = transaction.serialize().len();
    if serialized_size > policy.max_transaction_size {
        return Err(TransactionError::PolicyViolation(
            "transaction exceeds maximum size".to_string(),
        ));
    }
    if transaction.inputs.is_empty() || transaction.inputs.len() > policy.max_inputs {
        return Err(TransactionError::ExcessiveCount);
    }
    if transaction.lock_time != 0 {
        return Err(TransactionError::PolicyViolation(
            "non-zero locktime is not supported by BCH exact".to_string(),
        ));
    }
    if merchant_amount < policy.dust_threshold {
        return Err(TransactionError::PolicyViolation(
            "merchant output is below dust".to_string(),
        ));
    }
    if source_outputs.len() != transaction.inputs.len() {
        return Err(TransactionError::PolicyViolation(
            "source output count does not match transaction inputs".to_string(),
        ));
    }
    if transaction.outputs.len() > 2 {
        return Err(TransactionError::PolicyViolation(
            "BCH exact permits one merchant output and one change output".to_string(),
        ));
    }

    let mut input_value = 0u64;
    let mut payer_hash = None;
    for (index, source_output) in source_outputs.iter().enumerate() {
        input_value = input_value
            .checked_add(source_output.value)
            .ok_or(TransactionError::ArithmeticOverflow)?;
        let hash = transaction.verify_p2pkh_input(index, source_output)?;
        payer_hash.get_or_insert(hash);
    }

    let merchant_matches = transaction
        .outputs
        .iter()
        .filter(|output| output.value == merchant_amount && output.script_pubkey == merchant_script)
        .count();
    if merchant_matches != 1 {
        return Err(TransactionError::PolicyViolation(
            "transaction must contain exactly one exact merchant output".to_string(),
        ));
    }

    let mut output_value = 0u64;
    for output in &transaction.outputs {
        if !is_p2pkh_script(&output.script_pubkey) {
            return Err(TransactionError::PolicyViolation(
                "all BCH exact outputs must be standard P2PKH".to_string(),
            ));
        }
        output_value = output_value
            .checked_add(output.value)
            .ok_or(TransactionError::ArithmeticOverflow)?;
    }
    let fee = input_value
        .checked_sub(output_value)
        .ok_or(TransactionError::PolicyViolation(
            "outputs exceed input value".to_string(),
        ))?;
    let minimum_fee = (serialized_size as u64)
        .checked_mul(policy.fee_rate_sat_per_byte)
        .ok_or(TransactionError::ArithmeticOverflow)?;
    if fee < minimum_fee {
        return Err(TransactionError::PolicyViolation(
            "transaction fee is below the BCH exact minimum".to_string(),
        ));
    }
    if transaction.outputs.len() == 2 {
        let change = transaction
            .outputs
            .iter()
            .find(|output| {
                !(output.value == merchant_amount && output.script_pubkey == merchant_script)
            })
            .ok_or_else(|| {
                TransactionError::PolicyViolation("missing change output".to_string())
            })?;
        if change.value < policy.dust_threshold {
            return Err(TransactionError::PolicyViolation(
                "change output is below dust threshold".to_string(),
            ));
        }
        if change.script_pubkey == merchant_script {
            return Err(TransactionError::PolicyViolation(
                "duplicate merchant output is not valid change".to_string(),
            ));
        }
    }

    let payer_hash = payer_hash.ok_or(TransactionError::InvalidSignature)?;
    Ok(VerifiedPayment {
        txid: transaction.txid(),
        payer: CashAddr {
            network,
            hash160: payer_hash,
        },
        fee,
        input_value,
        output_value,
    })
}

pub fn is_p2pkh_script(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
}

pub fn make_p2pkh_script(public_key: &[u8]) -> Vec<u8> {
    p2pkh_script(&hash160(public_key))
}

pub fn push_data(data: &[u8]) -> Result<Vec<u8>, TransactionError> {
    if data.len() > 75 {
        return Err(TransactionError::InvalidScript);
    }
    let mut result = Vec::with_capacity(data.len() + 1);
    result.push(data.len() as u8);
    result.extend_from_slice(data);
    Ok(result)
}

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

fn parse_pushes(script: &[u8]) -> Result<Vec<&[u8]>, TransactionError> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    while offset < script.len() {
        let opcode = script[offset];
        offset += 1;
        let length = match opcode {
            0x01..=0x4b => opcode as usize,
            0x4c => usize::from(*script.get(offset).ok_or(TransactionError::InvalidScript)?),
            0x4d => {
                let bytes = script
                    .get(offset..offset + 2)
                    .ok_or(TransactionError::InvalidScript)?;
                offset += 2;
                usize::from(u16::from_le_bytes([bytes[0], bytes[1]]))
            }
            _ => return Err(TransactionError::InvalidScript),
        };
        if opcode == 0x4c {
            offset += 1;
        }
        let end = offset
            .checked_add(length)
            .ok_or(TransactionError::InvalidScript)?;
        let value = script
            .get(offset..end)
            .ok_or(TransactionError::InvalidScript)?;
        result.push(value);
        offset = end;
    }
    Ok(result)
}

fn write_bytes(value: &[u8], output: &mut Vec<u8>) {
    write_varint(value.len() as u64, output);
    output.extend_from_slice(value);
}

fn write_varint(value: u64, output: &mut Vec<u8>) {
    if value <= 252 {
        output.push(value as u8);
    } else if value <= u16::MAX as u64 {
        output.push(253);
        output.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= u32::MAX as u64 {
        output.push(254);
        output.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        output.push(255);
        output.extend_from_slice(&value.to_le_bytes());
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TransactionError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(TransactionError::Truncated)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(TransactionError::Truncated)?;
        self.offset = end;
        Ok(result)
    }

    fn u32(&mut self) -> Result<u32, TransactionError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn i32(&mut self) -> Result<i32, TransactionError> {
        let bytes = self.take(4)?;
        Ok(i32::from_le_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn u64(&mut self) -> Result<u64, TransactionError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn varint(&mut self) -> Result<u64, TransactionError> {
        let first = self.take(1)?[0];
        match first {
            0..=252 => Ok(u64::from(first)),
            253 => {
                let value = u16::from_le_bytes(self.take(2)?.try_into().expect("length checked"));
                if value < 253 {
                    Err(TransactionError::NonCanonicalVarInt)
                } else {
                    Ok(u64::from(value))
                }
            }
            254 => {
                let value = u32::from_le_bytes(self.take(4)?.try_into().expect("length checked"));
                if value <= u16::MAX as u32 {
                    Err(TransactionError::NonCanonicalVarInt)
                } else {
                    Ok(u64::from(value))
                }
            }
            255 => {
                let value = u64::from_le_bytes(self.take(8)?.try_into().expect("length checked"));
                if value <= u32::MAX as u64 {
                    Err(TransactionError::NonCanonicalVarInt)
                } else {
                    Ok(value)
                }
            }
        }
    }

    fn bytes(&mut self) -> Result<Vec<u8>, TransactionError> {
        let length = self.varint()? as usize;
        Ok(self.take(length)?.to_vec())
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_and_parses_a_minimal_transaction() {
        let transaction = BchTransaction {
            version: 2,
            inputs: vec![TxInput {
                outpoint: OutPoint {
                    txid: TxId([1; 32]),
                    vout: 0,
                },
                script_sig: vec![0x01, 0x01],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput {
                value: 1_000,
                script_pubkey: p2pkh_script(&[2; 20]),
            }],
            lock_time: 0,
        };
        assert_eq!(
            BchTransaction::parse(&transaction.serialize()).unwrap(),
            transaction
        );
    }

    #[test]
    fn rejects_trailing_bytes() {
        let transaction = BchTransaction {
            version: 1,
            inputs: vec![TxInput {
                outpoint: OutPoint {
                    txid: TxId([0; 32]),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput {
                value: 1,
                script_pubkey: p2pkh_script(&[0; 20]),
            }],
            lock_time: 0,
        };
        let mut raw = transaction.serialize();
        raw.push(0);
        assert!(BchTransaction::parse(&raw).is_err());
    }
}
