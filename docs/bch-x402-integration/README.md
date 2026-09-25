# BCH x402 integration design record

This directory records the design decisions, rejected alternatives, open
questions, and implementation plan for adding Bitcoin Cash support to x402-rs.
It is intentionally part of the repository so future contributors and review
tools can reconstruct why the implementation looks the way it does.

## Current status

The repository currently contains only the BCH network-identity foundation in
`crates/chains/x402-chain-bch`. No BCH transaction construction, signing,
facilitator, or server integration has been implemented yet.

The current identities are:

- Mainnet: `bch:bitcoincash`
- Chipnet: `bch:bchtest`

These match the current OPTN WalletConnect mapping. `bch:mainnet`,
`bch:chipnet`, and `bip122:*` are deliberately not accepted by the typed BCH
identity layer.

## Design target

The first implementation target is x402 v2 `exact` for native BCH:

1. A client selects an x402 BCH requirement.
2. The client constructs and signs a normal BCH UTXO transaction.
3. The payment payload carries the serialized signed transaction.
4. A facilitator verifies the transaction against authoritative source UTXOs.
5. The facilitator broadcasts the same transaction and reports its TXID.

This preserves the canonical x402 transport and facilitator flow while adapting
the authorization object to BCH's transaction-based authorization model.

## Future interoperability scope

The POC deliberately starts with native BCH, P2PKH, CashAddr, and finalized
raw transactions. The long-term design leaves room for:

- CashTokens with typed asset conservation and successor-output validation.
- Multiple BCH address encodings, normalized internally to validated locking
  scripts and explicit token metadata.
- PSBT-based offline and hardware-wallet signing, finalized before x402
  verification and settlement.

These additions are compatibility milestones, not reasons to broaden the POC
wire contract prematurely.

## Primary references

- `crates/x402-types/src/scheme/client.rs` — client scheme extension point.
- `crates/x402-types/src/scheme/mod.rs` — facilitator and scheme registry.
- `crates/chains/x402-chain-solana/src/v2_solana_exact/` — serialized signed
  transaction scheme pattern.
- `/mnt/hdd/projects/libauth/src/lib/message/transaction-types.ts` — BCH
  transaction and source-output model.
- `/mnt/hdd/projects/libauth/src/lib/message/transaction-encoding.ts` — BCH
  wire encoding and TXID byte-order behavior.
- `/mnt/hdd/projects/libauth/src/lib/vm/instruction-sets/common/signing-serialization.ts`
  — BCH signing serialization and sighash flags.
- `/mnt/hdd/projects/OPTNWallet/src/redux/walletconnect/constants.ts` — BCH
  WalletConnect network identifiers used by OPTN.

## Decision record

See `decision-log.md` for the prompt-by-prompt design history.

## Implementation plan

See `implementation-plan.md` for phases, crate structure, security checks,
testing, and acceptance criteria.

## Open decisions

See `open-decisions.md`. Each item has a recommended default. Implementation
should not silently change these wire-level decisions; if a default changes,
add a new entry to `decision-log.md` first.
