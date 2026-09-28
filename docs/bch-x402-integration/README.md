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

## Official-library comparison

The official x402 library defines generic payment and facilitator types, then
places each chain's client, server, and facilitator implementation in a
chain-specific mechanism package. Its Aptos exact mechanism is the closest
reference for BCH because it carries a complete client-signed transaction in
the payment payload and validates it again before settlement.

For native BCH, the canonical v2 flow is `upfront`: the facilitator revalidates
and broadcasts the transaction before the resource runs. `x402-rs` expresses
that same ordering through `settle_before_execution = true` in the paygate.
The BCH crate should follow Rust-local traits and `PriceTag` patterns rather
than copying the official TypeScript API surface.

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
- `libauth/src/lib/message/transaction-types.ts` — BCH
  transaction and source-output model.
- `libauth/src/lib/message/transaction-encoding.ts` — BCH
  wire encoding and TXID byte-order behavior.
- `libauth/src/lib/vm/instruction-sets/common/signing-serialization.ts`
  — BCH signing serialization and sighash flags.
- `WalletConnect BCH network constants` — BCH
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

## Readiness assessment

See `readiness-assessment.md` for the distinction between a constrained POC and
a reliable cross-SDK release, including the remaining conformance gates.
