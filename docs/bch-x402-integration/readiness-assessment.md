# BCH x402 implementation readiness assessment

## Verdict

We have enough context to begin a constrained proof-of-concept implementation
in both the official x402 TypeScript ecosystem and `x402-rs`.

We do not yet have enough frozen detail to describe the result as a reliable,
drop-in integration for unrelated third-party developers. The missing work is
not another broad architecture investigation. It is a short conformance phase:
freeze the BCH exact wire contract, publish cross-language transaction vectors,
and define the provider and signer boundaries that third-party applications
must implement.

The two SDK implementations do not need identical internal APIs. They must
produce and consume the same x402 v2 wire representation and the same BCH
transaction validity rules.

## Supported first release boundary

The first release can be reliable if it explicitly supports only:

- x402 v2 `exact`.
- `bch:bitcoincash` and `bch:bchtest`.
- Native BCH, represented as `asset: "BCH"` and
  `extra.assetTransferMethod: "native"`.
- `extra.paymentFlow: "upfront"`.
- CashAddr recipients with strict network validation.
- Standard P2PKH inputs, multiple inputs, one exact merchant output, and
  ordinary BCH change outputs.
- A complete client-signed raw transaction carried as
  `payload.transaction`.
- Client-paid fees; no facilitator input insertion, transaction mutation, or
  fee sponsorship.
- Token-bearing transactions rejected until CashToken conservation is
  implemented.
- Facilitator-side authoritative source-output lookup and raw transaction
  broadcast.

CashTokens, P2SH/CashScript, alternate address encodings, PSBT, sponsorship,
`upto`, and batch settlement must be advertised as unsupported in this release.

## Shared conformance gates before public release

### 1. Normative scheme document

Create one canonical BCH exact specification and use it as the source for both
SDKs. It must define:

- Exact JSON fields, casing, required/optional fields, and payload encoding.
- `bch:bitcoincash` and `bch:bchtest` identity rules.
- Native asset spelling and `assetTransferMethod` behavior.
- `paymentFlow: "upfront"` behavior.
- Satoshi parsing, overflow, and amount matching.
- CashAddr parsing and script equivalence rules.
- P2PKH-only script policy and rejected script types.
- Fee, dust, transaction size, input count, output count, and locktime policy.
- Exact merchant-output selection and duplicate-output behavior.
- Payer reporting semantics.
- Mempool versus confirmation success criteria.
- `settlement_pending`, conflict, already-known, and retry behavior.
- Error reason strings and their mapping in both SDKs.

The implementation must fail closed when a requirement is outside this
documented boundary.

### 2. Cross-language golden vectors

The TypeScript and Rust implementations need shared JSON fixtures for:

- Valid one-input and multi-input P2PKH transactions.
- BCH `0x61` signing serialization and signatures.
- Transaction IDs and byte-order conversion.
- CashAddr/script round trips on mainnet and Chipnet.
- Exact output matching with change.
- Wrong network, wrong payee, wrong amount, duplicate payment output, dust,
  excessive fee, malformed transaction, and trailing-byte rejection.
- Missing, spent, conflicting, and substituted source outputs.
- CashToken-prefix rejection.
- Settlement responses for broadcast success, mempool-only, confirmation,
  conflict, and indeterminate status.

Every successful fixture should decode consistently using libauth and the Rust
implementation. These vectors are more important than matching source-code
structure between SDKs.

### 3. Provider and signer contracts

Separate read-only chain access from signing and broadcast capabilities.

The client side needs UTXO discovery, source transaction data, fee policy, and
a signer capable of producing BCH-valid signatures. The facilitator side needs
source-output lookup, spentness/conflict state, raw transaction broadcast, and
status polling. A facilitator must not trust client-provided source outputs.

The provider contract must distinguish not-found, spent, conflicting, mempool,
confirmed, and transport-error states. A transport error cannot be interpreted
as either spendability or successful settlement.

### 4. Flow integration

The official x402 core supports scheme-specific client/server/facilitator
implementations in a chain mechanism package. BCH should be an external
package such as `@x402/bch` or an OPTN-maintained equivalent, without changing
`@x402/core`. It needs registration helpers, a signer/provider interface,
README examples, and unit/integration tests.

The Rust implementation should remain in `x402-chain-bch`, using the existing
Rust scheme traits, typed v2 aliases, `PriceTag`, and chain-provider patterns.
The current Rust paygate already has a settlement-before-execution mode, but
the BCH integration must make the `upfront` requirement and that configuration
inseparable or fail closed. A wire field alone must not allow an operator to
accidentally run BCH after resource execution.

### 5. Settlement recovery

The raw BCH transaction ID is the natural reconciliation value. After a
successful broadcast with indeterminate confirmation, return
`settlement_pending` with the TXID. A retry must check the existing TXID and
transaction state before attempting any new broadcast. An already-known
identical transaction is not the same as a conflicting transaction.

The first release should document whether `success: true` means accepted into
the mempool or confirmed. A configurable policy is acceptable, but each SDK's
default must be explicit and tested.

## SDK-specific implementation readiness

### Official x402 TypeScript ecosystem

The official architecture is ready for a new mechanism package. The required
surface is the core `SchemeNetworkClient`, `SchemeNetworkServer`, and
`SchemeNetworkFacilitator` interfaces. The closest reference is the official
Aptos exact mechanism because it carries a complete signed transaction and
revalidates it at settlement.

The official repository may accept BCH through its specification-first review
process, but acceptance is not required for interoperability. A separately
published BCH mechanism package can register with `@x402/core` as long as it
uses the canonical wire contract.

### x402-rs

The Rust architecture already has the relevant extension points:

- Chain-specific crate and network identity.
- Generic v2 payload and requirements aliases.
- Client candidate/signer traits.
- Facilitator builder, verification, settlement, and supported-capability
  traits.
- `PriceTag` construction and facilitator-capability enrichment.
- Axum settlement-before-execution support.

The main missing Rust work is BCH-specific: UTXO provider traits, transaction
and sighash primitives, client transaction construction, facilitator policy
checks, raw broadcast/status handling, and a BCH price-tag/server adapter.

The Rust core currently treats settlement responses as generic JSON and does
not provide the official TypeScript payment-flow resolver. BCH can still be
implemented safely by enforcing `upfront` through the BCH integration and
paygate configuration, but this must be covered by integration tests and
documented as an explicit compatibility boundary.

## Recommended implementation order

1. Freeze and publish the scheme document and shared fixtures.
2. Implement libauth-checked BCH primitives and a mock provider in Rust.
3. Implement the Rust client, facilitator, price tag, and Axum flow.
4. Implement the TypeScript BCH mechanism package against `@x402/core`.
5. Run both SDKs against the same fixtures and mocked provider scenarios.
6. Run Chipnet-only end-to-end tests with non-production test funds.
7. Publish integration examples, unsupported-feature limitations, and the
   compatibility matrix.

Only after these gates should the integration be presented as suitable for
general third-party use.
