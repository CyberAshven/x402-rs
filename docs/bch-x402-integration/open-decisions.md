# BCH x402 open decisions

These are the decisions to confirm before the implementation crosses the wire
compatibility boundary. The defaults are recommendations, not hidden choices.

## POC versus long-term interoperability

The first proof of concept is intentionally narrow: native BCH, standard
P2PKH inputs, CashAddr recipients, and a finalized signed transaction as the
payment payload. Those limits are staging boundaries, not permanent protocol
limits.

The implementation should keep a script-, UTXO-, and asset-first internal
model so that later work can add CashTokens, additional BCH address encodings,
and PSBT signing/interchange without changing the meaning of the initial
native-BCH wire contract.

## 1. Native asset spelling

Recommended default: use:

```json
{
  "asset": "BCH",
  "extra": {
    "assetTransferMethod": "native"
  }
}
```

Rationale: the network already identifies BCH, while `BCH` is clear to
developers and matches the native-symbol style used by other x402 scheme
specifications. The implementation should accept exactly one spelling.

## 2. Settlement timing

Recommended default: BCH exact uses settle-before-resource execution.

Rationale: `/verify` cannot reserve a UTXO. A payer can double-spend an input
between verification and settlement. Broadcasting before resource execution
provides a stronger guarantee than a verify-only authorization flow.

## 3. Confirmation threshold

Recommended default: make the threshold configurable, with `mempool accepted`
as an explicit low-latency mode and at least one confirmation as the conservative
production mode.

The settlement response must distinguish confirmed, mempool-only, and pending
states. A transport error after broadcast must not cause an unsafe blind retry.

## 4. Initial script scope

Recommended default: standard P2PKH only, with multiple inputs allowed.

This permits independent BCH signature verification without pretending to
support arbitrary CashScript or covenant semantics. P2SH, P2SH32, and arbitrary
CashScript should be separate milestones. Additional address encodings may be
accepted in a later phase, but they must resolve to a validated locking script
before transaction policy checks are performed.

## 5. Source-output transport

Recommended default: the client sends only the signed transaction; the
facilitator fetches source outputs from its configured provider.

Client-supplied source outputs may be useful as a cache hint, but must never be
authoritative. If they are added later, the facilitator must compare them with
chain data.

## 6. Local test identity

Recommended default: keep public identities limited to `bch:bitcoincash` and
`bch:bchtest`, and configure local tests through an explicit test-provider mode.

If a public wire identity for regtest is needed, add it only after verifying the
BCH ecosystem convention and record it as a new decision. Do not invent
`bch:mainnet` or `bip122:*` aliases for convenience.

## 7. CashTokens

Recommended default: reject token-bearing inputs and outputs in native BCH
exact until token conservation and successor-output validation are implemented.

Parsing a CashToken prefix is not equivalent to proving token correctness.
The future asset model must keep BCH value and token state separate, including
fungible amounts, NFT commitments and capabilities, genesis rules, and
successor-output requirements. A token-aware address must not silently turn a
token payment into a native-BCH payment or vice versa.

## 8. Payer reporting

Recommended default: report a deterministic address derived from the first
valid P2PKH input as an informational payer value. Security checks must validate
all inputs independently and must not rely on the reported payer string.

## 9. Fee sponsorship

Recommended default: client pays its own fee. Do not allow facilitators to
append inputs or mutate a signed transaction. Sponsorship requires a separately
specified sighash and signing protocol.

## 10. Address format extensibility

Recommended default: treat addresses as input/output encodings at the API
boundary, then normalize them to an internal network-qualified locking script
plus any explicit token metadata.

The POC should use CashAddr, but future support may include legacy Base58
addresses, token-aware CashToken addresses, and other BCH ecosystem formats.
The parser must validate the network, address type, checksum, payload length,
and token metadata before producing a script. Network or asset identity must
never be inferred from a text prefix alone, and serializing an address must not
discard token information.

## 11. PSBT support

Recommended default: keep the initial x402 payment payload as a finalized raw
transaction. Add PSBT as a wallet and signing interchange format, not as an
alternative settlement object, until BCH-specific PSBT semantics are defined.

Future PSBT support should cover unsigned transaction data, authoritative
source outputs, BCH sighash metadata, partial signatures, hardware-wallet
signing, finalization, and preservation of unknown/proprietary fields. The
facilitator should validate the finalized transaction using the same rules
regardless of whether the client assembled it directly or finalized it from a
PSBT. A PSBT should not be accepted for settlement merely because it can be
parsed; it must produce the exact signed transaction being verified and
broadcast.
