# BCH x402 open decisions

These are the decisions to confirm before the implementation crosses the wire
compatibility boundary. The defaults are recommendations, not hidden choices.

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
CashScript should be separate milestones.

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

## 8. Payer reporting

Recommended default: report a deterministic address derived from the first
valid P2PKH input as an informational payer value. Security checks must validate
all inputs independently and must not rely on the reported payer string.

## 9. Fee sponsorship

Recommended default: client pays its own fee. Do not allow facilitators to
append inputs or mutate a signed transaction. Sponsorship requires a separately
specified sighash and signing protocol.
