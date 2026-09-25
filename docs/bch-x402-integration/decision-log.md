# BCH x402 decision log

This log records the reasoning accumulated across the design prompts. It is a
design history, not a transcript of every message. New protocol decisions must
be appended rather than silently rewriting an earlier decision.

## Iteration 1 — canonical x402 versus the community BCH implementation

The community `x402-bch` project was identified as the likely source of the
existing BCH implementation, but it was not treated as authoritative. Its
documented flow uses an initial batch payment followed by later off-chain
debits. That is materially different from canonical x402 `exact`, where the
payment requirement describes the payment settled for the request.

Decision: use the canonical x402 v2 transport and scheme extension points as
the authority. The community batch/debit design may be evaluated later as a
separate BCH-specific mechanism, but it must not define BCH `exact` behavior.

## Iteration 2 — x402-rs as the implementation target

The implementation scope was narrowed to `/mnt/hdd/projects/x402-rs`. BCH
transaction behavior is to be learned from `/mnt/hdd/projects/libauth`, but
libauth's TypeScript architecture is not to be copied into Rust.

Decision: create an independent Rust chain crate, `x402-chain-bch`, using
libauth for behavioral reference and cross-implementation vectors.

## Iteration 3 — UTXO adaptation

The account-model chains in x402-rs authorize transfers using chain-specific
signatures or signed transaction objects. BCH has no account nonce, ERC-20
allowance, or facilitator fee-payer primitive in a normal native BCH spend.

Decision: the first BCH payment payload will contain a complete signed BCH
transaction. The facilitator will fetch and validate source outputs, verify the
transaction, and broadcast that same transaction. The facilitator must not
rewrite the transaction or append inputs after the client signs it.

## Iteration 4 — first scheme and scope

The first useful parity target is v2 `exact` for native BCH. V1 adds a second
network vocabulary and `upto` requires a revocable authorization model that a
plain BCH transaction does not provide.

Decision: implement v2 `exact` first; defer V1, `upto`, facilitator fee
sponsorship, CashTokens, and arbitrary covenant execution.

## Iteration 5 — network identity correction

An initial working assumption was `bch:mainnet` / `bch:chipnet`. OPTN source
verification showed that its current WalletConnect mapping is:

```text
mainnet -> bch:bitcoincash
chipnet -> bch:bchtest
```

The requirement was then corrected to use `bitcoincash`, not `mainnet`.

Decision: BCH identities are `bch:bitcoincash` and `bch:bchtest`. The typed
identity layer rejects `bch:mainnet`, `bch:chipnet`, legacy aliases, and
`bip122:*` identifiers. The source of truth is
`/mnt/hdd/projects/OPTNWallet/src/redux/walletconnect/constants.ts`.

## Iteration 6 — parity review

The integration must provide the same x402 client/server/facilitator lifecycle
as the existing chain crates, but transaction correctness is BCH-specific.
The high-risk portion is not HTTP integration; it is source-UTXO binding,
BCH signing serialization, value conservation, exact payment-output matching,
replay handling, and double-spend races.

Decision: phase the work so transaction primitives and security invariants are
complete before the HTTP-facing client and facilitator are advertised as
usable.

## Current decisions that are still provisional

The following are recommendations awaiting explicit confirmation or an
implementation-time decision recorded here:

- Represent the native asset as `BCH`, with
  `extra.assetTransferMethod = "native"`.
- Use settle-before-resource execution for the first BCH deployment.
- Support standard P2PKH inputs and CashAddr recipients first.
- Fetch source outputs from the facilitator's chain provider, rather than
  trusting source-output data supplied by the client.
- Use BCH `0x61` (`ALL | FORKID | UTXOS`) for client signatures.
- Treat mainnet/chipnet as public identities and add a separate local test
  identity only if the test harness needs one.
- Reject CashToken-bearing transactions until token conservation is implemented.
