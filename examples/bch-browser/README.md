# Browser BCH exact payment

This page signs a Chipnet-shaped exact payment with the same Rust client used
by native callers. The page supplies a JavaScript Fulcrum transport. The Rust
client selects the UTXO, builds the transaction, checks the serialized fee and
dust, and verifies the signature before returning.

The mnemonic is the public BIP39 test vector. The merchant address is the
chipnet CashAddr for the same 20-byte hash used by the native tests. The
transport returns one local UTXO and rejects every other method, including
broadcast.

An omitted CashToken `tokenOutputValue` defaults to 1,000 satoshis in this
client. Native outputs keep the 546-satoshi dust floor.

Build the package from the repository root, with Clang available:

```bash
wasm-pack build crates/chains/x402-chain-bch --target web --out-dir ../../../examples/bch-browser/pkg
```

Serve this directory over HTTP and open `index.html`. A successful page sets
`document.documentElement.dataset.status` to `ok`.
