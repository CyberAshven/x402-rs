# x402-chain-bch

Bitcoin Cash native exact payment support for x402.

The BCH chain IDs exposed by this crate are:

| Network | Chain ID |
| --- | --- |
| Mainnet | `bch:bitcoincash` |
| Chipnet | `bch:bchtest` |

The references are the CashAddr network prefixes used by BCH integrations.
They are not derived from the Bitcoin/BCH genesis block or fork height.

The initial implementation supports finalized P2PKH transactions carrying
native BCH. It uses BCH `SIGHASH_ALL | SIGHASH_FORKID` (`0x41`), one exact
merchant output, an optional non-dust P2PKH change output, and a minimum fee of
1 satoshi per serialized byte. CashTokens, CashScript, PSBT, sponsorship, and
non-P2PKH scripts are intentionally outside this scheme boundary.

`FulcrumProvider` implements the Electrum Cash JSON-RPC boundary used by
Fulcrum. The local BCH node/indexer reference checkout is
`/home/lightswarm/projects/fulcrum`; applications may supply a TLS or
WebSocket transport through the `FulcrumTransport` trait.

The adapter accounts for Fulcrum's two amount encodings: verbose transaction
outputs are BCH decimal values, while blockchain.scripthash.listunspent returns
integer satoshis.

The crate test suite includes `test/fixtures/bch-exact-p2pkh.json`, a
deterministic native-BCH P2PKH payment fixture shared with the TypeScript
`@x402/bch` implementation. It covers the serialized transaction, source
output, merchant amount, payer, transaction ID, and fee so integrations can
compare results across both SDKs.

```rust,ignore
use x402_chain_bch::{BchChainReference, FulcrumProvider, FulcrumTcpTransport, V2BchExact};
use x402_types::scheme::X402SchemeFacilitatorBuilder;

let transport = FulcrumTcpTransport::connect("127.0.0.1:50002").await?;
let provider = FulcrumProvider::new(transport, BchChainReference::CHIPNET);
let facilitator = V2BchExact.build(provider, None)?;
```
