# x402-chain-bch

Bitcoin Cash network identity support for x402.

The BCH chain IDs exposed by this crate are:

| Network | Chain ID |
| --- | --- |
| Mainnet | `bch:bitcoincash` |
| Chipnet | `bch:bchtest` |

The references are the CashAddr network prefixes used by BCH integrations.
They are not derived from the Bitcoin/BCH genesis block or fork height.

This crate currently provides the typed network identity used by the BCH x402
implementation. Transaction construction, BCH sighash handling, UTXO
selection, and facilitator validation should build on this identity without
accepting untyped or legacy BCH network aliases.
