# ADR-0001: Feature modules with a consensus spine

- Status: Accepted
- Date: 2026-08-07
- Owners: Open Protocol Labs

## Context

A direct translation of Go package boundaries creates conceptual cycles among
scripts, transactions, templates, and the interpreter. The SDK also needs one
convenient import without making the entire implementation one compiler unit.

## Decision

Use compiler-enforced feature modules. The consensus path is `BSVCore ->
BSVBigNum -> BSVCrypto -> BSVKeys -> BSVScript -> BSVTransaction ->
BSVInterpreter`. SPV depends on Core, Crypto, Transaction, and Interpreter. Network
depends on Core, Transaction, and SPV so concrete header services can expose
the canonical block-header values. Wallet depends on Core, Crypto, Keys,
Script, and Transaction.

`BSVMessage` depends only on Core, Crypto, and Keys. It owns BRC-77 and BRC-78
portable messages. `BSVAuth` sits above Wallet and owns certificates and future
authentication sessions. Wallet-backed PushDrop adapters live in Wallet while
transaction-neutral PushDrop encoding and signing live in Transaction.
`ChainTracker` and `Broadcaster` protocols belong to `BSVTransaction`; concrete
clients belong to `BSVNetwork`. `BSVBigNum` is internal and shared by Crypto
and Script.

`BSVCompat` is a public opt-in feature module. It depends on Core, Crypto, and
Keys, but it is outside the modern dependency spine. It contains Bitcoin Signed
Message, Electrum and Bitcore ECIES, BIP-32, and BIP-39 compatibility APIs.
The `BSV` umbrella does not depend on or re-export `BSVCompat`.

## Consequences

The package has more targets, but dependency direction and consensus boundaries
are compiler enforced. Applications opt in to compatibility APIs separately.
Future service APIs must use named modules when their boundaries stabilize.

## Verification

Fable architecture review dated 2026-08-07 and P256K source audit.
