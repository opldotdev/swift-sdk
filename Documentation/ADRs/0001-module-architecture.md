# ADR-0001: Feature modules with a consensus spine

- Status: Accepted
- Date: 2026-08-07
- Owners: Open Protocol Labs

## Context

A direct translation of Go package boundaries creates conceptual cycles among
scripts, transactions, templates, and the interpreter. The SDK also needs one
convenient import without making the entire implementation one compiler unit.

## Decision

Use compiler-enforced feature modules with this spine:

`BSVCore -> BSVBigNum -> BSVCrypto -> BSVKeys -> BSVScript ->
BSVTransaction -> BSVInterpreter -> BSVSPV -> BSVNetwork -> BSVWallet`.

`BSVAuth` sits above wallet/network functionality. `BSVServices` sits above
Auth because identity and storage require authenticated certificate/fetch
flows. Wallet-backed PushDrop adapters live in Wallet while
transaction-neutral PushDrop encoding and signing live in Transaction.
`ChainTracker` and `Broadcaster` protocols belong to `BSVTransaction`; concrete
clients belong to `BSVNetwork`. `BSVBigNum` is internal and shared by Crypto
and Script.

## Consequences

The package has more targets, but dependency direction and consensus boundaries
are compiler enforced. Overlay and application services remain combined until
their APIs stabilize.

## Verification

Fable architecture review dated 2026-08-07 and P256K source audit.
