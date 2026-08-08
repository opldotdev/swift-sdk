# ADR 0005: Transaction values and ancestry graphs

- Status: Accepted
- Date: 2026-08-07

## Context

The pinned Go SDK stores transactions as mutable pointer graphs. An input may
point directly to its complete source transaction or to a cached source output.
BEEF and Atomic BEEF traverse and deduplicate that graph. Directly reproducing
those references in Swift would introduce aliasing, cycles, custom cloning,
and concurrency isolation into the lowest transaction wire model.

At the same time, transaction signing needs the spent output's satoshi amount
and locking script, while BEEF needs complete ancestry and Merkle paths.

## Decision

`Transaction`, `TransactionInput`, `TransactionOutput`, and `Outpoint` are
`Hashable`, `Sendable` value types. An input may carry an optional
`sourceOutput` value for signing and fee calculation. That hydration metadata
is not serialized and does not participate in equality or hashing; adding
known source information cannot change the identity of otherwise equal wire
transactions.

Construction-only fee metadata follows the same rule: unsigned inputs may
carry an unlocking-script size estimate and outputs may be marked as change.
Neither marker participates in wire serialization, equality, or hashing.

Complete source transactions are not recursively embedded in inputs. The BEEF
packet will introduce an explicit graph/store keyed by `TransactionID` and
will pass that store or a resolver into ancestry-dependent operations. The
store owns deduplication, missing-parent handling, and proof association.
Ordinary transaction parsing and serialization remain independent of graph
state.

Arrays and scripts use Swift copy-on-write value semantics. A transaction copy
therefore needs no public clone API and cannot silently mutate through another
reference. Mutable workflows use local `var` values or a higher-level owner;
the consensus model itself does not require locks or actor isolation.

## Consequences

- Raw transaction APIs remain deterministic, easily `Sendable`, and free of
  cycles or shared mutable identity.
- Sighash can read `sourceOutput` directly without knowing the ancestry store.
- BEEF and Atomic BEEF APIs must make their graph dependency explicit.
- Equality describes wire-semantic input identity, not the completeness of
  locally attached source metadata.
- Go pointer identity and mutation order are not compatibility promises; wire
  bytes, transaction IDs, ancestry contents, and observable protocol results
  are.

## Review evidence

The Fable transaction-foundation review accepted this choice before the public
API shipped and specifically required equality semantics to be frozen at this
boundary. Unit tests verify that source hydration changes neither wire bytes,
equality, nor hashing.
