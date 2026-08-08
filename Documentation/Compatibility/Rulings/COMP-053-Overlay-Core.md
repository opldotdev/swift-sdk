# COMP-053: Bounded transport-neutral overlay core

## Decision

`BSVOverlay` owns the SHIP and SLAP value vocabulary: protocol and network
identifiers, tagged BEEF, topic acknowledgments, typed topic and lookup names,
metadata, and bounded opaque lookup values. It also defines narrow async
facilitator protocols for a caller-selected endpoint.

The module accepts only typed byte payloads. It does not use type erasure for
Go's `any` fields, mutable callback closures for formulas, or default global
HTTP clients. Every public variable-size value has an explicit caller-owned
limit.

## Go differences

Pinned Go combines core values with HTTP facilitators, mutable resolver maps,
hard-coded trackers, and a wallet-backed PushDrop admin token. The Go formula
and freeform result fields use `any`, while the formula history callback captures
mutable BEEF state. Those facilities require separate transport, trust, wallet,
and persistence decisions, so this packet does not expose partial success
implementations for them.

Swift rejects duplicate topics, output dependencies, instruction indexes, and
ancillary transaction IDs. It applies count and byte limits before it stores
each caller-owned collection. One lookup answer also has an aggregate BEEF byte
limit.

This packet adds no wire codec. It does not claim byte-level parity for Go JSON
or binary HTTP responses. A later transport packet must define and test those
formats before it sends or accepts network data.
