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

This core packet added no wire codec. COMP-061 adds the bounded HTTP formats,
deterministic resolver, and one-shot broadcaster without changing these core
value rules.

## @bsv/sdk 4.1.1 alignment

Live overlay hosts run `@bsv/sdk` 4.1.1 (ts-stack `3b1abc569`). These core rules
now follow it:

- Topic and service names use the `@bsv/sdk` grammar (`overlay-tools/OverlayNames.ts`):
  `tm_` or `ls_`, then lowercase ASCII letters and digits in segments joined by
  single underscores, 256 bytes at most. The earlier rule allowed uppercase,
  repeated or trailing underscores, and longer names that TS hosts reject.
- A lookup output may carry the optional `context` bytes and `txid` that TS
  hosts return. `OverlayLimits.maximumLookupContextByteCount` (1 MiB by default)
  bounds each context, and the aggregate answer limit counts context bytes.
