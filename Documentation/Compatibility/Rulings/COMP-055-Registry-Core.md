# COMP-055: Bounded registry core

Pinned Go registry functionality couples its definition values to mutable client
configuration, default network selection, wallet transactions, and overlay HTTP
work. It also exposes an open definition interface and a production mock.

`BSVRegistry` retains the three definition categories, exact
`beforeCompatibility` PushDrop field order, registry records, and typed query
vocabulary. It uses immutable `Sendable` values, explicit limits, canonical
byte-sorted certificate maps, and injected narrow lookup or publisher protocols.

The package deliberately excludes default trackers, HTTP, overlay discovery,
wallet register/revoke/list-own orchestration, persistence, factory setters,
and production mocks. Those capabilities need separate packets with explicit
transport and authority rules.
