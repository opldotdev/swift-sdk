# COMP-056: Bounded transport-neutral key-value token core

Pinned Go `kvstore` combines a portable one-field PushDrop value with wallet
output queries, action creation and signing, BEEF resolution, optional wallet
encryption, local mutexes, and assumptions about output ordering.

`BSVKVStore` retains only the independently meaningful token: one nonempty raw
byte field under a compressed public-key PushDrop lock in Go's explicit
`beforeCompatibility` layout. It provides bounded immutable locator and token
values plus a strict codec. A locator represents the future wallet basket/tag
pair but is not presented as data committed by the locking script.

The package deliberately excludes `LocalKVStore`, wallet actions, BEEF,
encryption, newest-value selection, persistence, retention, overlay discovery,
and network transport. Those need later packets with an explicit wallet
authority, storage/conflict policy, and transport boundary.

The valid one-field script format remains compatible with pinned Go v1.3.3.
GO-027 through GO-035 record confirmed Go implementation defects that Swift
does not reproduce.
