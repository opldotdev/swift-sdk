# COMP-056: Bounded transport-neutral key-value token core

> **Superseded in part (2026-11-16).** The one-field token described in the
> next three paragraphs is no longer read or written. Swift now uses the
> two-field signed TypeScript 4.1.1 token and can sign it through a wallet;
> see "TypeScript 4.1.1 token alignment" below. Swift no longer reads or
> writes the pinned Go v1.3.3 one-field token. The original text is kept for
> history.

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

## TypeScript 4.1.1 token alignment (2026-11-16)

TypeScript `LocalKVStore` (`packages/sdk/src/kvstore/LocalKVStore.ts`) now
reads only two-field tokens: the value and a signature over the value, with
`decodeCanonicalPushDrop(..., { fieldCount: 2 })` and
`verifySignature(..., counterparty: "self")`. It writes them with
`pushdrop.lock([value], [2, context], key, "self")`. A one-field Go or Swift
token is no longer readable by TypeScript, so the TypeScript wire format wins:

- `KVStoreTokenCodec` reads and writes exactly two fields. One-field tokens
  are rejected with `invalidTokenFieldCount(actual: 1)`.
- `KVStoreToken` carries the signature and its initializer checks it against
  the locking key. Decoding checks the same, with a strict DER signature of at
  most 72 bytes.
- `KVStoreTokenCodec.lockingScript(value:locator:using:limits:)` writes a
  token through the wallet's key and signature capabilities with protocol
  `[2, context]`, key ID `key`, counterparty self.
  `decode(_:locator:using:limits:)` also checks that the locking key is the
  wallet's key for the locator, as TypeScript does before it trusts an output.
- The standard value limit is 2 MiB, the TypeScript `MAX_LOCAL_TOKEN_BYTES`,
  so encrypted values near the 1 MiB plaintext limit stay readable.

- Like TypeScript, verification has no low-S rule: a high-S signature from
  another wallet verifies. The DER encoding must still be strict.
- The locator's wallet protocol and key ID conversions throw
  `KVStoreError.invalidWalletLocator` when the wallet grammar refuses the
  context or key (for example a context under 5 characters).

The rest of this ruling stands: wallet signing is the only wallet use; there
are still no wallet actions, BEEF, encryption, newest-value selection,
persistence, or transport.
