# COMP-055: Bounded registry core

Pinned Go registry functionality couples its definition values to mutable client
configuration, default network selection, wallet transactions, and overlay HTTP
work. It also exposes an open definition interface and a production mock.

`BSVRegistry` retains the three definition categories, exact
`beforeCompatibility` PushDrop field order, registry records, and typed query
vocabulary. It uses immutable `Sendable` values, explicit limits, canonical
byte-sorted certificate maps when it writes, and injected narrow lookup or
publisher protocols.

The package deliberately excludes default trackers, HTTP, overlay discovery,
wallet register/revoke/list-own action orchestration, persistence, factory setters,
and production mocks. Those capabilities need separate packets with explicit
transport and authority rules.

## TypeScript 4.1.1 token alignment (2026-11-16)

Live overlay hosts run the TypeScript `tm_basketmap`, `tm_protomap`, and
`tm_certmap` topic managers, which call `decodeAndVerifyRegistryToken`
(`packages/sdk/src/registry/registryTokenValidation.ts`). The TypeScript wire
format wins:

- A token has the 6 (basket, protocol) or 7 (certificate) data fields in the
  existing order, followed by one DER signature field: 7, 7, or 8 fields.
  Unsigned 6/6/7-field tokens, which Swift used to write, are rejected.
- The protocols are `[1, "basketmap"]`, `[1, "protomap"]`, and
  `[1, "certmap"]`, key ID `"1"`. Swift used security level 2.
- The locking key must be the "anyone" key's BRC-42 view of the registry
  operator (the last data field), and the signature over the concatenated
  data fields must verify under it. TypeScript creates tokens with
  `pushdrop.lock(fields, protocol, "1", "anyone", true)`.
- `RegistryDefinitionCodec.lockingScript(for:using:limits:)` now signs through
  the wallet's key and signature capabilities, as `IdentityClient` does. The
  wallet identity must be the operator, and no data field may be empty: an
  empty field is written as `OP_0` and read back as `[0]`, so its signature
  can never verify (TypeScript has the same limit). The unsigned
  `lockingScript(for:publicKey:limits:)` is removed.
- Embedded certificate-field JSON is decoded in any key order or spacing, as
  TypeScript `JSON.parse` does. Each descriptor must have exactly the keys
  `friendlyName`, `description`, `type`, and `fieldIcon`. Swift still writes
  its canonical byte-sorted form. The protocol ID field keeps its canonical
  check: TypeScript writes it with `JSON.stringify`, which yields the same
  bytes for every name Swift's protocol-ID profile accepts.
- `RegistryLimits` now requires `pushDropLimits.maximumFieldCount >= 8`.

Swift keeps its larger per-field text limits; they accept everything
TypeScript writes.
