# COMP-060: BRC-103 certificate exchange

## Decision

`BSVAuth` supports signed certificate-request and certificate-response messages.
A request contains a nonempty bounded set of certifiers and a bounded map of
certificate types to field names. The map and each field list may be empty, as
in `@bsv/sdk` 4.1.1 (`AuthMessageValidation.ts:122`). A response is an
allowlist answer to the pending request: each certificate must have a requested
certifier and type and reveal a nonempty subset of that type's fields. A
response may contain no certificates (`Peer.ts:359-389`, `Peer.ts:1117`).

Certificate messages carry the sender's session nonce in `initialNonce`
(`AuthMessageValidation.ts:404`, `:415`). Swift sends it and requires it to
equal the session nonce it holds for the peer.

A certificate policy in a received `initialRequest` or `initialResponse` is
returned as a certificate-request action (`Peer.ts:644-650`, `Peer.ts:866-875`).
A handshake policy without certifiers means no request. A certificate-request
message without certifiers is rejected; TypeScript accepts one, but it asks for
nothing. The peer may answer a handshake request before the other side sends
its first signed message. A policy in `initialRequest` is unsigned, so answer
it only with wallet-proved keyrings, which are encrypted to the claimed
identity.

`PeerAuthenticator` verifies the peer message signature and correlates one
response with one pending request. This verification does not establish
certificate trust. The caller must use `AuthCertificateExchange.validate` to
verify each BRC-52 certificate, bind the subject to the peer, decrypt every
requested field, and apply its own trust and revocation policy.

The wallet preparation helper lists certificates and proves exactly the
requested fields for the verifier. It fails unless it can satisfy every
requested certificate type. `AuthCertificateExchange.validate` also requires
every requested field. Both are caller policy; the wire accepts subsets.

## Compatibility

Canonical certificate responses reencode through Go SDK v1.3.3. Requested
certificate sets do not: pinned Go emits uppercase `Certifiers` and
`CertificateTypes`, loses the `types` field lists from canonical lowercase
input, and signs different JSON bytes. GO-066 records the defect. The
differential oracle preserves those raw bytes and uses a test-only schema
adapter for semantic comparison. Production Swift does not accept the
uppercase aliases.

Swift requires canonical padded Base64, lowercase compressed-key and DER hex,
unique certifiers and fields, complete JSON consumption, low-S signatures, and
explicit resource limits.

The signed text is the JSON the sender wrote, in its member order
(`Peer.ts:453`, `Peer.ts:1142`). Swift verifies a received request over
`JSON.stringify` of the received value (`Peer.ts:1070`). It verifies a received
response over each certificate rebuilt in the order `type`, `serialNumber`,
`subject`, `certifier`, `revocationOutpoint`, `fields`, `signature`, `keyring`,
with `fields` and `keyring` in received order (`Peer.ts:341-357`,
`Peer.ts:1205`). Strings are escaped as `JSON.stringify` escapes them: `"`,
`\`, the short escapes for backspace, tab, line feed, form feed and carriage
return, and other control characters as lowercase `\u00xx`. `&`, `<`, `>`,
U+2028 and U+2029 are not escaped. When Swift sends, it writes certificate
types, fields and keyring entries in UTF-8 byte order, with array-index names
first as JavaScript orders them, and puts the same bytes on the wire.

Swift ignores certificates that arrive in `initialResponse`. The certificate
trust decision stays with the caller through the signed certificate-response
message.

The BRC-104 requested-certificate HTTP header remains unavailable. The Go
transport does not bind that header to the signed general-message payload. A
caller must use the signed BRC-103 certificate-request message.

## Exclusions

This ruling does not add a concrete HTTP or WebSocket transport, AuthFetch,
automatic payment, persistent trust policy, or chain-aware revocation lookup.

## Changes for `@bsv/sdk` 4.1.1

The earlier form of this ruling required an exact response to an exact
request, signed byte-sorted JSON while writing the wire with Foundation
`.sortedKeys`, escaped `&`, `<`, `>`, U+2028 and U+2029, omitted
`initialNonce`, and rejected certificate policies in the handshake. Each of
these broke certificate exchange with TypeScript in one direction or both:

- TypeScript signs and verifies JSON in member order, so a TypeScript request
  or response that was not byte-sorted failed in Swift.
- On Linux, Foundation `.sortedKeys` orders `aWlp…` before `Z2dn…`; byte order
  is the reverse. A Swift request with such types failed in TypeScript.
  `TypeScriptInteropTests.foundationSortedKeysOrder` records this.
- TypeScript rejects certificate messages without `initialNonce`.
- TypeScript answers a request with any allowed subset, including none.

`TypeScriptAuthVectors.md` lists the vectors and the check of Swift messages
against a live TypeScript peer.
