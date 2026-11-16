# COMP-060: BRC-103 certificate exchange

## Decision

`BSVAuth` supports signed certificate-request and certificate-response messages.
A request contains a bounded set of certifiers and a bounded map of
certificate types to field names. The certifier set, the map and each field
list may be empty, as in `@bsv/sdk` 4.1.1 (`AuthMessageValidation.ts:122`,
`:134-136`). A request with no certifiers asks for nothing: Swift sends it
without awaiting an answer, and a received one authenticates the sender and
needs no answer (`Peer.ts:1097-1100`).

A response is an allowlist answer to an open request: each certificate must
name the responder as subject, have a requested certifier and type, and reveal
a nonempty subset of that type's fields. A response may contain no
certificates (`Peer.ts:359-389`, `Peer.ts:1117`).

Certificate messages carry the sender's session nonce in `initialNonce`
(`AuthMessageValidation.ts:404`, `:415`). Swift sends it and requires it to
equal the session nonce it holds for the peer.

### Open requests

Each direction of a session may have up to 16 open certificateRequests at
once, as `Peer.ts:474-478` keeps one per request nonce, besides a handshake
policy. A seventeenth request, sent or received, fails with
`AuthError.resourceLimit` and leaves the session open. The open requests a
peer has sent are also charged together against
`AuthLimits.maximumCertificateAggregateBytes` (33 bytes per certifier, and
32 per type plus its field names), so one authenticated peer can make a
session hold no more than one request may hold. A received request identical
to one already open fails with `AuthError.unexpectedMessage`.

A response does not name the request it answers. As in `Peer.ts:1229-1241`,
its signature is verified first; it then settles the oldest certificateRequest
it fits and the handshake policy only if none fits. An empty response declines
the oldest open request in the same order, where `@bsv/sdk` leaves its
requests open (`Peer.ts:1229`); a TypeScript `Peer` without certificates sends
one empty response per request (`Peer.ts:1117`), so the two stay in step.
`makeCertificateResponse(_:using:answering:)` can name the request being
answered on the sending side only: the peer still settles the first of its
own requests the certificates fit. A response that fits no open request, or
arrives when none is open, is refused.

### Handshake policies

A certificate policy in a received `initialRequest` or `initialResponse` is
returned as a certificate-request action (`Peer.ts:644-650`, `Peer.ts:866-875`).
A handshake policy without certifiers means no request. The peer may answer a
handshake request before the other side sends its first signed message. A
policy in `initialRequest` is unsigned, so answer it only with wallet-proved
keyrings, which are encrypted to the claimed identity.

Swift sends a policy in the same places. `beginAuthentication(requesting:)`
puts one in `initialRequest`. `PeerAuthenticator(certificatesToRequest:)` sets
a policy that a responder puts in every `initialResponse` and that an
initiator uses when `beginAuthentication` names none. A TypeScript `AuthFetch`
client answers a responder policy on its own with a `certificateResponse`
(`AuthFetch.ts:496-511`); Swift returns that as a certificate-response action.
Certificates a peer includes in `initialResponse` are checked against the
policy Swift sent and returned as a certificate response, and are ignored when
none was sent. They are not covered by any signature (`Peer.ts:960-982`).

`@bsv/sdk` holds general messages until its handshake policy is answered
(`Peer.ts:1326-1328`). Swift delivers them; holding them is caller policy.

### Validation

`PeerAuthenticator` verifies the peer message signature and correlates each
response with one open request. This does not establish certificate trust.
The caller validates the certificates with `AuthCertificateExchange`:

- `validate` requires every requested type and every requested field of each
  certificate. It fails when given no certificates.
- `validateSubset` accepts what `validateCertificates` in `@bsv/sdk` accepts
  (`validateCertificates.ts:23-29`): a nonempty subset of the requested fields
  for each certificate, with requested types allowed to be missing. Like
  `validateCertificates.ts:74`, it fails when given no certificates. The
  caller decides whether what was disclosed is enough.

Both verify each BRC-52 signature, bind the subject to the peer, decrypt every
revealed field, and fail as a whole when any certificate fails. The caller
still applies its own trust and revocation policy.

The wallet preparation helper lists certificates and proves exactly the
requested fields for the verifier. It fails unless it can satisfy every
requested certificate type.

### Errors

Errors stay short and name no side, so the same text fits Swift as client or
server. The detailed cause of a refused message or certificate, such as the
underlying `BRC104Error`, JSON or certificate decoding error, or which
certificate failed which check, is written to the system log on Apple
platforms through `os.Logger` with subsystem `dev.opl.swift-sdk` and category
`BSVAuth`. The reasons `BSVAuth` writes hold no certificate field value,
keyring, nonce or signature. An underlying error defined by this SDK is logged
in full; any other, such as one from a caller's wallet, is public by type only
and its description is marked private.

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

The BRC-104 `x-bsv-auth-requested-certificates` header is read and written
(COMP-059) but not acted on, as `Peer.processGeneralMessage` does not act on
it. Neither the Go nor the TypeScript transport binds that header to the
signed general-message payload, so a caller asks with the signed BRC-103
certificate-request message or a handshake policy.

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
- TypeScript keeps several requests open and sends a responder policy in
  `initialResponse`, which `AuthFetch` answers on its own.

`TypeScriptAuthVectors.md` lists the vectors and the check of Swift messages
against a live TypeScript peer.
