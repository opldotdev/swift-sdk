# COMP-052: BRC-103 and BRC-104 core

Status: Accepted

## Scope

This ruling covers the transport-neutral BRC-103 message codec and peer
authentication state. It also covers the BRC-104 request and response payload
codec.

HTTP clients, HTTP servers, and WebSocket transports are outside this scope.
COMP-060 covers signed certificate exchange.

## Decision

Swift emits BRC-103 version `0.1`. It rejects unknown versions. The strict JSON
codec rejects duplicate and unknown object members, invalid UTF-8, lone
surrogates and excessive nesting before Foundation decodes the document. It
requires canonical compressed public keys, canonical Base64 nonces, complete
low-S DER signatures, and explicit JSON and payload limits. Swift writes the
message JSON itself, so certificate data on the wire is byte-identical to the
text it signs (COMP-060).

The peer authenticator uses an injected wallet, secure random source, and
clock-based session timeout. It binds an expected peer identity, rejects nonce
reuse and message replay, limits sessions and accepted messages, and checks
cancellation around each wallet call. A responder remains unauthenticated
until it verifies the first signed general, certificate-request or
certificate-response message from the initiator.

Every session nonce Swift creates, as initiator or responder, is 48 random
bytes in canonical padded Base64 (64 characters). Message nonces are 32 bytes.
Swift accepts 32-byte and 48-byte session nonces from peers and propagates
random-source failures. It does not accept the other variable nonce lengths
that the pinned Go verifier accepts.

The BRC-104 codec is transport-neutral. It binds a 32-byte request identifier
to the method, path, optional query, selected headers, body, or response status.
It uses canonical CompactSize values and explicit payload and header limits.
It excludes every header whose name starts with `x-bsv-auth` from the signed
payload, as `AuthFetch.ts:727` does, rejects duplicate headers, and sorts the
lowercase selected header names in `localeCompare` order (`AuthFetch.ts:740`).
That order differs from the Go SDK's UTF-8 byte order only where names differ
at a `_`: `localeCompare` puts `x-bsv-a_b` before `x-bsv-a-b`, `x-bsv-a1` and
`x-bsv-ab`, and byte order puts it after them. A signed header value must be
printable ASCII without leading or trailing spaces, because `fetch` trims
values and reads them as Latin-1 before a TypeScript client rebuilds the
payload; Swift refuses other values rather than sign bytes the peer will not
see.

An absent or empty body is written as -1, never 0, in requests and responses.
When a client encodes a POST, PUT, PATCH or DELETE request with an absent body
and a `content-type` containing `application/json`, it signs and sends `{}`.
An empty body stays empty. A server rebuilding a received request never adds
`{}`. A `multipart/form-data` content type is signed whole, with its boundary;
any other content type is cut at the first `;` and trimmed.

## Go SDK defects

The separate Go SDK defect report records the related pinned defects:

- GO-006: nonce generation discards random-source failure.
- GO-007: nonce verification accepts noncanonical HMAC lengths.
- GO-008: a responder authenticates an unsigned initial request.
- GO-009: the handshake does not enforce the expected peer identity.
- GO-066: requested-certificate JSON does not match BRC-103.

Swift does not reproduce these defects. Shared messages other than requested
certificate sets remain interoperable through the pinned Go oracle. COMP-060
records the requested-certificate wire incompatibility.

## Changes for `@bsv/sdk` 4.1.1

TypeScript `@bsv/sdk` 4.1.1 is the reference peer. Where this ruling and that
SDK disagreed on the wire, Swift now follows the SDK:

- A responder created 32-byte session nonces. TypeScript requires exactly 48
  bytes for `initialNonce` and `yourNonce` (`AuthMessageValidation.ts:391-428`)
  and rejected every Swift initialResponse.
- A responder became authenticated only on a general message. TypeScript marks
  the peer authenticated on any verified certificate request, certificate
  response or general message (`Peer.ts:1092`, `Peer.ts:1227`, `Peer.ts:1317`).
- An empty body was written as 0. TypeScript writes and expects -1 in both
  directions (`clients/AuthFetch.ts:762-770`,
  `transports/SimplifiedFetchTransport.ts:314-321`,
  `auth-express-middleware/src/index.ts:2112-2117`). The client `{}` default
  applies only to an absent body, as in `clients/AuthFetch.ts:755-760`.
- `content-type` was cut at `;` without trimming, also for multipart.
  TypeScript uses `authenticatedContentType` (`utils/paymentTransport.ts:84-90`).
- Default limits were below what TypeScript sends. They now match: 16 MiB
  messages (`AuthMessageValidation.ts:8`), payloads of 16 MiB plus 512 KiB
  (`clients/AuthFetch.ts:147`), 100 certificates, certifiers and types
  (`AuthMessageValidation.ts:12-14`), and 512 headers, 1 KiB names, 32 KiB
  values and 256 KiB in total, with 256 KiB for `x-bsv-payment`
  (`transports/SimplifiedFetchTransport.ts:25-28`, `:655-661`). BRC-103 signs
  each general payload through the wallet, so `WalletCryptoLimits` defaults to
  the same 16 MiB plus 512 KiB (`WalletCryptoLimits.defaultPayloadByteCount`,
  which `AuthLimits.defaultPayloadBytes` is); the TypeScript `ProtoWallet` has
  no bound.

`Tests/BSVAuthTests/BRC103/TypeScriptInteropTests.swift` replays TypeScript
messages from `TypeScriptAuthVectors.md` and checks Swift messages against a
live TypeScript peer.
