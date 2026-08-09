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
codec rejects duplicate and unknown object members before Foundation decodes
the document. It requires canonical compressed public keys, canonical Base64
nonces, complete low-S DER signatures, and explicit JSON and payload limits.

The peer authenticator uses an injected wallet, secure random source, and
clock-based session timeout. It binds an expected peer identity, rejects nonce
reuse and message replay, limits sessions and accepted messages, and checks
cancellation around each wallet call. A responder remains unauthenticated
until it verifies the first signed general message.

Swift accepts 32-byte protocol nonces and the exact 48-byte Go nonce form. It
generates 32-byte nonces and propagates random-source failures. It does not
accept the other variable nonce lengths that the pinned Go verifier accepts.

The BRC-104 codec is transport-neutral. It binds a 32-byte request identifier
to the method, path, optional query, selected headers, body, or response status.
It uses canonical CompactSize values and explicit payload and header limits.
It excludes all `x-bsv-auth-*` headers from the signed payload, rejects
duplicate headers, and sorts selected header names by lowercase UTF-8 bytes.

## Go SDK defects

The separate Go SDK defect report records the related pinned defects:

- GO-006: nonce generation discards random-source failure.
- GO-007: nonce verification accepts noncanonical HMAC lengths.
- GO-008: a responder authenticates an unsigned initial request.
- GO-009: the handshake does not enforce the expected peer identity.

Swift does not reproduce these defects. Canonical shared messages remain
interoperable through the pinned Go oracle.
