# COMP-060: BRC-103 certificate exchange

## Decision

`BSVAuth` supports signed certificate-request and certificate-response messages
after peer authentication. A request contains a nonempty bounded set of
certifiers, certificate types, and required disclosure fields. A response must
match the exact pending request.

`PeerAuthenticator` verifies the peer message signature and correlates one
response with one pending request. This verification does not establish
certificate trust. The caller must use `AuthCertificateExchange.validate` to
verify each BRC-52 certificate, bind the subject to the peer, decrypt every
requested field, and apply its own trust and revocation policy.

The wallet preparation helper lists certificates and proves exactly the
requested fields for the verifier. It fails unless it can satisfy every
requested certificate type.

## Compatibility

Canonical request and response JSON reencodes through Go SDK v1.3.3. Swift
requires canonical padded Base64, lowercase compressed-key and DER hex, unique
certifiers and fields, complete JSON consumption, exact request matching, low-S
signatures, and explicit resource limits.

Swift does not accept certificate data in the initial handshake. It uses the
signed post-authentication messages because the current `PeerAuthenticator`
does not contain certificate trust policy.

The BRC-104 requested-certificate HTTP header remains unavailable. The Go
transport does not bind that header to the signed general-message payload. A
caller must use the signed BRC-103 certificate-request message.

## Exclusions

This ruling does not add a concrete HTTP or WebSocket transport, AuthFetch,
automatic payment, persistent trust policy, or chain-aware revocation lookup.
