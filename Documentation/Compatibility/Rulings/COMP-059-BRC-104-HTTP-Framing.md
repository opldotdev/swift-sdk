# COMP-059: Bounded BRC-104 HTTP framing

Pinned Go joins BRC-104 message framing to concrete HTTP clients, callback
state, fallback requests, and automatic payments. These operations require
transport and payment policies that a framing codec cannot select safely.

`BSVAuth` provides a bounded, transport-neutral HTTP frame codec for signed
general messages. The codec uses the seven BRC-104 authentication headers. It
requires canonical header values, one value for each authentication header,
complete request-ID correlation, valid HTTP component text, and explicit
resource limits. It rejects the requested-certificate header because that
header is not part of the signed payload. Callers use the signed BRC-103
certificate-request message from COMP-060.

The package does not provide an HTTP or WebSocket client, automatic retry,
unauthenticated fallback, automatic payment, or session persistence. A future
transport must use this codec and must define endpoint, cancellation, response,
retry, and payment policies.
