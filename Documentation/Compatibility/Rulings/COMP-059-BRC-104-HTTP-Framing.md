# COMP-059: Bounded BRC-104 HTTP framing

Pinned Go joins BRC-104 message framing to concrete HTTP clients, callback
state, fallback requests, and automatic payments. These operations require
transport and payment policies that a framing codec cannot select safely.

`BSVAuth` provides a bounded, transport-neutral HTTP frame codec for signed
general messages. The codec uses the seven BRC-104 authentication headers. It
requires canonical header values, one value for each authentication header,
complete request-ID correlation, valid HTTP component text, and explicit
resource limits.

`x-bsv-auth-message-type` is optional on requests. `AuthFetch` sends only the
other six headers (`transports/SimplifiedFetchTransport.ts:189-194`) and the
TypeScript middleware assumes `general`
(`auth-express-middleware/src/index.ts:361-366`). When the header is present it
must be `general`. Swift still sends it; TypeScript ignores it. A received
request is rebuilt without the client JSON body default, and an empty body is
signed as -1 (COMP-052).

The default framing limits allow 1024 headers, 1 KiB names, 256 KiB values and
1 MiB of headers in total, so a frame that carries the largest TypeScript
signed headers (COMP-052) and the authentication headers fits. It rejects the requested-certificate header because that
header is not part of the signed payload. Callers use the signed BRC-103
certificate-request message from COMP-060.

The package does not provide an HTTP or WebSocket client, automatic retry,
unauthenticated fallback, automatic payment, or session persistence. A future
transport must use this codec and must define endpoint, cancellation, response,
retry, and payment policies.
