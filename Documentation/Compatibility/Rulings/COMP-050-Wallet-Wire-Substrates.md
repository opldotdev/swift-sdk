# COMP-050: Transport-neutral wallet-wire substrates

Status: Accepted

## Scope

This ruling covers the Go SDK v1.3.3 `wallet/substrates` binary wallet-wire
processor and transceiver. It covers call discriminators 1 through 28.

HTTP JSON, HTTP wallet-wire, WebSocket, retry, persistence, and wallet
implementation behavior are outside this scope.

## Decision

Swift provides these transport-neutral boundaries:

- `WalletWireTransport` sends one bounded request. Each call supplies the
  maximum response byte count. The transport must enforce that limit before it
  buffers or copies a larger response.
- `WalletWireProcessor` decodes a complete request, authorizes its originator,
  calls a supplied `WalletInterface`, and encodes one result.
- `WalletWireTransceiver` binds one validated originator to one transport and
  implements `WalletInterface`.
- `WalletWireOriginatorAuthorizing` is a required injected capability. The
  processor does not silently accept an originator.
- `WalletWireFailureMapping` controls conversion of wallet and authorization
  failures to remote errors. `WalletWireRedactingFailureMapper` preserves an
  existing bounded remote error and redacts any other error.

The processor and transceiver require explicit `WalletWireLimits`,
`BEEFLimits`, and `CertificateLimits`. They use the existing wallet-wire codecs.
They do not add a second serializer.

## Originator model

Go passes the originator string to every wallet method. The current Swift
`WalletInterface` methods do not take an originator. Swift therefore enforces
originator policy at an injected processor boundary before wallet dispatch.
The transceiver stores one originator that its initializer validates.

An application that needs originator-specific wallet state must construct an
originator-bound processor and wallet facade. Its authorizer must reject every
other originator. The substrate does not use task-local state or an implicit
global originator.

## Error and cancellation model

Malformed requests fail as processor transport errors. This matches the pinned
Go processor contract. Malformed results fail with the strict typed codec
errors. The processor does not call the authorizer or wallet for malformed
operation parameters.

Authorization and wallet failures use a result failure frame. The standard
mapper does not copy the source error text. `WalletWireRemoteError` keeps its
existing redacted description and reflection behavior. A caller can inspect
its explicit bounded `code`, `message`, and `stack` properties.

Transport failures become `WalletWireSubstrateError.transportFailure`. This
error does not retain transport text. `CancellationError` stays cancellation
at the client, authorizer, processor, wallet, and transport boundaries.

## Intentional differences from Go v1.3.3

- Go constructors do not require resource limits. Swift requires all limits.
- Go passes originator to the wallet method. Swift uses the required injected
  originator authorizer because `WalletInterface` has no originator parameter.
- The Go processor returns wallet failures through the transport error path.
  Swift encodes them as bounded result failure frames so a remote transport can
  preserve the protocol distinction.
- Swift hides arbitrary transport and wallet error text by default.
- Swift rejects noncanonical or trailing operation data through the existing
  strict codecs.

## Supported calls

All 28 calls map to current typed models and codecs:

- Calls 1 through 7 use the action and output codecs.
- Calls 8 and 11 through 16, and calls 23 through 28, use the key and query
  codecs.
- Calls 9, 10, and 17 through 22 use the certificate, linkage, and discovery
  codecs.

There is no model gap for this packet.

The substrate inherits the existing codec representability rules. Examples
include false verification results, false completion results, and the pinned
Go create-action signable union. A wallet result that the codec marks as
non-round-trippable fails at the processor boundary. The substrate does not
replace it with a different value.
