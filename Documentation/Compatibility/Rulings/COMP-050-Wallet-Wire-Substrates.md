# COMP-050: Transport-neutral wallet-wire substrates

Status: Accepted. Revised: processor failures are answered in-band, as
`@bsv/sdk` 4.1.1 does.

## Why the wire follows TypeScript

TypeScript wallets and apps are the 1Sat wallet's peers (COMP-045). A
TypeScript transceiver reads every processor failure, including a request it
built wrongly or a call the processor does not know, as an error frame. A
transport error instead looks like a dead connection, and the call-29 probe
fails outright.

## Scope

Binary wallet-wire processor and transceiver, calls 1 through 28, plus the
in-band answer to call 29. HTTP JSON, WebSocket, retry, persistence and
wallet behavior are out of scope.

## Decision

- `WalletWireTransport` sends one bounded request with a caller-supplied
  response limit.
- `WalletWireProcessor` decodes a request, authorizes its originator, calls
  the wallet and encodes one result frame.
- `WalletWireTransceiver` binds one originator to one transport and
  implements `WalletInterface`. Its `listOutputsEncoding` selects the
  optional spendable listOutputs extension (COMP-046).
- `WalletWireOriginatorAuthorizing` is required. The processor never accepts
  an originator silently.
- `WalletWireFailureMapping` turns authorization and wallet failures into
  remote errors. `WalletWireRedactingFailureMapper` keeps an existing bounded
  remote error and otherwise sends `Wallet operation failed`, as TypeScript
  does for an error that is not a `WalletError`.
- Processor and transceiver require explicit wire, BEEF and certificate
  limits.

## Error and cancellation model

Every failure becomes an error frame (code, message, empty stack), as
`WalletWireProcessor.ts` does:

- An unknown call, including 29, is code 1 `Invalid call code: N`.
- A truncated request is code 1
  `ReaderUint8Array read exceeds available data`.
- Trailing request bytes are code 1
  `Wallet Wire <call> request contains trailing data`.
- Any other malformed request is code 1 `Invalid Wallet Wire <call> request:`
  followed by a short reason that never contains payload bytes.
- A wallet result the codec cannot write is code 1 `Invalid <call> result:`
  and a short reason. `WalletWireResultRejection` carries a specific code and
  message, such as code 8 for an abort refusal.
- Authorization and wallet failures use the failure mapper.

Codes outside 2 through 8 are sent as 1. Messages are cut to the configured
limit (4,096 bytes by default). The malformed request never reaches the
authorizer or the wallet. `CancellationError` still propagates at every
boundary, and transport failures stay `WalletWireSubstrateError.transportFailure`.

## Differences from pinned Go v1.3.3

- Go returns malformed requests through the transport error path. Swift and
  TypeScript answer in-band.
- Go constructors do not require limits. Swift requires them.
- Go passes the originator to each wallet method. Swift uses the injected
  authorizer because `WalletInterface` has no originator parameter.
- Swift hides arbitrary wallet error text by default.
