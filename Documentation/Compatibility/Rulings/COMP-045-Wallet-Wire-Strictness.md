# COMP-045: Wallet-wire primitives follow TypeScript 4.1.1

Status: Accepted. Revised: the wire now follows `@bsv/sdk` 4.1.1 instead of
pinned Go v1.3.3.

## Why the wire follows TypeScript

TypeScript wallets and apps are the 1Sat wallet's peers. Every binary
wallet-wire frame a Swift processor or transceiver exchanges with them must
have the bytes `@bsv/sdk` 4.1.1 writes and must accept the bytes it sends.
Where pinned Go v1.3.3 differs, Swift now follows TypeScript and records the
Go difference as a divergence in the Go-oracle tests.

Safety bounds stay. They reject hostile or malformed input but never
legitimate TypeScript traffic.

## Ruling

Encoding follows the TypeScript writers in
`packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts` and
`WalletWireProcessor.ts`:

- An omitted optional Boolean is `ff`. TypeScript writes a byte only for a
  boolean value, and its callers omit `false`, so Swift writes `privileged`
  and `forSelf` as `ff` when they are false. It reads `00`, `01` and `ff`.
- An omitted counterparty is `00`. Swift reads it as the call's default
  (`self`, or `anyone` for `createSignature`).
- An empty string in a label or tag list is written with length 0. Length 0
  and `-1` both read as the empty string.
- An omitted optional string in a request may be empty.
- A false `verifyHMAC` or `verifySignature` result is the error frame
  TypeScript sends: code 1 with `HMAC is not valid` or
  `Signature is not valid`.
- A false `waitForAuthentication` result is code 1 with `Wallet did not
  affirmatively authenticate` (`WalletWireProcessor.ts:1683`).
- Error frames carry a code from 1 to 8. Any other code is sent as 1. The
  message is cut to 4,096 UTF-8 bytes on a character boundary, and the stack
  is empty. The standard remote message limit is 4,096 bytes.
- Error text follows TypeScript where peers see it: an originator that is not
  UTF-8 is `The encoded data was not valid for encoding utf-8` (a fatal
  `TextDecoder`, `primitives/utils.ts:237`), and a bad getPublicKey
  `identityKey` byte is `Invalid identityKey flag: expected 0 or 1, received N`
  (`WalletWireProcessor.ts:49`). Other request failures name the field and the
  reason, for example `Invalid Wallet Wire createAction request: <reason>`.
- A processor never sends an error's type or value to the peer. An error the
  codecs do not describe gets a fixed text (`Invalid Wallet Wire <call>
  request`, `Invalid <call> result`). The full error goes to the local log:
  subsystem `dev.opl.swift-sdk`, category `BSVWallet` (`WalletLog`).

Swift keeps these bounds: canonical CompactSize, explicit frame, payload,
text, originator and error limits, checked UInt32 values, low-S DER
signatures, exact SEC1 keys and full payload consumption.

## Divergence from pinned Go v1.3.3

Go stores `privileged`, `forSelf` and `seekPermission` as plain Booleans and
writes `00` for false where Swift and TypeScript write `ff`. The safe Go
adapter rejects zero-length list entries. `WalletWireGoOracleTests` and
`WalletWireActionGoOracleTests` assert both differences.

## Tests

`WalletWireKeyQueryTests`, `WalletWireAdversarialTests` and
`WalletWireTypeScript41VectorTests` cover the vectors with TypeScript source
citations. `WalletWireTypeScriptOracleTests` compares every call with live
TypeScript frames when `BSV_TS_WALLET_WIRE_VECTORS` is set
(`Tools/Conformance/TSOracle/generate.sh`).
