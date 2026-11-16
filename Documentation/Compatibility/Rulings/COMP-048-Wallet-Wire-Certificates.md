# COMP-048: Wallet-wire certificate calls follow TypeScript 4.1.1

Status: Accepted. Revised: certificate calls now accept the `@bsv/sdk` 4.1.1
forms instead of requiring pinned Go v1.3.3 ordering and totals.

## Why the wire follows TypeScript

TypeScript wallets and apps are the 1Sat wallet's peers (COMP-045). Their
certificate frames must be read and answered without rejection.

## Ruling

- **Map order.** TypeScript writes keyrings, fields and attributes in object
  insertion order. Swift reads maps in any order and rejects only a repeated
  name. Swift writes maps sorted by raw UTF-8 bytes, which TypeScript accepts.
- **List and discovery totals.** `totalCertificates` counts every match. The
  records follow with no count and end at the end of the frame. A page may be
  shorter than its total but never longer, and never longer than the
  request's limit.
- **listCertificates verifier.** The wire carries the 33 compressed key bytes,
  or length 0 when absent. The ABI and JSON keep the hex text. Any other
  length is refused.
- **Keyring presence.** `nil` is `00`; a nonempty map is `01` and the map.
  TypeScript writes an empty keyring as `00` and returns `{}` for it, so JSON
  `keyring: {}` reads as no keyring.
- **Call 29.** TypeScript 4.x probes call 29 (certificate compatibility
  profile) before discovery and some list, prove and relinquish calls. A Swift
  processor answers code 1 `Invalid call code: 29`, the exact answer on which
  the TypeScript transceiver falls back to the plain calls. The full profile
  is not implemented: it exists to carry certificate types other than 32 bytes,
  which Swift `CertificateTypeID` cannot represent.

Swift keeps canonical CompactSize, compressed keys, low-S DER, checked UInt32
values, canonical Base64 and full consumption.

## Divergence from pinned Go v1.3.3

The safe Go adapter requires sorted maps and a record count equal to the
total, and the pinned identity-certificate reader cannot read more than one
discovery record (GO-001). `WalletWireCertificateGoOracleTests` asserts the
total difference. Canonical certificate frames with sorted maps still match Go
byte for byte.

## Tests

`WalletWireCertificateTests`, `WalletWireCertificateAdversarialTests` and
`WalletWireTypeScript41VectorTests` cover these forms.
`WalletWireTypeScriptOracleTests` replays live TypeScript frames, including the
call-29 probe and fallback.
