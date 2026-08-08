# COMP-048: Wallet-wire certificate strictness

Status: Accepted.

## Context

Pinned Go v1.3.3 defines wallet-wire calls 9, 10, and 17 through 22. Its
canonical writers sort most certificate maps, use display-order transaction ID
bytes in certificate revocation outpoints, and use CompactSize for lengths and
counts.

The pinned implementation also has three observable artifacts:

- A list-certificate result uses `00` for an absent keyring and `01` plus a map
  for a present keyring. Its reader turns a present empty map into absence.
- The prove-certificate result writer ranges over its map without sorting.
- The identity-certificate reader checks for end of input inside one item. It
  cannot read a discovery result that contains more than one certificate.

The separate Go maintainer report tracks this issue as
[GO-001](../GoSDK-v1.3.3-Defects.md#go-001-discovery-results-cannot-contain-more-than-one-identity-certificate).

Several pinned readers also accept nonminimal CompactSize, unchecked UInt32
conversion, unsorted or duplicate maps, non-low-S signatures, loose presence
bytes, or trailing data.

## Ruling

Swift provides strict bounded typed request and result codecs for the eight
calls. The codecs:

- Require canonical CompactSize and complete input consumption.
- Check all counts and lengths before collection allocation or copying.
- Require canonical compressed public keys and low-S DER signatures.
- Use display-order transaction ID bytes for certificate revocation outpoints.
- Emit and require unique map keys in raw UTF-8 byte order.
- Require canonical Base64 in embedded certificate field values.
- Use checked UInt32 conversions for outpoint indexes and pagination.
- Keep request, result, direct ABI, and reflection diagnostics redacted.

`WalletCertificateResult.keyring` is optional. `nil` encodes as `00`. A
nonempty map encodes as `01` followed by the map. The initializer and decoder
reject a present empty map because Go cannot preserve that state.

Swift implements the intended bounded nested grammar for discovery results and
supports multiple certificates. Live-Go byte parity covers zero or one item.
The safe Go adapter rejects multiple items before it calls the defective pinned
reader. For a prove-certificate result, the live Go adapter performs strict
canonical preflight and pinned typed parsing, then returns the validated input
bytes. It does not return nondeterministic pinned map-writer output.

## Consequences

Canonical zero- and one-certificate packets have the same bytes in Swift and
pinned Go v1.3.3. Swift also supports bounded multi-certificate discovery
packets, although pinned Go cannot read them. Malformed, lossy, or
nondeterministic forms fail with bounded typed errors. The packet supplies
serialization only. It does not supply wallet execution, persistence,
transport, permission prompts, certificate revocation checks, or trust policy.
