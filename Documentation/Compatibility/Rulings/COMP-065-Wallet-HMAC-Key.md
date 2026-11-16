# COMP-065: Wallet HMAC key length

Status: Accepted. Replaces the HMAC part of COMP-002.

## Context

BRC-2 and BRC-56 key wallet HMACs with the X coordinate of the shared
type-42 point. COMP-002 keyed both AES-GCM and HMAC with the 32-byte
zero-padded X coordinate, following Go v1.3.3.

`@bsv/sdk` 4.1.1 keys HMAC-SHA256 with the minimal-length big-endian X
coordinate (`SymmetricKey.toArray()` with no length). TypeScript SDK 2 and 3
did the same, so every TypeScript wallet and app issues tags this way. Its
test `packages/sdk/src/wallet/__tests/ProtoWallet.brc56-hmac-key.test.ts`
pins six vectors and rejects tags made with the padded key. The two keys
differ only when the X coordinate starts with a zero byte, about one key in
256. For those keys a Swift tag failed TypeScript verification, and a
TypeScript tag failed Swift verification.

## Ruling

- `ProtoWallet.createHMAC` keys HMAC-SHA256 with the minimal-length X
  coordinate.
- `ProtoWallet.verifyHMAC` accepts a tag made with the minimal key or with the
  32-byte padded key. The padded check runs only when the two keys differ.
- AES-256-GCM encryption and decryption keep the 32-byte key. TypeScript
  4.1.1 also uses the 32-byte key there.

## Reason

TypeScript wallets and apps are the 1Sat wallet's peers, so their HMAC tags
must verify in Swift and Swift tags must verify in TypeScript. Accepting the
padded tag keeps tags that earlier Swift releases and Go v1.3.3 peers created
valid. This is a deliberate leniency: TypeScript 4.1.1 rejects the padded tag.

## Tests

`ProtoWalletTests.testBRC56HMACKeyVectorsMatchTypeScript` checks all six
TypeScript vectors: the derived key, the created tag, verification of the tag,
and acceptance of each padded-key tag. The published BRC-2 HMAC vector is
unchanged because its X coordinate has no leading zero byte.
