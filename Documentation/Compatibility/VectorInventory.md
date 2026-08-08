# Phase 0/1 vector and oracle inventory

Baseline: Go SDK v1.3.3 at
`de26fdec57a945ddc06de5d5617f6c32374f3929`.

Policy: Go SDK source/fixtures are behavior reference and external-oracle input
only. No translation or reshaping makes an Open BSV fixture suitable for this
MIT repository. Static fixtures come directly from identified permissive or
public-domain originals, with their license, revision, original path, local
hash, and transformation recorded in the fixture manifest.

Dependency pins:

- Swift Crypto 4.5.1, revision
  `47d3869a7291f085c1fb9fb1e6d3b97a793f45c6`, Apache-2.0.
- swift-secp256k1 0.23.2, revision
  `e70a10e036a55fffea31568f0af92d69b6d449cd`, MIT.
- swift-asn1 1.7.1, transitive dependency.

## Static vector sources

| Family | Preferred committed source | License | Packet / notes |
| --- | --- | --- | --- |
| Hex | Go standard library `encoding/hex/hex_test.go` or independently authored equivalent | BSD-3-Clause | P1-B; upper/lowercase, odd nibble, invalid byte. |
| Base64 | Go standard library `encoding/base64/base64_test.go` or RFC 4648 cases | BSD-3-Clause / direct standard | P1-B; standard/URL-safe and padding policy. |
| CompactSize/VarBytes | btcd v0.24.2 `wire/common_test.go` | ISC | P1-A; all boundaries, short reads/writes, noncanonical forms, declared-length overflow. Go SDK's permissive behavior is oracle-only and selected by policy. |
| SHA-256/SHA-512 | Swift Crypto digest tests | Apache-2.0 | P1-C; adapter results still need SDK-owned composition tests. |
| HMAC SHA-256/SHA-512 | RFC 4231, optionally represented through Swift Crypto tests | RFC / Apache-2.0 copy | P1-C; empty and block-boundary properties added locally. |
| RIPEMD-160 | `golang.org/x/crypto` v0.54.0 `ripemd160_test.go` | BSD-3-Clause | P1-C; empty, short strings, alphabet, long input, million-`a`. |
| Hash/txid byte order | `bitcoinsv/bsvd` chainhash tests | ISC | P1-C; prefer this clean upstream to similar cases inside Go SDK. |
| AES block | Go stdlib `crypto/aes/aes_test.go` / FIPS 197 | BSD-3-Clause / public standard | P2; AES-128/192/256 KATs. |
| AES-CBC/PKCS#7 | Swift Crypto CryptoExtras tests and Wycheproof CBC JSON | Apache-2.0 | P2; invalid padding is mandatory. |
| AES-GCM | Swift Crypto Wycheproof `aes_gcm_test.json` | Apache-2.0 | P2; 316 valid/invalid cases; hash `f7d77a3a059f30c80b05376a44286f79c50150537b9588e74d87158c2c64de80`. |
| PBKDF2/BIP-39 | `trezor/python-mnemonic` v0.21 English vectors and wordlist, plus fixed PBKDF2-HMAC-SHA512 known answers | MIT / independently authored | P3; exact SHA-512, 2,048-round, 64-byte profile and all 24 official English vectors are committed with strict provenance. |
| secp key parsing | Decred secp256k1 v4.4.0 tests | ISC | P2; compressed/uncompressed/hybrid, prefix/length/range/off-curve failures. |
| ECDH | swift-secp256k1 tests plus vendored Wycheproof ECDH JSON | MIT / Apache-2.0 | P2; 752 cases. Explicitly distinguish compressed, uncompressed, and x-only output. |
| ECDSA verify | vendored Wycheproof Bitcoin/secp256k1 JSON | Apache-2.0 | P2; 463 valid/invalid cases; hash `1be8742064fec73d670339f0036dec56b21baa94cb2d8e0fbbb6fb480f733869`. |
| DER/recovery/RFC6979 | Decred secp256k1 ECDSA tests and P256K binding tests | ISC / MIT | P2; strict DER, compact, recovery header/id, high-S normalization. |
| Base58/Base58Check/WIF/address | `bitcoinsv/bsvutil` tests | ISC | Raw Base58 P1-B; checksum/key/address façades later. |
| Script ASM and standard templates | Independently authored BRC-106/BRC-18 examples plus pinned Go differential queries | Original / oracle-only | Canonical `OP_FALSE`/`OP_TRUE`, aliases, push normalization, P2PK/P2PKH/P2SH, false-return parts, malformed and bounded input. No BRC repository text is copied because that repository has no identified license. |
| Script number small corpus | btcd v0.24.2 `txscript/scriptnum_test.go` | ISC | BigNum concepts P1-D; production era-aware codec later. |

Wycheproof provenance recorded by the selected dependencies identifies Apache
2.0 and upstream commits. Copy source JSON, not generated headers, and preserve
the dependency NOTICE information.

## Go-only behavior sources

These are queried through the pinned oracle and are never copied:

- `util/{bytemanipulation,bytestring,reader,varint,writer_reader_extra}_test.go`
- `chainhash/{hash,hashfuncs,marshal}_test.go`
- `primitives/hash/hash_test.go`
- `primitives/drbg/testdata/vectors.json`
- `primitives/ec/testdata/{BRC42.private,BRC42.public,SymmetricKey}.vectors.json`
- EC key/signature/WIF tests under `primitives/ec` and `primitives/ecdsa`
- AES tests under `primitives/aescbc` and `primitives/aesgcm`
- Script-number behavior under `script/interpreter/number_test.go`
- Transaction/script/BUMP/BEEF/wallet serializer fixtures cataloged in the Go
  surface inventory for later phases.

Important gaps:

- HMAC-DRBG appears NIST-derived but has no independent in-tree provenance;
  re-source it directly from NIST before committing a static corpus.
- The Go symmetric envelope vectors are SDK-specific and remain oracle-only.
- The PBKDF2-HMAC-SHA512/BIP-39 gap is closed by direct
  `trezor/python-mnemonic` v0.21 vectors at revision
  `d4b106cdec196202d44628026fcb8fedc8ea50c1`, with the exact English wordlist
  and MIT license recorded by the fixture manifest.
- Go has no dedicated raw ECDH KAT; point/X serialization must be tested from
  permissive dependency sources plus composed BRC-42 differential cases.
- P256K does not expose an obvious hybrid-key parser; hybrid acceptance versus
  documented deviation needs an explicit compatibility ruling before key API
  freeze.

## Required adversarial cases

- Hex/Base64: invalid character at every position, odd hex, padding and
  whitespace policy, decoded-size limit.
- Binary/CompactSize/VarBytes: truncation after every prefix byte, nonminimal
  forms under both policies, trailing data, UInt64 narrowing overflow, declared
  length beyond remaining/configured maximum, max-u64 sentinel ambiguity.
- Hash/HMAC: empty inputs, block-size minus/exact/plus one, multi-block,
  incremental/one-shot equivalence, exact digest width and txid reversal;
  valid, tampered, and every truncated-tag length for the verification adapter.
- AES/PBKDF2: every invalid size, empty plaintext/AAD, tag/ciphertext/AAD
  tampering, every PKCS#7 bad-padding class, unsafe rounds/output limits.
- secp: private zero/order/out-of-range/wrong length; public bad prefix/length,
  off-curve, coordinate ≥ field, infinity, hybrid parity mismatch.
- DER/compact/recovery: wrong tags/lengths, truncation/trailing data, negative or
  padded/zero/out-of-range R/S, compact length, recovery ID/header, high-S
  normalization and idempotence.
- Base58Check/WIF/address: forbidden alphabet, leading zeros, short payload,
  every checksum-byte flip, unsupported version, compression marker, scalar
  range.
- Raw Base58: an explicit decoded-byte maximum with limit minus one, exact, and
  plus one cases; no unbounded decoding entry point.
- Big/script number: empty/negative zero/redundant sign bytes, sign boundaries,
  divide/mod zero, skewed operands, era limit minus/exact/plus one, and proof
  that serialization does not mutate the value.

## Oracle contract

An original adapter under `Tools/Conformance/GoOracle` imports the pinned
external module but copies no implementation or fixture.

- Commands: `metadata` and `serve`.
- `serve`: bounded UTF-8 NDJSON, one ordered response per request, protocol JSON
  on stdout and diagnostics on stderr.
- Schema: `bsv-conformance/1`; opaque unique string ID, fixed operation name,
  fixed args/result shape, lowercase even hex bytes, decimal-string integers.
- Reject duplicate IDs, unknown fields/operations, oversized lines/results,
  ambiguous conversions, ambient randomness/network/time/locale.
- Catch panics at an operation boundary as `oraclePanic`; Swift never emulates
  them.
- Verification mismatch is a successful `valid: false` result.

Initial operation registry:

```text
metadata
bytes.reverse
u16|u32|u64.encode|decode
hex.encode|decode
base64.encode|decode
varint.encode|decode
varbytes.encode|decode
hash.sha256|sha256d|sha512|ripemd160|hash160
hmac.sha256|sha512
digest32.parse|display
base58.encode|decode
base58check.encode|decode
big.umod
scriptnum.encode|decode
drbg.generate
transaction.decode
```

Later operations extend the same versioned envelope for AES, secp keys,
ECDH output formats, DER/ECDSA/recovery, WIF/address, and BIP-39 seed behavior.

Stable error categories include invalid encoding/character/length,
truncation/trailing data, noncanonical encoding, overflow/resource limit,
checksum/version/key/signature/scalar errors, authentication/padding failure,
number-too-large/nonminimal/division-by-zero, unsupported operation, panic, and
internal. Typed errors win; any string mapping is isolated and locked to the
pinned commit. Diagnostic messages are not asserted.

## Pin and CI requirements

The lock must add SHA-256 for Go SDK license
`d869a62568556cc7f61304b768074b40d7511ddb414f4e546101f860ee0ea853`,
`go.mod` `7dd043b15ec0f317eeb6aa2bbc336eed940c127343d613129c0f176153f9d8c5`,
and `go.sum` `3ae1f83b189e48db4a8577a10fc74e1d04ab83b8998852526040d509066e177d`,
plus a trusted archive or deterministic tree-manifest hash.

Git mode requires exact clean HEAD/tag and a real path outside this repository.
Archive mode fails closed without a trusted full-tree hash. Metadata returns
source mode/tree hash, dirty flag, Go version, dependency-graph hash, license
hash, and operations, and the Swift client verifies it before cases.

Static permissive fixtures run on every macOS/Linux job without Go or network.
Differential tests use a separate offline job with pre-provisioned source,
toolchain, and module cache. Locally, a missing oracle produces one explicit
unavailable result; with `BSV_ORACLE_REQUIRED=1`, absence or mismatch is fatal.
Oracle stdout is never committed or cached as golden fixture data.

Oracle request and response lines are capped at 1 MiB. Scale tests at 750 KiB
and 32 MiB remain Swift-only; the oracle covers small/medium arithmetic parity.
The Swift client enforces a 10-second request deadline, terminates a hung child,
and force-kills it after a two-second grace period. Required CI uses the exact
Go toolchain version recorded in the lock; any toolchain drift fails metadata
validation rather than becoming a new behavioral baseline.
