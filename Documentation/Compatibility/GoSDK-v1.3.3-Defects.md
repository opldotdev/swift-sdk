# Go SDK v1.3.3 defect report

## Purpose

This file records confirmed defects in the pinned Go SDK that were found during
Swift parity work. It is a separate report for the Go SDK maintainers. The
normal parity map describes supported behavior and links here when a defect
changes the shared compatibility domain.

Reference:

- Repository: [`bsv-blockchain/go-sdk`](https://github.com/bsv-blockchain/go-sdk)
- Release: `v1.3.3`
- Commit: `de26fdec57a945ddc06de5d5617f6c32374f3929`
- Audit date: 2026-08-08

The Swift SDK does not reproduce these defects. It keeps canonical valid wire
behavior compatible and rejects or corrects the defective case.

## Confirmed defects

### GO-001: Discovery results cannot contain more than one identity certificate

- Package: `wallet/serializer`
- Files: [`identity_certificate.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/wallet/serializer/identity_certificate.go),
  [`discover_certificates_result.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/wallet/serializer/discover_certificates_result.go)
- Severity: high

`DeserializeDiscoverCertificatesResult` passes one shared reader to
`DeserializeIdentityCertificate` for each item. The item decoder calls
`CheckComplete` before the outer decoder reads the next item. Therefore, the
first item reports trailing data when the result contains two or more identity
certificates.

Suggested correction: remove the item-level completion check when the decoder
uses a shared outer reader. Keep one completion check after the outer loop.

Swift handling: Swift reads each bounded item from the shared reader and checks
for completion after the full collection. The Go differential uses only zero or
one certificate until the Go decoder is corrected.

### GO-002: Prove-certificate result encoding is not deterministic

- Package: `wallet/serializer`
- File: [`prove_certificate.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/wallet/serializer/prove_certificate.go)
- Severity: high

`SerializeProveCertificateResult` writes `KeyringForVerifier` by ranging over a
Go map. Go map iteration order is not stable. The same semantic result can
produce different bytes.

Suggested correction: collect the keys, sort them by raw UTF-8 bytes, and write
the entries in that order.

Swift handling: Swift always writes keyring names in raw UTF-8 byte order.

### GO-003: SPV verification does not reject zero-fee or inflationary ancestors

- Package: `spv`
- File: [`verify.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/spv/verify.go)
- Severity: critical

The verifier adds each source-output value to `inputTotal`, but it never uses
the total. When no fee model is supplied, an unproved transaction can have
outputs that equal or exceed its inputs and still pass if its scripts pass.

Suggested correction: compare input and output totals for every unproved
transaction. Reject arithmetic overflow, output value above input value, and
zero fee. Apply an optional fee model as an additional root-transaction rule.

Swift handling: Swift requires input value to be greater than output value for
each unproved transaction and can apply a stronger injected fee policy.

### GO-004: BEEF parsing can index outside the BUMP collection

- Package: `transaction`
- File: [`beef.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/transaction/beef.go)
- Severity: critical

The BEEF reader assigns `BUMPs[int(bumpIndex)]` while it parses a raw
transaction with a BUMP index. This path does not first prove that the index is
inside the collection. A hostile packet can cause an out-of-range panic.

Suggested correction: validate the decoded index before any collection access
and return a typed parse error.

Swift handling: Swift validates every proof index before access and never
reproduces the panic.

### GO-005: Symmetric-key parsing can terminate the process

- Package: `primitives/ec`
- File: [`symmetric.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/primitives/ec/symmetric.go)
- Severity: critical

`NewSymmetricKeyFromString` calls `log.Fatalf` when Base64 input is malformed.
A library parser must not terminate its host process. The random constructor in
the same file also discards `crypto/rand` errors.

Suggested correction: return `(*SymmetricKey, error)` from both constructors.
Reject invalid key lengths before an AES operation.

Swift handling: Swift returns typed errors, propagates random-source failure,
and accepts only bounded canonical Base64.

### GO-006: Auth nonce generation discards random-source failure

- Package: `auth/utils`
- File: [`base64.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/utils/base64.go)
- Severity: critical

`RandomBase64` discards the result and error from `crypto/rand.Read`. A failed
read can return predictable or incomplete nonce material without an error.

Suggested correction: return `(wallet.StringBase64, error)`, require the exact
requested byte count, and propagate the error through every caller.

Swift handling: Swift uses an injected secure-random source and propagates each
failure.

### GO-007: Auth nonce verification accepts noncanonical HMAC lengths

- Package: `auth/utils`
- File: [`verify_nonce.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/utils/verify_nonce.go)
- Severity: high

`VerifyNonce` accepts every decoded value longer than 16 bytes. It copies the
remaining bytes into a fixed 32-byte HMAC. Short values are zero-padded and long
values are truncated by `copy`. This accepts multiple encodings for one HMAC
input.

Suggested correction: require exactly 48 decoded bytes: 16 data bytes and 32
HMAC bytes.

Swift handling: the compatibility handshake can read the exact 48-byte Go form.
It rejects all other HMAC-backed nonce sizes.

### GO-008: A responder authenticates an unsigned initial request

- Package: `auth`
- File: [`peer.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/peer.go)
- Severity: critical

`handleInitialRequest` creates a session with `IsAuthenticated: true`. It sets
the value to false only when certificates are required. The initial request has
no peer signature. A responder can therefore mark an unproved identity as
authenticated.

Suggested correction: keep the responder session unauthenticated until the
peer sends the first valid signed message that binds the session nonces and
identity key.

Swift handling: the responder waits for a valid signed `general` message before
it changes the session to authenticated.

### GO-009: The auth handshake does not enforce the expected peer identity

- Package: `auth`
- File: [`peer.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/peer.go)
- Severity: critical

The initial-response path verifies the signature against the identity key in
the received message, then stores that key in the pending session. It does not
compare the key with the identity that the caller requested for that session.
This permits identity substitution at the API boundary.

Suggested correction: store the expected identity in the pending session and
compare it before signature verification and session mutation.

Swift handling: a pending session binds an optional expected identity and
rejects a different response identity.

### GO-010: The block-headers client bypasses its configured HTTP client

- Package: `transaction/chaintracker/headers_client`
- File: [`headers_client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/transaction/chaintracker/headers_client/headers_client.go)
- Severity: high

`IsValidRootForHeight`, `BlockByHeight`, `GetBlockState`, and `GetChaintip`
create new `http.Client` values instead of using `getHTTPClient`. These paths
discard caller transport, timeout, proxy, and test configuration. Several paths
also read or decode an unbounded body and do not check the HTTP status before
they parse it.

Suggested correction: use the configured client for every request. Apply one
response-size limit, check status first, and return sanitized errors. Construct
URLs with `net/url` instead of string concatenation.

Swift handling: the Swift client uses the existing bounded, cancellable HTTP
transport for every request. It does not copy these unsafe request paths.

### GO-011: The exported default identity certificate verifier accepts every certificate

- Package: `identity`
- File: [`testable_client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/identity/testable_client.go)
- Severity: critical

`DefaultCertificateVerifier.Verify` always returns `nil`. The type is in
production source and its constructor installs it when the caller supplies no
verifier. An invalid certificate can therefore pass this exported verification
boundary.

Suggested correction: perform the real certificate verification or require an
explicit verifier. Do not provide an accepting default.

Swift handling: Swift verifies the certificate signature with the bounded
certificate implementation. It has no accepting verifier placeholder.

### GO-012: Public identity disclosure discards the verifier private key

- Package: `identity`
- File: [`client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/identity/client.go)
- Severity: high

`PubliclyRevealAttributes` creates a random private key, supplies its public key
to `ProveCertificate`, and then discards the private key. It publishes the
verifier-specific keyring returned for that key. A consumer cannot use that
keyring after the only matching private key is lost.

Suggested correction: require the intended verifier key as an input, or define
and implement a public-disclosure keyring scheme that does not require a lost
secret.

Swift handling: the caller must supply the verifier public key explicitly.

### GO-013: Identity output-index configuration has no effect

- Package: `identity`
- Files: [`types.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/identity/types.go),
  [`client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/identity/client.go)
- Severity: medium

`IdentityClientOptions.OutputIndex` is public and configurable, but no identity
operation reads it. Nonzero values appear to select an output and then have no
effect.

Suggested correction: remove the option or apply it to a defined multi-output
transaction rule.

Swift handling: the one-output disclosure action accepts only output index
zero.

### GO-014: Display identity keys contain raw compressed-key bytes

- Package: `identity`
- File: [`client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/identity/client.go)
- Severity: high

`parseIdentity` converts the 33 compressed SEC1 bytes directly to a Go string.
The result can contain invalid UTF-8 and control bytes. It is not a canonical
public-key identifier, and its first ten bytes are used as display text.

Suggested correction: encode the compressed public key as canonical lowercase
hex before it is stored or abbreviated.

Swift handling: Swift exposes the 66-character lowercase compressed-key hex and
uses its first ten ASCII characters for the abbreviation.

### GO-015: Unknown identity types receive inconsistent key treatment

- Package: `identity`
- File: [`client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/identity/client.go)
- Severity: medium

The parser suppresses identity keys only when the 32-byte type equals the ASCII
text `unknownType` followed by zero bytes. Every other unrecognized type gets
the unknown badge but still receives an identity key and abbreviation.

Suggested correction: base unknown handling on membership in the recognized
type catalog, not one sentinel byte sequence.

Swift handling: every unrecognized certificate type uses the complete unknown
fallback and has no identity key.

### GO-016: The testable identity broadcaster injection is ignored

- Package: `identity`
- File: [`testable_client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/identity/testable_client.go)
- Severity: medium

`WithBroadcaster` stores a broadcaster in the client. The disclosure method
does not use that field. It creates a new local topic broadcaster instead, so
the advertised injection cannot control or isolate the broadcast.

Suggested correction: call the injected broadcaster and require one when the
client has no safe default.

Swift handling: the disclosure method requires a generic transport-neutral
`Broadcaster` value and uses that exact value.

### GO-017: The exported testable identity client changes disclosure data

- Package: `identity`
- File: [`testable_client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/identity/testable_client.go)
- Severity: high

The testable disclosure method locks the constant `test-cert-data`. It omits
the certificate JSON and discards the proved keyring. It also omits several
certificate checks used by the regular client. The exported type therefore
does not test the production disclosure semantics.

Suggested correction: share one production implementation and inject only the
external verifier, transaction decoder, and broadcaster boundaries.

Swift handling: Swift has one disclosure implementation. Tests inject typed
wallet and broadcaster capabilities around that implementation.

### GO-018: A missing identity wallet creates an unrelated random wallet

- Package: `identity`
- File: [`client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/identity/client.go)
- Severity: high

`NewClient(nil, ...)` creates a new random private key and wraps it in a
completed wallet. The resulting client does not represent the caller's
identity, and the identity changes on each construction.

Suggested correction: reject a missing wallet. If an ephemeral wallet is
needed for a separate workflow, expose it through an explicit constructor.

Swift handling: `IdentityClient` requires an injected wallet and has no
fallback wallet.

### GO-019: The identity README names a constructor that does not exist

- Package: `identity`
- File: [`README.md`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/identity/README.md)
- Severity: low

The usage examples call `NewIdentityClient`. The package exports `NewClient`,
so the examples do not compile.

Suggested correction: update the examples to call `NewClient` and check them in
a documentation test.

Swift handling: Swift documentation names the compiled `IdentityClient`
initializer.

### GO-020: Public identity disclosure trusts an inconsistent proved keyring

- Package: `identity`
- File: [`client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/identity/client.go)
- Severity: high

The client publishes `KeyringForVerifier` without checking that its keys match
`fieldsToReveal`. A faulty or hostile wallet can omit a requested field or add
an unrequested field key to the public disclosure.

Suggested correction: require exact set equality between requested field names
and returned keyring names before transaction construction.

Swift handling: Swift rejects a missing or extra proved-keyring entry before it
builds the PushDrop script or calls `CreateAction`.

### GO-021: Registry resolution indexes an unvalidated lookup output index

- Package: `registry`
- File: [`methods.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/registry/methods.go)
- Severity: high

`ResolveProtocol` and `ResolveCertificate` index `tx.Outputs[output.OutputIndex]`
without first establishing that `OutputIndex` is in range. A malformed lookup
response can therefore panic the process instead of producing an ordinary
resolution failure.

Suggested correction: validate every output index before indexing the decoded
transaction and return a typed malformed-lookup error when it is out of range.

Swift handling: this core packet has no lookup resolver. Any future resolver
must bound result counts and validate indices before it accesses a transaction
output.

### GO-022: Registry list-own bounds checks depend on a test logger

- Package: `registry`
- File: [`methods.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/registry/methods.go)
- Severity: high

`ListOwnRegistryEntries` performs an output-index bounds check only when a test
logger is installed, then indexes the output unconditionally. Production
wallet results with an invalid output index can panic, while the same value is
handled differently in tests.

Suggested correction: make the bounds check unconditional and return one typed
error regardless of logging configuration.

Swift handling: `RegistryRecord` owns a validated, immutable token value; no
wallet listing path is included in this core packet.

### GO-023: Malformed registry certificate fields silently become an empty map

- Package: `registry`
- File: [`client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/registry/client.go)
- Severity: high

When certificate descriptor JSON cannot be unmarshaled, `parseLockingScript`
replaces it with an empty map and returns a successful certificate definition.
Corrupt on-chain fields are indistinguishable from a deliberate empty schema.

Suggested correction: return a malformed-definition error and preserve no
partially decoded certificate definition.

Swift handling: `RegistryDefinitionCodec` rejects malformed, noncanonical, and
unknown certificate descriptor JSON before it constructs a definition.

### GO-024: Registry default-network detection never adopts the wallet network

- Package: `registry`
- Files: [`client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/registry/client.go),
  [`methods.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/registry/methods.go)
- Severity: high

`NewRegistryClient` initializes `network` to mainnet. The later lazy update is
conditioned on that field being unset, so it never obtains the wallet network.
A testnet wallet can consequently use mainnet registry behavior unless callers
remember to call `SetNetwork`.

Suggested correction: require the network in the constructor or use an explicit
optional state that is resolved once from the wallet.

Swift handling: `BSVRegistry` has neither a default network nor a tracker.
Transport and network selection belong to a future injected resolver packet.

### GO-025: Unknown registry definition types panic in public mapping helpers

- Package: `registry`
- File: [`client.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/registry/client.go)
- Severity: medium

The functions mapping a public string `DefinitionType` to wallet protocol,
basket, topic, or service use `panic` for an unrecognized value. Hostile or
unvalidated input can terminate a process through an ordinary public API.

Suggested correction: use a closed definition type or return an explicit
unsupported-type error from every mapping function.

Swift handling: `RegistryDefinitionKind` is a closed enum. Its dependent
identifier accessors are bounded, throwing constructors rather than panic paths.

### GO-026: Registry revocation treats a source output index as a transaction input index

- Package: `registry`
- File: [`methods.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/registry/methods.go)
- Severity: high

The revocation flow uses `record.OutputIndex` as the index in the newly created
transaction's input and signing maps. A registrant token originating at a
nonzero output need not occupy that input position, which can sign the wrong
input or index outside the transaction.

Suggested correction: record the created input index or map by outpoint, then
use that value consistently for signing and partial-transaction metadata.

Swift handling: this core packet does not construct or revoke wallet
transactions. A future revocation packet must bind signing metadata to the
selected outpoint and created input index.

### GO-027: KVStore exports unused options and unimplemented retention configuration

- Package: `kvstore`
- Files: [`interfaces.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/interfaces.go),
  [`local_kv_store.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/local_kv_store.go)
- Severity: high

`NewLocalKVStore` accepts `KVStoreConfig`, not the exported
`NewLocalKVStoreOptions`. Consequently `RetentionPeriod` and `BasketName` are
never read. The package documentation advertises configurable retention even
though no retention behavior exists.

Suggested correction: remove the dead options type and related sentinels, or
make one validated constructor consume every documented option and implement
the declared retention behavior.

Swift handling: `BSVKVStore` contains no retention or wallet configuration.
The future wallet-backed layer must define and implement those semantics before
exporting them.

### GO-028: KVStore Get never returns its documented ErrKeyNotFound result

- Package: `kvstore`
- Files: [`interfaces.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/interfaces.go),
  [`local_kv_store.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/local_kv_store.go)
- Severity: medium

`Get` returns the supplied default value and `nil` whenever no output exists.
It never returns `ErrKeyNotFound`, although the exported interface describes
that result when no default is supplied.

Suggested correction: choose one behavior and document it precisely. A typed
optional lookup result is less ambiguous than overloading an empty string.

Swift handling: the token-only packet has no lookup API.

### GO-029: KVStore Set can overwrite after failed or corrupt lookup

- Package: `kvstore`
- Files: [`local_kv_store.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/local_kv_store.go),
  [`kvstore_extra_test.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/kvstore_extra_test.go)
- Severity: critical

`Set` logs and treats most `lookupValue` failures as an absent key. Real BEEF
and PushDrop decoding failures are generic wrapped errors rather than
`ErrCorruptedState`, so malformed existing state can cause creation of a new
token without spending the old outputs. The pinned test
`TestLocalKVStoreSetListOutputsFailsWarnsAndContinues` explicitly accepts the
same behavior after a list failure.

Suggested correction: fail closed on every lookup, BEEF, and script-decoding
error. Only an explicit, successful empty query may start a new key.

Swift handling: `BSVKVStore` performs no state lookup or mutation.

### GO-030: KVStore's newest-value rule depends on unspecified output ordering

- Package: `kvstore`
- Files: [`local_kv_store.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/local_kv_store.go),
  [`kvstore_extra_test.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/kvstore_extra_test.go)
- Severity: high

Lookup selects the last `ListOutputs` item as the most recent value. Neither
the KVStore API nor the consumed wallet result defines that ordering. The test
for multiple outputs merely repeats the same output and therefore cannot prove
the ordering policy.

Suggested correction: carry an explicit monotonic ordering value or require a
wallet query with a documented, verified order before selecting a winner.

Swift handling: ordering and conflict resolution are outside the token core.

### GO-031: KVStore Remove races with Set and other Remove calls

- Package: `kvstore`
- File: [`local_kv_store.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/local_kv_store.go)
- Severity: high

`Set` holds `LocalKVStore.mu` across lookup and mutation, but `Remove` takes no
lock. It can interleave with `Set` or another `Remove` after listing outputs
and before creating or signing a spending action, producing conflicting stale
spends.

Suggested correction: serialize all mutations over one authority, or define
an optimistic conflict/retry protocol at the wallet boundary.

Swift handling: `BSVKVStore` has no mutable store or mutation operation.

### GO-032: KVStore writes keys and outpoints to stdout on failure paths

- Package: `kvstore`
- File: [`local_kv_store.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/local_kv_store.go)
- Severity: medium

Set and Remove print keys, outpoints, and underlying wallet errors when lookup,
signing, or relinquishment fails. A library must not disclose application
identifiers and wallet state through an uncontrolled process-wide diagnostic
channel.

Suggested correction: return typed wrapped errors and let the host choose
redacted structured logging.

Swift handling: token and locator descriptions and reflection are redacted.

### GO-033: KVStore assumes every newly created token is transaction output zero

- Package: `kvstore`
- File: [`local_kv_store.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/local_kv_store.go)
- Severity: high

For a newly created key, Set returns `"<txid>.0"` after `CreateAction` without
receiving or validating the output index. This silently relies on action output
ordering and is wrong if a wallet inserts another output before the token.

Suggested correction: have the wallet return the created token outpoint, or
bind the requested output to a returned index and validate it.

Swift handling: token encoding does not create wallet transactions.

### GO-034: KVStore's String API can store values that are not UTF-8 text

- Package: `kvstore`
- File: [`local_kv_store.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/local_kv_store.go)
- Severity: medium

The package stores arbitrary bytes in PushDrop and converts them with Go's
`string(valueBytes)`. A Go string can contain invalid UTF-8, despite the public
key-value API presenting values as strings. Other language SDKs cannot expose
those values as ordinary text without loss or replacement.

Suggested correction: make the stored value a byte type, or require and
validate UTF-8 at both Set and Get boundaries.

Swift handling: `KVStoreToken.value` is explicitly `[UInt8]`; no text claim is
made.

### GO-035: Same-value Set returns an outpoint inconsistent with lookup's current value

- Package: `kvstore`
- Files: [`local_kv_store.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/local_kv_store.go),
  [`kvstore_extra_test.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/kvstore/kvstore_extra_test.go)
- Severity: medium

Lookup declares the last matching output current, but a same-value `Set`
returns the first matching outpoint. With duplicate outputs the idempotent
result can therefore identify a different token than the current-value rule.

Suggested correction: define one ordering policy and return the selected
current outpoint consistently, or collapse duplicates before testing
idempotence.

Swift handling: selection and idempotence are intentionally deferred with the
wallet-backed store layer.

### GO-036: Storage downloads read unbounded response bodies

- Package: `storage`
- File: [`downloader.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/storage/downloader.go)
- Severity: high

After accepting a host response, `Download` calls `io.ReadAll(resp.Body)` with
no byte ceiling. Any resolved host can send an arbitrarily large body and force
the process to allocate until memory exhaustion before the content hash is
checked.

Suggested correction: require a caller-selected maximum response size and stop
reading once the limit is exceeded before hashing or retaining content.

Swift handling: `UHRPDownloader` passes the caller's content limit to the HTTP
transport before reading the body. `StorageContent` applies the same limit
before it retains the result.

### GO-037: Storage upload errors read and disclose unbounded server bodies

- Package: `storage`
- File: [`uploader.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/storage/uploader.go)
- Severity: high

For a non-200 upload response, `uploadFile` reads the entire body and embeds it
verbatim in its returned error. A server or intermediary can exhaust memory and
inject arbitrary, possibly sensitive text into application diagnostics.

Suggested correction: cap and sanitize an optional error-body excerpt, and do
not reflect credentials, pre-signed URLs, or arbitrary response text by
default.

Swift handling: no uploader or HTTP error body path is present in this core.
Content descriptions and reflection are redacted.

### GO-038: Storage resolution has no bounds before BEEF parsing and host accumulation

- Package: `storage`
- File: [`downloader.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/storage/downloader.go)
- Severity: high

`Resolve` iterates every lookup output, parses each BEEF payload, and appends
every accepted host without output-count, BEEF-size, aggregate, or host-count
limits. A hostile lookup service can consume unbounded CPU and memory before a
download starts.

Suggested correction: bound lookup outputs and BEEF bytes before parsing, cap
accepted hosts and aggregate text, and return a typed resource error.

Swift handling: the injected overlay resolver uses bounded output values and
BEEF parsing. `UHRPDownloader` adds explicit advertisement and host-count
limits before it accumulates download locations.

### GO-039: Storage ListUploads exposes an unbounded type-erased public result

- Package: `storage`
- File: [`uploader.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/storage/uploader.go)
- Severity: medium

`ListUploads` decodes JSON into `interface{}` and returns that value through a
public `interface{}` result. Callers cannot rely on a stable schema, and a
service can create arbitrarily nested or large decoded object graphs.

Suggested correction: define a bounded typed upload-record list and reject
unknown, oversized, or malformed response shapes before materialization.

Swift handling: service metadata and upload listing are deferred. The public
core has no erased result type.

### GO-040: Storage accepts negative retention and renewal periods

- Package: `storage`
- File: [`uploader.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/storage/uploader.go)
- Severity: medium

`PublishFile` forwards any signed `retentionPeriod`, and `RenewFile` forwards
any signed `additionalMinutes`, including negative values. The SDK neither
defines their valid domain nor rejects an invalid local request before it is
authenticated and sent.

Suggested correction: use nonnegative bounded duration values and fail before
creating a request when callers supply an invalid period.

Swift handling: retention and renewal are uploader concerns and are not part of
the UHRP core.

### GO-041: Storage host validation accepts non-HTTP and relative locations

- Package: `storage`
- File: [`downloader.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/storage/downloader.go)
- Severity: medium

`Resolve` accepts a host whenever `url.Parse` succeeds and the text is nonempty.
That permits relative references and non-HTTP schemes; `Download` subsequently
passes those values to `http.NewRequestWithContext` without a scheme, host, or
HTTPS policy.

Suggested correction: validate an absolute allowed-scheme URL with a nonempty
host before returning it from resolution, then enforce the same policy at the
transport boundary.

Swift handling: `UHRPDownloader` accepts only absolute HTTPS locations with a
nonempty host and without credentials, fragments, or control characters.

### GO-042: Overlay lookup reads an unbounded response body

- Package: `overlay/lookup`
- File: [`facilitator.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/lookup/facilitator.go)
- Severity: high

After an HTTP 200 response, `HTTPSOverlayLookupFacilitator.Lookup` passes the
entire response to `io.ReadAll` before it decides whether to decode JSON or an
aggregated BEEF response. A hostile service can exhaust process memory.

Suggested correction: enforce a response byte limit while streaming, before
JSON or BEEF parsing begins.

Swift handling: `HTTPSOverlayLookupFacilitator` passes an explicit response
ceiling to the injected network transport before it parses JSON or BEEF.

### GO-043: Binary overlay lookup trusts attacker-controlled counts and indexes

- Package: `overlay/lookup`
- File: [`facilitator.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/lookup/facilitator.go)
- Severity: critical

`parseBinaryLookupAnswer` reserves metadata storage from an unbounded varint,
casts an unbounded context length to `int`, and narrows a `uint64` output index
to `uint32`. Malformed binary input can force allocation, overflow a length,
or silently change the selected output.

Suggested correction: cap every count and byte length before allocation or
conversion, reject nonrepresentable output indexes, and bound aggregate BEEF.

Swift handling: the binary lookup codec requires canonical CompactSize values,
bounds counts and context before allocation, checks UInt32 conversion, parses
bounded BEEF, and validates each transaction and output index.

### GO-044: Topic discovery can panic on an unvalidated output index

- Package: `overlay/topic`
- File: [`broadcaster.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/topic/broadcaster.go)
- Severity: high

`FindInterestedHosts` parses a returned BEEF and directly indexes
`tx.Outputs[output.OutputIndex]` without checking the index. A malicious lookup
answer can terminate the process.

Suggested correction: validate every returned output index before indexing and
return a typed malformed-response error.

Swift handling: `OverlayTopicBroadcaster` parses bounded BEEF and validates the
output index before it decodes and verifies a SHIP administration token.

### GO-045: Broadcaster construction can panic and accepts zero topics

- Package: `overlay/topic`
- File: [`broadcaster.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/topic/broadcaster.go)
- Severity: high

`NewBroadcaster` dereferences `cfg` without checking for nil. It also rejects
only a nil topic slice, so an empty non-nil slice produces a broadcaster despite
the documented requirement for at least one topic.

Suggested correction: reject nil configuration or define an explicit safe
default, and require `len(topics) > 0`.

Swift handling: `OverlayTopicBroadcaster` has an explicit throwing initializer.
It requires a nonempty bounded unique topic list and injected policy values.

### GO-046: Broadcaster dereferences a successful nil acknowledgement

- Package: `overlay/topic`
- File: [`broadcaster.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/topic/broadcaster.go)
- Severity: high

The public facilitator interface can return `(nil, nil)`. `BroadcastCtx` marks
that response successful and later ranges over `*result.Steak`, which panics.

Suggested correction: reject a nil acknowledgement before recording a
successful host response.

Swift handling: `TopicFacilitator` returns a nonoptional bounded `Steak` value.

### GO-047: Topic submission cannot be cancelled and has no response bound

- Package: `overlay/topic`
- File: [`facilitator.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/topic/facilitator.go)
- Severity: high

`HTTPSOverlayBroadcastFacilitator.Send` creates a new background context, so a
caller cannot cancel an in-flight submission. It also decodes the response JSON
directly from an unbounded body.

Suggested correction: accept the caller context, propagate cancellation, and
enforce byte and collection limits before decoding a STEAK response.

Swift handling: `HTTPSOverlayTopicFacilitator` performs one bounded POST. It
does not retry. Cancellation or transport failure after submission starts has
uncertain delivery.

### GO-048: Named HTTPS overlay facilitators accept arbitrary concatenated URLs

- Packages: `overlay/lookup`, `overlay/topic`
- Files: [`facilitator.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/lookup/facilitator.go), [`facilitator.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/topic/facilitator.go)
- Severity: high

Both types called HTTPS facilitators append `"/lookup"` or `"/submit"` to an
unvalidated caller string. They accept non-HTTPS, credential-bearing, relative,
and path-ambiguous values; the pinned tests themselves use `http://` URLs.

Suggested correction: require an absolute HTTPS URL without credentials,
query, fragment, or ambiguous trailing slash, then build paths with a URL
component API.

Swift handling: `OverlayHost` remains transport-neutral. Each HTTPS facilitator
requires an absolute HTTPS origin without credentials, path, query, fragment,
or trailing slash before it constructs the fixed endpoint path.

### GO-049: Administration-token decoding accepts ambiguous and invalid fields

- Package: `overlay/admin-token`
- File: [`admin-token.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/admin-token/admin-token.go)
- Severity: high

`Decode` accepts any field count of four or more, ignores surplus fields, and
hex-encodes the identity field without establishing that it is a compressed
secp256k1 key. A malformed signed advertisement can therefore be treated as a
valid host record.

Suggested correction: require the exact signed field layout, validate the
identity key, and verify the appended signature before returning a token.

Swift handling: `OverlayAdminTokenCodec` requires five bounded fields, parses
the identity key, and verifies the signature against the PushDrop locking key.

### GO-050: Administration-token unlock accepts an unknown protocol

- Package: `overlay/admin-token`
- File: [`admin-token.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/admin-token/admin-token.go)
- Severity: medium

`Lock` rejects an unknown overlay protocol, but `Unlock` creates a wallet
unlocker with an empty derived protocol identifier for the same input. The two
public operations have incompatible validation semantics.

Suggested correction: reject unknown protocols before constructing an unlocker.

Swift handling: wallet construction and spending are deliberately deferred;
the verification codec uses a closed SHIP/SLAP subject enum.

### GO-051: Overlay resolver fan-out is unbounded

- Package: `overlay/lookup`
- File: [`resolver.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/lookup/resolver.go)
- Severity: high

`Query` and `FindCompetentHosts` start one goroutine per configured or
discovered host and accumulate every result without host-count, result-count,
or aggregate-byte limits. Mutable overrides and discovered domains can grow
without a resource policy.

Suggested correction: validate and deduplicate bounded host lists, use bounded
concurrency, and cap accepted results before BEEF processing.

Swift handling: `LookupResolver` requires explicit tracker and host lists,
deduplicates and sorts them, caps their count, and queries them with bounded
concurrency. It has no default tracker list.

### GO-052: Overlay resolver results are nondeterministically ordered

- Package: `overlay/lookup`
- File: [`resolver.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/overlay/lookup/resolver.go)
- Severity: medium

The first freeform answer to arrive wins, and output-list values are emitted by
ranging over a Go map. Identical host responses can therefore produce different
results based on scheduling and randomized map iteration.

Suggested correction: specify deterministic answer arbitration and sort output
keys before returning them.

Swift handling: `LookupResolver` selects freeform data by sorted host order,
deduplicates output keys, and sorts them by transaction ID and output index. It
rejects mixed answer representations.

### GO-053: Auth HTTP paths read unbounded bodies and messages

- Package: `auth/authpayload`, `auth/transports`
- Files: [`authpayload/http.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/authpayload/http.go),
  [`transports/simplified_http_transport.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/transports/simplified_http_transport.go),
  [`transports/websocket_transport.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/transports/websocket_transport.go)
- Severity: high

Request, response, error, and WebSocket receive paths retain attacker-controlled
content without a caller-selected byte limit. Several HTTP paths use
`io.ReadAll`, and the WebSocket path receives a complete message before JSON
decoding.

Suggested correction: require byte limits at every receive boundary and stop
reading before the limit is exceeded.

Swift handling: the HTTP frame and BRC-104 payload codecs require explicit
limits. No concrete HTTP or WebSocket receiver is included.

### GO-054: Auth payload readers accept incomplete or unbounded structure

- Package: `auth/authpayload`
- File: [`http.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/authpayload/http.go)
- Severity: high

The request and response readers do not require complete input consumption.
They do not bound header counts or text before iteration. The response reader
also reads status and header counts through `ReadVarInt32`, creates a map from
the decoded count, and does not require an HTTP status in 100 through 599. The
request reader accepts the optional-string absence sentinel for a path that the
writer treats as required.

Suggested correction: use canonical checked integer decoding, validate the
status and required path, bound all fields before allocation, and reject
trailing bytes.

Swift handling: `BRC104Codec` and `BRC104HTTPFrameCodec` apply full-consumption,
text, count, status, and aggregate limits.

### GO-055: General HTTP responses do not correlate the returned request ID

- Package: `auth/transports`
- File: [`simplified_http_transport.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/transports/simplified_http_transport.go)
- Severity: high

`authMessageFromGeneralMessageResponse` constructs the signed response payload
with the request ID that the caller sent. It does not read and compare the
`x-bsv-auth-request-id` response header. A response can therefore carry a
different correlation header without rejection.

Suggested correction: decode the returned header, require exactly 32 bytes,
and compare it with the expected request ID before message verification.

Swift handling: `decodeResponse` requires the header ID to match the explicit
expected request ID and uses that ID in the reconstructed payload.

### GO-056: AuthFetch bypasses injected transport policy and can downgrade authentication

- Package: `auth/clients/authhttp`
- File: [`authhttp.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/clients/authhttp/authhttp.go)
- Severity: high

Some fallback and certificate-request paths construct a new `http.Client`
instead of using the injected client. The fetch flow can also resend a request
without authentication after authentication fails. These paths can bypass
caller timeout, proxy, transport, test, and confidentiality policy.

Suggested correction: use only the injected client and require an explicit
caller policy before any unauthenticated retry.

Swift handling: no AuthFetch client or fallback is included. The accepted API
is a pure frame codec.

### GO-057: AuthFetch cancellation can leave result senders blocked

- Package: `auth/clients/authhttp`
- File: [`authhttp.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/clients/authhttp/authhttp.go)
- Severity: medium

Fetch and certificate flows use unbuffered result channels. If the caller
returns after context cancellation, a later goroutine can block while it sends
the result. Pending-certificate polling also has paths that do not observe the
request context.

Suggested correction: use cancellation-aware sends, bounded buffering, and
context checks in every polling loop. Ensure cleanup cannot wait for an
abandoned sender.

Swift handling: no asynchronous HTTP client is included. A future transport
must preserve structured cancellation.

### GO-058: WebSocketTransport does not implement the documented transport interface

- Package: `auth/transports`
- Files: [`interface.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/transports/interface.go),
  [`websocket_transport.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/transports/websocket_transport.go)
- Severity: medium

The interface requires context-aware `Send` and `OnData` functions. The
WebSocket implementation has different signatures without a context. It also
does not provide the handler lookup required by the root auth transport use.
It cannot satisfy the documented interface.

Suggested correction: use one interface and add compile-time conformance
assertions for every production transport.

Swift handling: WebSocket transport remains future work.

### GO-059: SimplifiedHTTPTransport stops after the first callback error

- Package: `auth/transports`
- File: [`simplified_http_transport.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/transports/simplified_http_transport.go)
- Severity: low

The callback loop comment says that callback errors do not stop other
callbacks. The implementation returns when the first callback returns an
error, so later callbacks do not run.

Suggested correction: either continue and collect callback errors or change
the documented contract and tests to require first-error termination.

Swift handling: the pure frame codec has no callback registry.

### GO-060: Automatic HTTP payment has no caller approval or satoshi limit

- Package: `auth/clients/authhttp`
- File: [`authhttp.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/clients/authhttp/authhttp.go)
- Severity: high

The client can create a payment for a positive server-selected amount without
an approval callback or caller-selected satoshi ceiling. It can default to
mainnet after a network lookup failure. The retry path also has response-body
lifetime hazards around recursive payment handling.

Suggested correction: require explicit payment approval and a maximum amount,
fail closed on network lookup errors, validate all server payment fields, and
close each response before retry.

Swift handling: automatic payment is not included. Any future client must make
payment authority and limits explicit.

### GO-061: Certificate validation does not enforce requested disclosures

- Package: `auth/utils`
- File: [`validate_certificates.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/utils/validate_certificates.go)
- Severity: high

`verifyForRequestedType` confirms that each supplied certificate has a
requested type, but it reads and then ignores the requested field list.
`ValidateCertificates` also does not require at least one certificate for each
requested type. A nonempty response can therefore pass request matching while
it omits a requested type or disclosure field.

Suggested correction: compare every keyring field with the requested field
list and require the complete requested type set before success.

Swift handling: preparation and validation require exact keyring fields and
the complete requested type set. The operation is all-or-nothing.

### GO-062: Certificate responses are not correlated with a pending request

- Package: `auth`
- File: [`peer.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/peer.go)
- Severity: high

`RequestCertificates` does not store the request on the session.
`handleCertificateResponse` accepts a signed response for a session and checks
it against the peer-wide `CertificatesToRequest` configuration. It does not
require a pending request or bind the response to the request that caused it.
An unsolicited or stale response can therefore enter validation under the
wrong request state.

Suggested correction: store one bounded pending request on the session,
compare the exact response with that request, and clear the request only after
successful signature and certificate validation.

Swift handling: `PeerAuthenticator` stores one pending request per session,
rejects unsolicited or mismatched responses, and clears the request only after
successful response-signature verification.

### GO-063: The requested-certificate HTTP header is not signed

- Package: `auth/transports`
- File: [`simplified_http_transport.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/auth/transports/simplified_http_transport.go)
- Severity: high

`authMessageFromGeneralMessageResponse` reads
`x-bsv-auth-requested-certificates` into the authentication message after it
creates the signed response payload. Auth headers are excluded from that
payload, and the general-message signature covers only the payload. A network
intermediary can therefore alter the certificate request without invalidating
the signature.

Suggested correction: include a canonical hash of the requested-certificate
set in the signed payload, or send a signed BRC-103 certificate-request
message.

Swift handling: the HTTP frame codec rejects this header. Callers use the
signed BRC-103 certificate-request message.

### GO-064: Storage resolution does not bind advertisements to the requested UHRP identifier

- Package: `storage`
- File: [`downloader.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/storage/downloader.go)
- Severity: medium

Each advertisement has a content-hash field and a UHRP-identifier field, but
`Resolve` ignores both fields. It accepts the host from any current four-field
PushDrop result, even when the lookup service returns an advertisement for a
different file. The later download hash check prevents incorrect content from
being returned, but the client still contacts an unrelated server and spends
network and hashing work on an invalid result.

Suggested correction: require the 32-byte hash and parsed UHRP field to equal
the requested identifier before the host enters the result set.

Swift handling: `UHRPDownloader` checks both fields before it accepts the
advertisement or starts a request.

### GO-065: Storage expiry fields accept trailing bytes

- Package: `storage`
- File: [`downloader.go`](https://github.com/bsv-blockchain/go-sdk/blob/de26fdec57a945ddc06de5d5617f6c32374f3929/storage/downloader.go)
- Severity: low

`Resolve` reads one variable integer from the expiry field but does not require
the field reader to reach its end. Multiple byte strings can therefore
represent the same expiry value.

Suggested correction: decode one canonical CompactSize value and require
complete field consumption.

Swift handling: the advertisement parser uses exact canonical CompactSize
decoding and rejects nonminimal or trailing forms.

## Reporting format

When a new defect is confirmed, add one entry with:

- the pinned package and file;
- a small reproducible input or test;
- the effect on callers;
- a suggested correction;
- the Swift compatibility decision.

Do not add unverified differences to this file. Put ordinary API differences in
the surface matrix and deliberate Swift policy in the compatibility rulings.
