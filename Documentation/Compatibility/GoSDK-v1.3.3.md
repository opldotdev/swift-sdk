# Go SDK v1.3.3 surface matrix for Swift parity

## Baseline and scope

- Audited source: `/private/tmp/bsv-go-sdk-research`
- Pinned release: `bsv-blockchain/go-sdk` v1.3.3
- Lock commit: `de26fdec57a945ddc06de5d5617f6c32374f3929`
- Explicitly excluded: dirty/conflicted `/Users/satchmo/code/go-sdk` at `90f6988`.
- Inventory: 91 Go packages total; 55 non-example packages, including three test-support packages. The other 36 are executable documentation examples, not reusable API.
- The Go module directly requires `github.com/pkg/errors`, `golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/sync`, and `github.com/stretchr/testify`. Some production files unfortunately import `testing`/`testify` because mocks live outside `_test.go`.

“Public” below means Go-exported. Some exported test helpers are called out separately and should not become production Swift API.

## Executive findings

The current Swift target graph resolves these package-boundary differences:

1. Go and TypeScript place portable messages outside Auth. Swift uses the
   standalone `BSVMessage` module with only Core, Crypto, and Keys dependencies.
2. The reference SDKs expose named identity, overlay, registry, and storage
   packages. Swift does not expose an empty general services module.
3. Go `transaction/template/pushdrop` depends on `wallet`, but Swift
   `BSVTransaction` must remain below `BSVWallet`. Keep PushDrop data
   encoding/locking and transaction-context signing in `BSVTransaction`; move
   the wallet-backed unlocker/factory into `BSVWallet`.
4. Go places WIF methods in `primitives/ec`, addresses in `script`, and BIP-32
   in `compat`. Mirroring those namespaces would create Swift cycles. Keep WIF
   and Address in `BSVKeys`; place BIP-32 with the other common compatibility
   families in `BSVCompat`.

The lowest primitive seam is:

```text
BoundedByteReader/Writer + canonical/flexible CompactSize policy
  -> fixed-size Hash256/TxID/Outpoint representations
  -> hashing functions
  -> BigNum SPI + secp256k1 adapter + injected randomness
  -> Script bytes/opcodes/script-number codec
  -> Transaction model + four protocols:
       UnlockingScriptTemplate
       FeeModel
       ChainTracker
       Broadcaster
  -> Interpreter Engine
  -> SPV and concrete networking
  -> Wallet capability protocols
  -> Auth certificates and future sessions

Keys -> portable messages
```

## Package-by-package capability inventory

### Core encodings and block primitives

#### `chainhash` → primarily `BSVCore`, hashing constructors in `BSVCrypto`

Purpose: fixed 32-byte hashes, display/wire endianness, single/double SHA-256 helpers.

Public surface:

- Constants/errors: `HashSize`, `MaxHashStringSize`, `ErrHashStrSize`.
- Type: `Hash [32]byte`.
- Constructors/functions: `NewHash`, `NewHashFromHex`, `Decode`, `HashB/HashH`, `DoubleHashB/DoubleHashH`.
- Methods: byte cloning/set, equality, reverse-display `String`, binary and JSON marshal/unmarshal, size/marshal-to.

Internal dependencies: none. External: stdlib SHA-256/hex/JSON.

Swift split: `Hash256` storage/hex/endian semantics in `BSVCore`; hashing constructors in `BSVCrypto` to preserve the no-crypto dependency of Core.

#### `util` → `BSVCore`

Purpose: binary reader/writer, CompactSize/VarInt, byte reversal, optional encodings, byte-string DB/JSON adapters, modular arithmetic helpers, HTTP client seam.

Public surface:

- `VarInt`: `Bytes`, `Length`, `PutBytes`, `ReadFrom`, `UpperLimitInc`, `NewVarIntFromBytes`.
- `Reader`: byte/fixed/reversed/int-prefixed/string/slice/txid/optional/varint readers and `IsComplete`.
- `ReaderHoldError`: same family with deferred error accumulation plus hex/base64 helpers and `CheckComplete`.
- `Writer`: fixed/reversed/int-prefixed/string/map/slice/txid/optional/varint writers.
- `ByteString`: hex construction, string, JSON and SQL scan/value.
- Helpers: `ReverseBytes`, `ReverseBytesInPlace`, `LittleEndianBytes`, pointer helpers, `NegativeOne`, `IsNegativeOne`, `Umod`, `NewRandomBigInt`.
- Protocol/model: `HTTPClient`, `HTTPError`, `BytesOption`.

Internal dependency: `chainhash`. External: `pkg/errors`, stdlib DB/HTTP/big-int.

Public vs internal: `ReaderHoldError` is an implementation convenience and should be internal Swift machinery; bounded throwing cursor APIs should be public only if intentionally supported. `HTTPClient` belongs at the network seam, not Core.

Important quirk: `NewVarIntFromBytes` indexes without a length check and accepts non-minimal encodings. Swift needs an explicit “wire-compatible permissive decode” versus “canonical required” policy and bounded allocation before consuming declared lengths.

#### `compat/base58` → `BSVCore`

Public: `Encode([]byte) string`, `Decode(string) ([]byte,error)`. No internal dependency; uses `math/big`.

#### `block` → `BSVSPV`

Purpose: 80-byte block header representation.

Public: `HeaderSize`; `Header`; `NewHeaderFromBytes/Hex`; `Bytes`, `Hex`, `Hash`, `String`.

Dependency: `chainhash`.

### Cryptographic primitives

#### `primitives/hash` → `BSVCrypto`

Public: `Sha256`, `Sha256d`, `Sha512`, `Ripemd160`, `Hash160`, `Sha256HMAC`, `Sha512HMAC`.

External: `x/crypto/ripemd160`; otherwise stdlib.

#### `primitives/aescbc` → `BSVCrypto`

Public: `AESCBCEncrypt`, `AESCBCDecrypt`, `PKCS7Padd`, `PKCS7Unpad`. Stdlib AES only.

#### `primitives/aesgcm` → `BSVCrypto`

Public: high-level `AESEncrypt/AESDecrypt`; low-level `AESGCMEncrypt/AESGCMDecrypt`; exported `Ghash`.

Public API judgment: raw `Ghash` is exported Go implementation surface, not an application-level requirement unless differential/API parity is literal. Preserve behavior in tests; keep Swift implementation internal/SPI.

#### `primitives/drbg` → `BSVCrypto`

Public: `DRBG`, `NewDRBG`, `Generate`, `Reseed`. Dependency: `primitives/hash`. HMAC-DRBG state is private.

#### `primitives/ec` → `BSVKeys`, with symmetric cryptography in `BSVCrypto`

Purpose: secp256k1 curve, keys, DER/compact signatures, ECDH/BRC-42 derivation, symmetric encryption, Shamir bridge.

Public surface:

- Types: `Curve`, `CurveParams`, `KoblitzCurve`, `Point`, `PrivateKey`, `PublicKey`, `Signature`, `SymmetricKey`, `Network`.
- Curve/functions: `S256`, point add/double/scalar multiplication, `FromHex`, `NAF`, `IsCompressedPubKey`.
- Private keys: random/bytes/hex/WIF/key-shares/backup constructors; `Serialize`, `Hex`, `PubKey`, `Sign`, `DeriveChild`, `DeriveSharedSecret`, Shamir conversion, `Wif/WifPrefix`.
- Public keys: parse from bytes/string; compressed/uncompressed/hybrid/DER; JSON; equality/validation; multiply/tweak; verify; child/shared-secret derivation; compact recovery.
- Signatures: generic/DER parsing, DER serialization, equality, verify; compact signing/recovery.
- Symmetric keys: random/bytes/base64 constructors, byte/string encrypt/decrypt.
- Constants/errors for key/signature lengths, network prefixes, checksum and key parsing.

Internal edges: `base58`, `aesgcm`, `hash`, `keyshares`, `util`. External: stdlib crypto/ecdsa, HMAC, zlib, ASN.1, big-int.

Swift design: `BSVKeys` owns the P256K adapter, serialized point validation,
raw ECDH point normalization, tweak operations, compact recovery, low-S
normalization, and WIF. `BSVCrypto` owns the symmetric-key implementation. This
split preserves the Go concepts without copying the Go package boundary.

#### `primitives/ecdsa` → `BSVKeys`

Public: `Sign`, `SignWithCustomK`, `Verify`. Supports forced low-S and custom nonce. Dependency: `primitives/ec`.

Consensus/compatibility: deterministic nonce behavior, DER permissiveness, and externally supplied high-S normalization need byte-level vectors. Locally generated P256K signatures are low-S, but parsing/normalization still needs a narrow wrapper.

#### `primitives/keyshares` → `BSVKeys` over `BSVBigNum`

Public:

- `Curve`, `NewCurve`.
- `PointInFiniteField`, constructor/parser/string.
- `Polynomial`, constructor and `ValueAt`.
- `KeyShares`, constructors from points or backup strings, `ToBackupFormat`.

Edges: `base58`, `util`, `math/big`. The arithmetic/storage details are implementation; backup text format is compatibility API.

#### `primitives/schnorr` → `BSVKeys`

Public: `Proof`; `Schnorr`, `New`, `GenerateProof`, `VerifyProof`. Dependencies: EC and hash. This is the BRC-94-style proof seam, not general transaction Schnorr signing.

### Compatibility namespace

These are explicitly compatibility packages. The four families shared with the
TypeScript compatibility namespace are in the opt-in `BSVCompat` module.

#### `compat/bip39` and `compat/bip39/wordlists` → `BSVCompat`

Public:

- Entropy/mnemonic/seed: `NewEntropy`, `NewMnemonic`, `EntropyFromMnemonic`, `MnemonicToByteArray`, `NewSeed`, `NewSeedWithErrorChecking`, `IsMnemonicValid`.
- Mutable word-list API: `GetWordList`, `SetWordList`, `GetWordIndex`.
- Exported word lists: `English`, `ChineseSimplified`, `ChineseTraditional`, `Czech`, `French`, `Italian`, `Japanese`, `Korean`, `Spanish`.

Dependencies: wordlists and `x/crypto/pbkdf2`.

Swift concern: a process-global mutable word list is unsafe under Swift 6 concurrency. Model language/word list as an explicit value passed to mnemonic operations; retain a compatibility default if needed, actor/lock-isolated.

#### `compat/bip32` → `BSVCompat`

Public:

- `ExtendedKey`; master/string/xpub/mnemonic/random constructors.
- Child/path derivation, public neutering, network conversion, address/key extraction, string encoding, zeroing.
- Convenience functions for path-number conversion, address/public/private key batches, seed/key-pair generation.
- HD network/version constants and errors.

Edges: `base58`, `bip39`, EC/hash, Go `script.Address`, `transaction/chaincfg`.

Swift cycle-breaking: define P2PKH address/network version types in `BSVKeys`;
`BSVCompat` BIP-32 imports `BSVKeys` but not `BSVScript` or `BSVTransaction`.

#### `compat/bsm` → `BSVCompat`

Public: `SignMessage`, `SignMessageString`, `SignMessageWithCompression`, `PubKeyFromSignature`, `VerifyMessage`, `VerifyMessageDER`.

Edges: EC/hash, Go script address, util. Swift should perform address recovery/comparison through `BSVKeys`.

#### `compat/ecies` → `BSVCompat`

Public:

- Bitcore binary: `BitcoreEncrypt/Decrypt`.
- Electrum binary: `ElectrumEncrypt/Decrypt`.
- Shared/single string envelopes: `EncryptShared/DecryptShared`, `EncryptSingle/DecryptSingle`.

Edges: AES-CBC, EC, hash.

### Script representation and interpreter

#### `script` → `BSVScript`, except P2PKH addresses should be owned by `BSVKeys`

Public:

- Opcode constants/maps, script classification constants/errors.
- `Script []byte`: bytes/hex/ASM constructors; append opcode, big-int, push-data and string variants; chunks/read-op/slice; equality; JSON; `ToASM`; classifications (`IsP2PK/H/P2SH/MultiSig/Data`); address/public-key extraction.
- `ScriptChunk`: decode bytes/hex, stringify.
- Push helpers: `PushDataPrefix`, `EncodePushDatas`, `MinPushSize`, `IsSmallIntOp`.
- `Address`: constructors from string/public key/hash, validation.
- `BIP276`: encode/decode plus prefix/version/network constants.
- `InscriptionArgs`, `EnrichedInscriptionArgs`.

Edges: base58, EC/hash, util, `pkg/errors`, big-int.

Important behavior:

- Push encoding and minimal-push choice are byte consensus seams.
- BIP-276 checksum is the first four bytes of double-SHA256 over the textual payload; `EncodeBIP276` returns literal `"ERROR"` for invalid version/network rather than an error.
- Chronicle opcodes `0xb3`–`0xb7` stringify using `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_LSHIFTNUM`, `OP_RSHIFTNUM`, taking precedence over legacy `NOP4`–`NOP8`.
- Address APIs are historical namespace placement, not a reason to invert Swift dependencies.

#### `script/interpreter` → `BSVInterpreter`

Public:

- `Engine` protocol with `Execute(options...)`; `NewEngine`.
- Execution options: scripts, tx/input/previous output, flags, state, P2SH, ForkID, post-Genesis, post-Chronicle, debugger.
- `OpcodeParser`, `DefaultOpcodeParser`, `ParsedOpcode`, `ParsedScript`.
- `State`, `StateHandler`; stack/conditional/script indices, code-separator index, flags, era and finished state.
- `Debugger` lifecycle hooks.
- `ScriptNumber`: construction, sign-magnitude bytes, arithmetic/comparisons, integer conversions.
- `CheckMinimalDataEncoding`, `MinimallyEncode`, external signature-verifier injection.
- Era/limit constants: pre-Genesis op/stack/script/element/number/pubkey limits and 32 MiB Chronicle number limit.

Edges: EC/hash, script, transaction, sighash, `x/crypto/ripemd160`.

Public vs implementation: opcode operation functions, concrete stack/thread/execution config and engine state transitions are unexported but consensus-observable. Swift does not need them public; conformance must cover them.

#### `script/interpreter/errs` → `BSVInterpreter`

Public: structured `Error`, `ErrorCode` enum/constants, `NewError`, `IsErrorCode`, string conversion. Swift should map stable categories, not exact Go wording.

#### `script/interpreter/scriptflag` → `BSVInterpreter`

Public: `Flag` bitmask and policy constants; `AddFlag`, `HasFlag`, `HasAny`.

#### `script/interpreter/debug` → `BSVInterpreter`

Public: `DefaultDebugger`, `NewDebugger`, rewind option, callback function types for thread state, stack, and errors. Optional/debug-only surface.

### Transactions, proofs, SPV, and network

#### `transaction/sighash` → `BSVTransaction`

Public `Flag` and constants: `Old`, `All`, `None`, `Single`, `AnyOneCanPay`, ForkID variants, `ForkID`, `Mask`; methods `Has`, `HasWithMask`, `String`.

Quirk: unknown flag `String()` defaults to `"ALL"`.

#### `transaction` → `BSVTransaction`

Purpose: transaction graph/model, serialization, sighash, fees, BUMP/MerklePath, BEEF v1/v2 and Atomic BEEF.

Public surface:

- Model: `Transaction`, `TransactionInput`, `TransactionOutput`, `Transactions`, `Outpoint`, `UTXO/UTXOs`.
- Constructors/parsers: raw bytes/hex/stream/BEEF; op-return output; UTXO/outpoint parsers.
- Mutation/building: add inputs/outputs/UTXOs/source outputs, pay-to-address, op-return, inscriptions, merkle proofs.
- Serialization/identity: `Bytes`, `Hex`, JSON, read-from, `TxID`, size, EF/EFHex, clone/shallow clone.
- Signing: `CalcInputPreimage`, legacy preimage, signature hash, `Sign`, `SignUnsigned`, sequence/output/source hashes.
- Accounting: totals, fee/get-fee, coinbase/data checks.
- Graph/envelopes: `MerklePath`, `PathElement`, `IndexedPath`, `Beef`, `BeefTx`, `ValidationResult`; construct/parse/serialize/merge/clone/find/trim/txid-only/verify operations.
- Broadcast result types and `BroadcastFailure.Error`.
- Protocols: `UnlockingScriptTemplate`, `FeeModel`, `Broadcaster`.
- Constants/enums: BEEF v1/v2/Atomic magic, sequence defaults, EF markers, data format/change distribution, ordinals prefix, structured errors.

Edges: chainhash, hash, script, chaintracker protocol, sighash, util, `pkg/errors`.

Critical semantics:

- `Transaction` is a mutable pointer graph. Inputs may reference a full source transaction and hide a cached `sourceOutput`. BEEF deduplication and ancestry identity depend on shared graph identity. Swift needs an explicit reference graph or txid-keyed store; a naive value tree is not equivalent.
- Txids/hashes are displayed reversed relative to wire bytes; outpoint wire order is txid little-endian then index.
- Legacy `SIGHASH_SINGLE` with an input index beyond outputs returns the consensus “hash of 1” result.
- `SIGHASH_NONE/SINGLE` sequence clearing, `ANYONECANPAY`, ForkID source amount/script inclusion, and the `uint64.max` placeholder outputs must match exactly.
- BEEF v1 (BRC-64), v2 (BRC-96), Atomic BEEF (BRC-95), txid-only entries, BUMP sharing, and computed leaves require graph-preservation tests.
- Raw transaction, EF, BEEF and Atomic BEEF parsers need explicit trailing-data and allocation-limit decisions; do not inherit unsafe Go reads.

#### `transaction/fee_model` → `BSVTransaction`

Public: `SatoshisPerKilobyte.ComputeFee`; `ErrNoUnlockingScript`. Depends on transaction/util.

#### `transaction/template/p2pkh` → `BSVTransaction`

Public: `Lock`, `Decode`, `P2PKH`, `Unlock`, `Sign`, `EstimateLength`. Default sighash is `AllForkID`.

Edges: EC, script, transaction, sighash.

#### `transaction/template/pushdrop` → split `BSVTransaction`/`BSVWallet`

Public:

- `PushDrop`, `PushDropData`, `Unlocker`, `UnlockOptions`, `LockPosition`.
- `Lock`, `Unlock`, `Decode`, minimal script-chunk helper; unlocker `Sign`/`EstimateLength`.

Edges: EC/script/transaction/sighash/util and wallet.

Split: PushDrop data/locking/transaction signer in Transaction; wallet-aware protocol derivation and unlock factory in Wallet.

#### `transaction/chaincfg` → `BSVKeys`

Public: `Params`, `MainNet`, `TestNet`, network constants, `Register`, `HDPrivateKeyToPublicKeyID`, HD-version errors. This is BIP-32/address network configuration, not concrete networking.

#### `transaction/chaintracker` → protocol in `BSVTransaction`, implementation in `BSVNetwork`

Public:

- `ChainTracker`: `IsValidRootForHeight`, `CurrentHeight`.
- `WhatsOnChain`, constructor, height/root/header calls.
- Models: `BlockHeader`, `ChainInfo`, `Network`.

#### `transaction/chaintracker/headers_client` → `BSVNetwork`

Public models: `Client`, `Header`, `MerkleRootInfo`, `RequiredAuth`, `State`, `Webhook`, `WebhookRequest`.

Client operations: block by height, current height, chain tip/state, paged merkle roots, webhook get/register/unregister, root validation.

#### `transaction/broadcaster` → `BSVNetwork`

Public:

- ARC: `Arc`, `ArcResponse`, `ArcStatus`, broadcast/status methods.
- TAAL: `TAALBroadcast`, `TAALResponse`.
- WhatsOnChain: `WhatsOnChain`, `WOCNetwork`.
- All conform to transaction broadcaster and context-aware variants.

External seam: `net/http`, JSON, context/time.

#### `spv` → `BSVSPV`

Public: `Verify`, `VerifyScripts`, `GullibleHeadersClient`, fee/source/merkle errors. Edges: chainhash, interpreter, transaction, chaintracker.

`GullibleHeadersClient` is useful for tests/examples but should be conspicuously unsafe or test-only in Swift.

### Wallet

#### `wallet` → `BSVWallet`

Purpose: BRC-100 protocol model, capability interfaces, key derivation, ProtoWallet, incomplete/testing wallet implementations.

Core public protocols:

- `Interface`: key operations, certificate management, create/sign/abort/list/internalize actions, outputs, key linkage, discovery, authentication, height/header/network/version.
- `KeyOperations` = `PublicKeyGetter` + `CipherOperations` + `HMACOperations` + `SignatureOperations`.
- `CertificatesManagement`.
- Key source constraints: `IdentityKeyPublicSource`, `IdentityKeySource`, `PrivateKeySource`, `WalletKeySource`.

Core implementations:

- `KeyDeriver`, `CachedKeyDeriver`: identity, private/public/symmetric derivation and specific/counterparty linkage revelation.
- `ProtoWallet`: public key, HMAC, signatures, encrypt/decrypt, linkage revelation.
- `CompletedProtoWallet`: embeds ProtoWallet and stubs/implements the full interface.
- `Wallet` and `NewWallet`.
- Generic helpers `ToPrivateKey`, `ToIdentityKey`, `ToKeyDeriver`, `AnyoneKey`.

Public protocol/model families:

- Key addressing: `Protocol`, `SecurityLevel`, `Counterparty/CounterpartyType`, `PrivHex`, `PubHex`, `WIF`.
- Encoded values: `Bytes32Base64`, `Bytes33Hex`, `BytesHex`, `BytesList`, `StringBase64`, `CertificateType`, `SerialNumber`, `Signature`.
- Actions: `CreateAction*`, `SignAction*`, `AbortAction*`, `InternalizeAction*`, `ListActions*`, `Action`, `ActionInput`, `ActionOutput`, statuses/options/spends/signable transaction.
- Outputs: `CreateActionOutput`, `Output`, `ListOutputs*`, `RelinquishOutput*`, baskets, payments, output include/query modes.
- Crypto request/result pairs: GetPublicKey, Encrypt, Decrypt, Create/VerifyHMAC, Create/VerifySignature, RevealCounterparty/SpecificKeyLinkage.
- Certificates: `Certificate`, `IdentityCertificate`, `IdentityCertifier`, acquire/list/prove/relinquish/discover args/results, acquisition protocol, trust-self/keyring revealer.
- Service results: authentication, height/header/network/version.
- Structured wallet `Error` with byte code/message/stack.
- String/enum parsing and JSON encodings for the above.

Public-but-test-only leakage: `TestWallet`, `TestWalletOpts`, `MockWalletMethods`, `NewTestWallet*`, `WithTestWallet*` and all `OnX` mock accessors import `testing`/`testify` from non-test Go files. Keep these in `BSVWalletTests` support, not the Swift library.

Edges: chainhash, EC/hash/Schnorr, transaction/sighash, util, internal logging.

Concurrency: the key cache and mock/session-like mutable objects need locks or actors. Protocols should be `Sendable`-aware from the first Swift version.

#### `wallet/serializer` → `BSVWallet`

Purpose: BRC-100 wire frames and per-method binary codecs.

Public types: `RequestFrame`, `KeyRelatedParams`, serialized `Outpoint`.

Public functions, organized completely:

- Framing: `ReadRequestFrame`, `WriteRequestFrame`, `ReadResultFrame`, `WriteResultFrame`.
- Certificate codecs: certificate with/without signature and identity certificate.
- Symmetric `SerializeX`/`DeserializeX` pairs for:
  `AbortAction`, `AcquireCertificate`, `CreateAction`, `CreateHMAC`,
  `CreateSignature`, `Decrypt`, `DiscoverByAttributes`,
  `DiscoverByIdentityKey`, `DiscoverCertificates`, `Encrypt`,
  `GetHeader`, `GetHeight`, `GetNetwork`, `GetPublicKey`, `GetVersion`,
  `InternalizeAction`, authenticated/wait-authenticated,
  `ListActions`, `ListCertificates`, `ListOutputs`, `ProveCertificate`,
  `RelinquishCertificate`, `RelinquishOutput`,
  `RevealCounterpartyKeyLinkage`, `RevealSpecificKeyLinkage`,
  `SignAction`, `VerifyHMAC`, and `VerifySignature`.
- Some empty results intentionally serialize to zero bytes.

Edges: chainhash, EC, transaction, util, wallet. This codec is a prime differential-oracle boundary.

Swift checkpoint: strict bounded request/result frames and typed payload codecs
are accepted for action calls 1 through 7, key calls 8 and 11 through 16, and
queries 23 through 28. Canonical CompactSize, exact discriminators and fixed
results, checked UInt32 conversion, complete error frames, and redacted bounded
remote errors follow COMP-045 and COMP-046. Go's absent `forSelf` value is
accepted and normalized to the required Swift value `false`; canonical Swift
output uses the explicit false byte. Action codecs require explicit BEEF limits
and a payload-bounded writer. They reject nil/empty collisions and the three
list-action script sentinels that the pinned Go writer emits but its reader
cannot consume. They add no wallet execution, transport, storage, or permission
policy.

#### `wallet/substrates` → `BSVWallet`, concrete HTTP in `BSVNetwork` if factored

Public:

- `Call` operation byte enum.
- `WalletWire` protocol.
- `WalletWireProcessor` and raw `TransmitToWallet`.
- `WalletWireTransceiver`, implementing every wallet operation over frames.
- `HTTPWalletWire`.
- `HTTPWalletJSON`, implementing every wallet operation over JSON.

Swift status: future. The accepted wallet-wire codec is stateless serialization
only and adds no processor, transceiver, HTTP transport, wallet execution,
persistence, or permission behavior.

Edges: wallet/serializer and stdlib HTTP.

### Messages and authentication

#### `message` → `BSVMessage`

Purpose: BRC-77-style recipient-specific encrypted and signed messages.

Public: version string/bytes, `SignedMessage`, `Encrypt`, `Decrypt`, `Sign`, `Verify`. Dependency: EC.

#### `auth/certificates` → `BSVAuth`

Public:

- `Certificate`, binary/wallet conversion, sign/verify.
- `MasterCertificate`, issue/new.
- `VerifiableCertificate`, binary construction and field decryption.
- `SignatureHex`.
- Field utilities/results: create encrypted fields, decrypt one/all fields, create verifier keyring, derive encryption protocol/key ID.
- `CertifierWallet` capability protocol.
- Structured errors.

Edges: EC, transaction, util, wallet, wallet serializer.

#### `auth/utils` → `BSVAuth`

Public: requested certificate-set models/JSON, nonce creation/verification, certificate lookup/validation/encoding, certifier membership, base64 utility.

Exported test leakage: `SignCertificateForTest`, `SignCertificateWithWalletForTest`, `GetEncodedCertificateForDebug` should live in Swift test support.

#### `auth` → `BSVAuth`

Public:

- Constants/version, message types and auth errors.
- `AuthMessage`, `CertificateQuery`.
- `Transport` protocol: registered handler, send, on-data.
- `SessionManager`; `DefaultSessionManager`.
- `PeerSession`.
- `PeerOptions`, `Peer`; start/stop, authenticated-session wait, send-to-peer, certificate request/response, callback registration/removal, logger.
- Callback types for messages and certificates.
- Certificate validation entry point.

Edges: certificates/utils, EC, wallet. Uses locks/atomics/time/logging. Peer/session objects should be actors or carefully synchronized `Sendable` references.

#### `auth/brc104` → `BSVAuth`

Public: authenticated HTTP header constants and included-header allowlists.

#### `auth/authpayload` → `BSVAuth`

Public: serialize/deserialize authenticated HTTP request/response payloads; simplified response; header inclusion policy; base-URL and sender-key options.

Edges: BRC-104, EC, util; stdlib HTTP/URL.

#### `auth/transports` → `BSVAuth`

Public:

- `SimplifiedHTTPTransport` and options; context-aware `Send`, `OnData`, handler retrieval.
- `WebSocketTransport` and options; send/callback.
- A second transport interface equivalent in purpose to auth transport.
- Handler errors.

Edges: auth, authpayload, BRC-104, utils, EC; external `x/net/websocket`.

#### `auth/clients/authhttp` → `BSVAuth`

Public: `AuthFetch`, `AuthPeer`, request/options models; constructor/options; authenticated `Fetch`, certificate request, received-certificate drain, logger.

Edges: all auth subpackages, EC, script, P2PKH, wallet; stdlib HTTP.

### Overlay and high-level services

These packages need named Swift modules when their public APIs are implemented.
They do not map to an empty general services module.

#### `overlay`

Public protocol models: networks, protocol names/IDs for SHIP/SLAP, `TaggedBEEF`, `Steak`, admittance instructions, applied transaction, topic data, metadata. Edges: chainhash, transaction.

#### `overlay/admin-token`

Public: `OverlayAdminToken`, lock/unlock; `OverlayAdminTokenData`, decode. Edges: overlay, script, PushDrop, wallet.

#### `overlay/lookup`

Public:

- `Facilitator.Lookup`.
- HTTPS facilitator.
- `LookupResolver`: query and competent-host discovery.
- `LookupQuestion`, `LookupAnswer`, `LookupFormula`, `OutputListItem`, `AnswerType`.
- Main/test tracker defaults and 30-second max wait.

Edges: overlay, admin token, transaction, util; HTTP.

#### `overlay/topic`

Public:

- Overlay `Broadcaster` implementing transaction broadcasting; host discovery.
- `BroadcasterConfig`.
- `Facilitator.Send`; HTTPS implementation.
- `AckFrom`, `Response`, `RequireAck`.
- 30-second query timeout.

Edges: overlay, admin token, lookup, transaction, util; HTTP.

#### `identity`

Public:

- `Client`: resolve by identity key/attributes, reveal attributes.
- `IdentityClientOptions`, originator/field constrained strings.
- `DisplayableIdentity`, parser, defaults and known identity types.
- `CertificateVerifier`, default verifier.
- `TransactionCreator`.
- `TestableIdentityClient`, mock verifier, injected broadcaster/transaction creator.

Edges: auth certificates, overlay/topic, EC, transaction, PushDrop, util, wallet.

Test-only judgment: `MockCertificateVerifier` and `TestableIdentityClient` should be test support, despite export.

#### `registry`

Public:

- `RegistryClientInterface`; `RegistryClient`.
- Register/revoke/list-own and resolve basket/protocol/certificate definitions.
- Definition protocol and models: basket/protocol/certificate data and queries, field descriptor, registry record/token data, result types and definition enum.
- Broadcaster factory/configuration and overlay network selection.

Edges: overlay lookup/topic, script, transaction, PushDrop, wallet.

Public test leakage: `MockRegistry` and `NewMockRegistry` live in production and import `testing`/`testify`; do not port into the Swift product.

#### `kvstore`

Public: `KVStoreInterface`, `LocalKVStore`, config/options, `KeyValue`, default payment amount, validation/corruption/wallet errors; async Get/Set/Remove semantics.

Edges: transaction, PushDrop, util, wallet.

#### `storage`

Public:

- UHRP helpers: normalize/validate, URL from hash/file, hash from URL.
- `StorageDownloaderInterface`, `StorageDownloader`, config/result; resolve and download.
- `StorageUploaderInterface`, `Uploader`, config; publish/find/list/renew.
- Upload/download/file/metadata/result models and status/errors.

Edges: auth HTTP client, base58, overlay/lookup, hash, transaction, PushDrop, util, wallet.

This package will need a direct Auth dependency when its named Swift module is
implemented.

### Internal/test-support packages

- `internal/logging`: only exported `NewTestLogger(testing.TB)`. Test support only.
- `util/test_util`: fixture builders/assertions for hashes, keys, transactions. No product API.
- `util/test_cert_util`: certificate test construction. No product API.
- `wallet/testcertificates`: test certificate manager. No product API.
- The 36 `docs/examples/...` packages are executable usage samples and expose no SDK surface.

## Internal dependency edges

Compact adjacency list, excluding stdlib and test-only imports:

```text
auth -> auth/certificates, auth/utils, ec, wallet
auth/authpayload -> auth/brc104, ec, util
auth/brc104 -> none
auth/certificates -> ec, transaction, util, wallet, wallet/serializer
auth/clients/authhttp -> auth, authpayload, certificates, transports, utils,
                         ec, script, p2pkh, wallet
auth/transports -> auth, authpayload, brc104, utils, ec
auth/utils -> certificates, ec, wallet

block -> chainhash
chainhash -> none
compat/base58 -> none
compat/bip32 -> base58, bip39, ec, hash, script, chaincfg
compat/bip39 -> wordlists
compat/bip39/wordlists -> none
compat/bsm -> ec, hash, script, util
compat/ecies -> aescbc, ec, hash

primitives/aescbc -> none
primitives/aesgcm -> none
primitives/drbg -> hash
primitives/ec -> base58, aesgcm, hash, keyshares, util
primitives/ecdsa -> ec
primitives/hash -> none
primitives/keyshares -> base58, util
primitives/schnorr -> ec, hash

script -> base58, ec, hash, util
script/interpreter -> ec, hash, script, interpreter/errs,
                      interpreter/scriptflag, transaction, sighash
script/interpreter/debug -> interpreter
script/interpreter/errs -> none
script/interpreter/scriptflag -> none

transaction -> chainhash, hash, script, chaintracker, sighash, util
transaction/broadcaster -> transaction, util
transaction/chaincfg -> none
transaction/chaintracker -> chainhash
transaction/chaintracker/headers_client -> chainhash
transaction/fee_model -> transaction, util
transaction/sighash -> none
transaction/template/p2pkh -> ec, script, transaction, sighash
transaction/template/pushdrop -> ec, script, transaction, sighash, util, wallet
spv -> chainhash, interpreter, transaction, chaintracker

wallet -> chainhash, internal/logging, ec, hash, schnorr,
          transaction, sighash, util
wallet/serializer -> chainhash, ec, transaction, util, wallet
wallet/substrates -> wallet, wallet/serializer

message -> ec
overlay -> chainhash, transaction
overlay/admin-token -> overlay, script, pushdrop, wallet
overlay/lookup -> overlay, admin-token, transaction, util
overlay/topic -> overlay, admin-token, lookup, transaction, util
identity -> auth/certificates, overlay, overlay/topic, ec,
            transaction, pushdrop, util, wallet
registry -> overlay, lookup, topic, script, transaction, pushdrop, wallet
kvstore -> transaction, pushdrop, util, wallet
storage -> authhttp, base58, overlay, lookup, hash,
           transaction, pushdrop, util, wallet
```

External runtime concentration:

- `github.com/pkg/errors`: util, script, transaction.
- `golang.org/x/crypto`: RIPEMD-160, PBKDF2.
- `golang.org/x/net/websocket`: auth WebSocket transport.
- `testing`/`testify` leaked into production: wallet test wallet, registry mock, internal logging and helper packages.
- `x/sync` is module-level/test usage, not a core public dependency.

## Tests and fixture inventory

All listed names are `_test.go` files in the corresponding package.

- `auth`: `errors_extra`, `peer_extra`, `peer`, `session_manager_concurrent`, `session_manager`, `validate_certificates`.
- `auth/authpayload`: `http`.
- `auth/certificates`: `certificate_extra`, `certificate`, `master`, `verifiable`.
- `auth/clients/authhttp`: `authhttp_concurrent`, `authhttp_coverage`, `authhttp_extra`, `authhttp`.
- `auth/transports`: `simplified_http_transport`, `transports_extra`, `websocket_transport`.
- `auth/utils`: `auth_utils_extra`, `crypto_nonce`, `get_verifiable_certificates`, `validate_certificates`.
- `block`: `header`.
- `chainhash`: `hash`, `hashfuncs`, `marshal`.
- `compat/base58`: `base58`.
- `compat/bip32`: `derive`, `extendedkey`, `hd_key`.
- `compat/bip39`: `bip39`.
- `compat/bsm`: `sign`, `verify`.
- `compat/ecies`: `ecies`.
- `identity`: `client`, `identity_extra`.
- `internal/logging`: `test_logger`.
- `kvstore`: `kvstore_extra`, `local_kv_store`.
- `message`: `encrypted`, `signed`.
- `overlay`: `overlay`.
- `overlay/admin-token`: `admin-token`, `admin_token_extra`.
- `overlay/lookup`: `facilitator`.
- `overlay/topic`: `broadcaster`, `facilitator`.
- `primitives/aescbc`: `cbc`.
- `primitives/aesgcm`: `aesgcm_extra`, `aesgcm`.
- `primitives/drbg`: `drbg_extra`, `drbg`.
- `primitives/ec`: `privatekey`, `publickey`, `shamir`, `signature`, `symmetric_compatibility`, `symmetric`, `wif`.
- `primitives/ecdsa`: `ecdsa_extra`, `ecdsa`.
- `primitives/hash`: `hash`.
- `primitives/keyshares`: `keyshares`, `polynomial`.
- `primitives/schnorr`: `schnorr`.
- `registry`: `registry_extra`, `registry_methods`, `registry`, `registry_unit`.
- `script`: `address`, `addressvalidation`, `bip276`, `script_chunk`, `script_extra`, `script`.
- `script/interpreter`: `chronicle_opcodes`, `engine`, `example`, `number`, `opcodeparser_bench`, `opcodeparser`, `reference`, `stack`.
- `script/interpreter/debug`: `debugger`, `example`.
- `script/interpreter/errs`: `error`, `new_error`.
- `script/interpreter/scriptflag`: `scriptflag`.
- `spv`: `scripts_only_extra`, `verify`.
- `storage`: `downloader_extra`, `downloader`, `storage_extra`, `storage_methods_extra`, `storage_uploader_extra`, `uploader`, `utils`.
- `transaction`: `beef`, `coverage_extra`, `input`, `merklepath`, `merkletreeparent`, `output`, `signaturehash`, `transaction`, `txjson`, `txoutput`.
- `transaction/broadcaster`: `arc_extra`, `arc`, `taal`, `woc`.
- `transaction/chaincfg`: `params`.
- `transaction/chaintracker`: `whatsonchain_extra`, `whatsonchain`.
- `transaction/chaintracker/headers_client`: `headers_client_extra`, `headers_client`.
- `transaction/fee_model`: `compute_fee`, `sats_per_kb`.
- `transaction/sighash`: `flag`.
- `transaction/template/p2pkh`: `decode_lock`, `p2pkh_compat`, `p2pkh`.
- `transaction/template/pushdrop`: `pushdrop`.
- `util`: `big`, `bytemanipulation`, `bytestring`, `reader`, `varint`, `writer_reader_extra`.
- `wallet`: `cached_key_deriver`, `completed_proto_wallet`, `encoding_json`, `encoding`, `interfaces`, `key_deriver`, `proto_wallet_brc`, `proto_wallet_reveal`, `test_wallet`, `wallet_keys`, `wallet`.
- `wallet/serializer`: `abort_action`, `acquire_certificate`, `authenticated`, `certificate`, `create_action_args`, `create_action_result`, `create_hmac`, `create_signature`, `decrypt`, `discover_by_attributes`, `discover_by_identity_key`, `discover_certificates_result`, `encrypt`, `frame`, `get_header`, `get_height`, `get_network`, `get_public_key`, `get_version`, `identity_certificate`, `internalize_action`, `list_actions`, `list_certificates`, `list_outputs`, `prove_certificate`, `relinquish_certificate`, `relinquish_output`, `reveal_counterparty_key_linkage`, `reveal_specific_key_linkage`, `serializer`, `sign_action_args`, `sign_action_result`, `verify_hmac`, `verify_signature`.
- `wallet/substrates`: `http_wallet_json_extra`, `http_wallet_json`, `http_wallet_wire`, `vector`, `wallet_wire_comprehensive`, `wallet_wire_error`, `wallet_wire_integration`.

Fixture locations:

- `primitives/drbg/testdata/vectors.json`
- `primitives/ec/testdata/BRC42.private.vectors.json`
- `primitives/ec/testdata/BRC42.public.vectors.json`
- `primitives/ec/testdata/SymmetricKey.vectors.json`
- `primitives/ecdsa/testdata/BRC42.private.vectors.json`
- `primitives/ecdsa/testdata/BRC42.public.vectors.json`
- `script/interpreter/data/script_tests.json`
- `script/interpreter/data/sighash_bip143.json`
- `script/interpreter/data/sighash_legacy.json`
- `script/interpreter/data/tx_invalid.json`
- `script/interpreter/data/tx_valid.json`
- `script/testdata/{valid.go,invalid.go,valid-spends.go}`
- `transaction/testdata/bump.go`
- `wallet/substrates/testdata/`: 50+ JSON request/result vectors covering every wallet wire call, including action, certificate, crypto, discovery, listing, relinquish, reveal, authentication, height/header/network/version flows.

License warning: these live under the Open BSV-licensed upstream. Use the Go oracle directly or source equivalent Bitcoin Core/BIP/NIST/BRC vectors under their original licenses; do not copy them into the MIT Swift repository without the planned provenance/legal gate.

## Consensus-sensitive and compatibility quirks to pin

1. Hash/txid display-versus-wire endianness, including outpoints and merkle node combination.
2. CompactSize decoding accepts non-minimal values in Go and has unsafe direct indexing; Swift should be bounded and explicitly decide permissive/canonical modes.
3. Script numbers are little-endian sign-magnitude with negative zero and minimality rules.
4. Go script-number artifacts requiring explicit parity/deviation rows:
   - pre-Genesis `Bytes()`/integer conversion clamping,
   - overflow results remain usable as bytes/booleans until reinterpreted numerically,
   - `MinimallyEncode` mutates the caller’s slice,
   - conversions can truncate through native `int64`,
   - Go’s large-byte conversion algorithm is quadratic and must not be copied.
5. Era boundaries:
   - pre-Genesis number length 4 and classic script/stack/op limits,
   - post-Genesis number ceiling 750,000 bytes,
   - post-Chronicle number ceiling 32 MiB,
   - Chronicle reactivates/version-gates `VER`, `VERIF`, `VERNOTIF`, `2MUL`, `2DIV`, `SUBSTR`, `LEFT`, `RIGHT`, numeric shifts.
6. Minimal-push is checked at numeric evaluation/policy-dependent points, not indiscriminately for every unevaluated push.
7. Legacy `SIGHASH_SINGLE` out-of-range “hash of 1” bug is consensus.
8. ForkID sighash must include previous output amount/script; `ANYONECANPAY`, NONE/SINGLE sequence/output behavior must be exact.
9. DER parsing versus canonical DER, compact recovery ID/compression bit, deterministic nonce, low-S signing and high-S normalization.
10. BRC-42 public/private derivation agreement, invoice string bytes, shared-secret point representation.
11. Base58Check/WIF/address network prefixes and checksum mismatch categories.
12. BIP-39 NFKD/string normalization and exact multilingual word lists.
13. BIP-276 textual checksum/casing and Go’s literal `"ERROR"` return.
14. ECIES Bitcore/Electrum framing, IV/MAC derivation and compressed-key encoding.
15. BEEF/BUMP graph identity, shared ancestor deduplication, txid-only entries, computed/duplicate path elements, version magic and Atomic BEEF target txid.
16. Wallet serializer zero-byte success results, optional-field sentinels, operation byte values, and frame error representation.
17. Auth signature payload canonicalization: selected headers, request IDs, URL/base-URL handling, nonce/replay/session timing, certificate field ordering.
18. Overlay/UHRP constants, topic names, admin-token PushDrop layout and HTTP result interpretation.

## Dependency-ordered implementation sequence

1. `BSVCore`: bounded cursor/writer, endian primitives, hex, CompactSize, Base58 core, fixed hash/txid/outpoint/network values, error categories.
2. `BSVBigNum`: magnitude/modular arithmetic SPI, sign/magnitude conversion helpers, allocation/operation budgets; test 750 KB and 32 MiB before higher layers rely on it.
3. `BSVCrypto` hashes and symmetric primitives: SHA/HMAC/RIPEMD/HASH160, AES-CBC/GCM, PKCS#7, DRBG, injected randomness.
4. `BSVKeys`: secp256k1 keys and points, parsing and serialization, ECDSA, DER,
   compact recovery, ECDH, tweaks, Base58Check, WIF, Address and network
   versions, BRC-42, BRC-94, and BRC-140.
5. `BSVCompat`: BIP-32, BIP-39, BSM, and ECIES.
6. `BSVScript`: script bytes/opcodes/pushes/ASM/BIP-276/inscriptions plus bounded ScriptNumber encoding. Establish era-independent encoding before execution.
7. `BSVTransaction` foundation: graph semantics ADR/prototype first; raw model/parser/serializer/txid/outpoint, sighash, fee protocol/model, P2PKH, transaction-neutral PushDrop, and the `UnlockingScriptTemplate`, `FeeModel`, `ChainTracker`, `Broadcaster` protocols.
8. Parallel after transaction serialization:
   - `BSVInterpreter`: parser/stack/control/arithmetic/crypto/signature opcodes and era policy.
   - `BSVTransaction` MerklePath/BUMP/BEEF parsing, serialization, merge and graph operations.
9. `BSVSPV`: block headers and complete transaction/script/merkle/fee validation.
10. `BSVNetwork`: concrete chain trackers, headers client, ARC/TAAL/WOC broadcasters, HTTP seam, Linux networking tests.
11. `BSVWallet`: BRC-100 models/protocols, key deriver/cache, ProtoWallet, wallet-backed PushDrop, serializers, wire/JSON substrates.
12. `BSVMessage`: BRC-77 and BRC-78 portable messages.
13. `BSVAuth`: certificates, nonce/certificate utilities, peer/session state, BRC-104 payloads, HTTP/WebSocket/auth-fetch.
14. Future named modules: overlay/admin/lookup/topic, identity, registry, KV store, and UHRP storage.
15. Hardening: differential oracle for every codec, explicit Go-error-to-Swift-error tables, malformed/truncation fuzzing, resource ceilings, concurrency/Sendable review, Linux live transport tests.

## Exact seam contracts to stabilize early

- `ByteReadable`: cursor position/remaining, exact reads, LE integers, CompactSize with maximum and canonicality policy; failure never advances ambiguously.
- `ByteWritable`: fixed LE values, canonical CompactSize, length-prefixed bytes; no implicit Foundation serialization.
- `SecureRandomSource: Sendable`: fill bytes, deterministic test implementation.
- `BigMagnitude` SPI: compare, add/subtract/multiply/quotient/remainder, shifts, modular normalize/inverse if required, import/export unsigned big-endian; Script layer alone owns Bitcoin sign-magnitude.
- `Secp256k1Provider`: parse/serialize key, derive public key, sign/verify, compact recover, ECDH raw point, tweak-add/multiply, low-S normalize.
- `UnlockingScriptTemplate`: sign using the complete transaction and input index; estimate serialized length using the same context.
- `FeeModel`: compute fee from a transaction whose unlocking sizes are either present or estimable.
- `ChainTracker`: async current height and root-valid-for-height.
- `Broadcaster`: async transaction broadcast returning a success or structured failure.
- `ScriptEngine`: execute unlocking + locking scripts under explicit tx/input/previous-output, flags and era; no global mutable verifier injection.
- Wallet capability protocols should retain the Go split (`PublicKey`, cipher, HMAC, signature, certificates, full wallet) so auth/services can accept the narrowest dependency.
- Network transport protocols must use `async throws`, injected clocks/session timeouts, and `Sendable` request/response values.

This inventory supports the approved modular architecture, including the
standalone message boundary and the PushDrop, WIF, and address namespace
adaptations.
