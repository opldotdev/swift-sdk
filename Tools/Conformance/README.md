# Differential conformance tools

The Go oracle is a tooling-only, ephemeral differential adapter. It imports an
external `github.com/bsv-blockchain/go-sdk` v1.3.3 source tree; no Go SDK source,
tests, fixtures, or generated answers are stored here.

Set `BSV_GO_SDK_PATH` to the external source, then run:

```sh
Tools/Conformance/GoOracle/test-external.sh
Tools/Conformance/GoOracle/run.sh metadata
Tools/Conformance/GoOracle/run.sh serve
```

The scripts select exactly Go 1.25.0, work offline when the module cache is
already populated, copy the adapter into a temporary directory, and create a
temporary `go.work` replacement. They never modify the external checkout.
`GO_COMMAND` can select an already-provisioned Go binary. The runtime still
checks `runtime.Version()` and refuses any toolchain drift. Compiled artifacts
default to the repository-private `.build/go-oracle-cache` with mode `0700`, so the
metadata and long-lived `serve` launches share an offline build cache even
though their workspaces are cleaned. Set `BSV_GO_ORACLE_GOCACHE` to override
that cache path.

## Pin validation

[`go-sdk.lock.json`](go-sdk.lock.json) pins the module, tag, commit, exact Go
version, required file hashes, dependency-lock hash, and separate trusted archive
and Git complete-tree hashes. Git mode requires the exact clean HEAD and tag, an
external real path, and equality with the pinned Git tree hash.
Archive mode requires an exact complete-tree SHA-256; absence or mismatch fails
closed. The tree identity excludes `.git` and rejects symlinks and every other
non-regular entry rather than following or partially identifying them.
`metadata` reports the validated source mode/tree, dirty state,
toolchain, dependency/file hashes, and sorted operation registry.

## NDJSON protocol

`serve` accepts newline-terminated UTF-8 JSON using schema
`bsv-conformance/1`. Requests are `{schema,id,op,args}`. IDs are opaque,
nonempty, unique strings. Responses echo schema and ID and contain `ok` plus
exactly one of `result` or `error`. Each request and response line, including
the newline, is capped at 1 MiB. Protocol JSON is the only stdout output;
diagnostics use stderr.

The Swift test client performs the metadata handshake once and then serializes
all requests through one long-lived `serve` child. Timeout, malformed or
oversized output, transport failure, or child exit terminates and permanently
invalidates that client. The per-request deadline covers both the bounded pipe
write and response wait, so a child that has not begun reading cannot strand a
large request. Call `close()` for prompt cleanup; deinitialization is a final
cleanup backstop.
Metadata/build startup has a separate 60-second deadline; request deadlines
remain 10 seconds by default. Linux test targets ignore `SIGPIPE` process-wide
because Foundation does not expose Darwin's per-file-descriptor
`F_SETNOSIGPIPE`; the test process must therefore not depend on `SIGPIPE` delivery.

Byte fields are lowercase, even-length hex. Integers are canonical decimal
strings. Objects reject unknown fields. Decoders reject trailing bytes unless
the result explicitly reports consumed bytes. CompactSize is the Bitcoin
unsigned CompactSize format; `canonical` is `required` or `permissive`, and
decodes report `value`, `bytesConsumed`, and `isCanonical`. Script numbers are
Bitcoin signed-magnitude little-endian values. Their `era` is `preGenesis`,
`postGenesis`, or `chronicle`; decode also names `minimal` and decimal
`maxBytes`, which may not exceed the selected era's 4, 750,000, or 33,554,432
byte ceiling. The protocol's 1 MiB limit keeps oracle arithmetic differentials
small or medium regardless of consensus-era ceilings.

The endian integer and hexadecimal adapters intentionally query the same Go
standard-library behavior to which the SDK delegates. `base64.decode` defaults
to the strict standard-padded policy; `policy: "strict"` names that behavior
explicitly, while `policy: "goSDK"` uses ordinary `base64.StdEncoding` to match
pinned SDK call sites, including their CR/LF and discarded-bit tolerance. Exact
32-byte digest width and case normalization are named COMP-016 adapter policy: parse
accepts upper- or lowercase 64-character hexadecimal and emits internal bytes,
while display is lowercase. Base58Check is the COMP-017 adapter policy and
supports exactly one version byte.

Bitcoin Signed Message operations use the pinned SDK's legacy 65-byte compact
format only. Messages are exact bytes rather than normalized text. Signing
accepts an exact private scalar and explicit compression flag; recovery emits a
canonical compressed SEC1 public key while separately preserving the header's
compression flag. BIP-137 SegWit headers and raw DER verification are outside
this adapter.

ECIES operations require explicit deterministic sender keys, and Bitcore also
requires an exact 16-byte IV. Electrum's empty `senderPublicKey` string selects
the embedded-key layout; a nonempty compressed key selects the omitted-key
layout. The pinned Go decryptor uses `len > 69` as an unsafe proxy for an
embedded key even when an external key is supplied. Consequently, omitted-key
packets whose padded ciphertext exceeds 32 bytes are mis-sliced by pinned Go
(the first affected plaintext length is 32 bytes). The adapter reports this as
`invalidLength` before Go's CBC implementation can panic. Swift's explicit
layout continues to decrypt these packets safely; differential coverage uses
valid Go omitted layouts through 31 plaintext bytes and records a 33-byte case
as the intentional compatibility artifact.

BRC-140 key-share operations are bounded interoperability probes for accepted
backup strings. Splitting requires an exact 32-byte private scalar and canonical
decimal-string values satisfying `2 <= threshold <= shareCount <= 20`.
Recovery accepts 2 through 20 shares, caps each UTF-8 share at 128 bytes, and
rejects malformed four-field framing before invoking pinned Go. Pinned Go
normalizes decoded coordinates modulo the field prime, while Swift deliberately
requires canonical, nonzero coordinates below the prime; differential tests use
the shared accepted policy and record malformed rejection only where both agree.
Go split output is fresh random secret-bearing material and is never cached,
printed, or committed.

| Operation | Args | Result |
| --- | --- | --- |
| `metadata` | `{}` | validated metadata object |
| `bytes.reverse` | `{hex}` | `{hex}` |
| `u16/u32/u64.encode` | `{value,endian}` | `{bytes}` |
| `u16/u32/u64.decode` | `{bytes,endian}` | `{value}` |
| `hex.encode` | `{bytes}` | `{text}` |
| `hex.decode` | `{text}` | `{bytes}` |
| `base64.encode` | `{bytes}` | `{text}` (RFC 4648 standard padded) |
| `base64.decode` | `{text,policy?}` | `{bytes}` (`policy` absent or `strict`: strict standard padded; `goSDK`: ordinary standard padded behavior used at pinned SDK call sites) |
| `varint.encode` | `{value}` | `{bytes}` |
| `varint.decode` | `{bytes,canonical}` | `{value,bytesConsumed,isCanonical}` |
| `varbytes.encode` | `{bytes}` | `{bytes}` (CompactSize prefix plus payload) |
| `varbytes.decode` | `{bytes,canonical}` | `{bytes,bytesConsumed,isCanonical}` |
| `hash.sha256/sha256d/sha512/ripemd160/hash160` | `{bytes}` | `{bytes}` |
| `hmac.sha256/sha512` | `{key,message}` | `{bytes}` |
| `digest32.parse` | `{display}` | `{bytes}` (internal byte order) |
| `digest32.display` | `{bytes}` | `{display}` (reversed hexadecimal order) |
| `drbg.generate` | `{entropy,nonce,actions}` | `{outputs,reseedCounter}` (`actions` contains strict `{type:"generate",count}` or `{type:"reseed",entropy}` objects; byte fields are lowercase hex and counts/counter are decimal strings) |
| `base58.encode` | `{bytes}` | `{text}` |
| `base58.decode` | `{text}` | `{bytes}` |
| `base58check.encode` | `{payload,version}` | `{text}` |
| `base58check.decode` | `{text}` | `{payload,version}` |
| `big.umod` | `{dividend,divisor}` | `{value}` |
| `brc42.private.derive` | `{recipientPrivateKey,senderPublicKey,invoiceNumber}` | `{privateKey}` using exact UTF-8 invoice bytes |
| `brc42.public.derive` | `{recipientPublicKey,senderPrivateKey,invoiceNumber}` | `{publicKey}` in compressed SEC1 form |
| `brc94.generate` | `{proverPrivateKey,counterpartyPublicKey}` | Fresh `{proverPublicKey,sharedSecret,noncePublicKey,nonceSharedSecret,response}` proof fields |
| `brc94.verify` | `{proverPublicKey,counterpartyPublicKey,sharedSecret,noncePublicKey,nonceSharedSecret,response}` | `{valid}` for both BRC-94 proof equations |
| `bsm.sign` | `{privateKey,message,compressed}` | `{signature}` as exact 65-byte lowercase hex from legacy Bitcoin Signed Message signing |
| `bsm.recover` | `{signature,message}` | `{publicKey,compressed}` with compressed SEC1 lowercase hex and the signature header's compression flag |
| `ecies.electrum.encrypt` | `{plaintext,recipientPublicKey,senderPrivateKey,omitSenderPublicKey}` | Deterministic `{envelope}` from pinned Go Electrum ECIES |
| `ecies.electrum.decrypt` | `{envelope,recipientPrivateKey,senderPublicKey}` | `{plaintext}`; empty sender selects the embedded key, nonempty selects an external key |
| `ecies.bitcore.encrypt` | `{plaintext,recipientPublicKey,senderPrivateKey,initializationVector}` | Deterministic `{envelope}` from pinned Go Bitcore ECIES with an exact 16-byte IV |
| `ecies.bitcore.decrypt` | `{envelope,recipientPrivateKey}` | `{plaintext}` from pinned Go Bitcore ECIES |
| `keyshares.split` | `{privateKey,threshold,shareCount}` | Fresh `{shares}` from pinned Go BRC-140 splitting; threshold and count are canonical decimal strings |
| `keyshares.recover` | `{shares}` | `{privateKey}` as exact 32-byte lowercase hex from pinned Go BRC-140 recovery |
| `symmetric.encrypt` | `{key,plaintext,nonce}` | Deterministic `{envelope}` as `32-byte nonce || ciphertext || 16-byte tag` |
| `symmetric.decrypt` | `{key,envelope}` | `{plaintext}` through pinned Go `SymmetricKey.Decrypt` |
| `script.asm.decode` | `{text}` | `{bytes}` (Go SDK canonical ASM parser) |
| `script.asm.encode` | `{bytes}` | `{text}` (Go SDK canonical ASM formatter) |
| `script.asm.names` | `{}` | `{names}` (all 256 pinned Go SDK opcode names in byte order) |
| `script.execute` | `{unlockingScript,lockingScript,era,flags?,transactionVersion?}` | `{stack,valid}` for bounded context-free execution; `transactionVersion` is a canonical decimal string used by Chronicle version opcodes |
| `scriptnum.encode` | `{value,era}` | `{bytes}` |
| `scriptnum.decode` | `{bytes,era,minimal,maxBytes}` | `{value}` |
| `transaction.beef.decode` | `{bytes}` | `{version,bumps,transactions,newestTxid,atomicSubject}` for BEEF v1/v2 or Atomic BEEF |
| `transaction.beef.merge` | `{left,right}` | Sorted semantic summary after pinned Go merges two envelopes |
| `transaction.beef.reencode` | `{bytes}` | `{bytes}` emitted by pinned Go after parsing BEEF v2 or Atomic BEEF |
| `transaction.beef.trim` | `{bytes,knownTransactionIDs}` | Sorted semantic summary after pinned Go trims known txid-only records |
| `transaction.beef.txidonly` | `{bytes}` | Sorted semantic summary after pinned Go projects all records to txid-only |
| `transaction.beef.validate` | `{bytes,allowTransactionIDOnly}` | `{valid}` using the pinned Go structural/proof policy |
| `transaction.beef.verify` | `{bytes,allowTransactionIDOnly,validRoots:[{blockHeight,root}]}` | `{valid}` after pinned Go structural and chain-root verification |
| `spv.verify` | `{bytes,validRoots:[{blockHeight,root}],satoshisPerKilobyte?}` | `{valid}` after pinned Go BRC-67 ancestry, root-fee, and Script verification of a v1 BEEF root transaction |
| `transaction.decode` | `{bytes}` | `{bytes,version,inputs,outputs,lockTime,txid}` |
| `transaction.fee` | `{bytes,satoshisPerKilobyte,unlockingByteCounts}` | `{fee}` using actual nonempty scripts or one decimal-string/null estimate per input |
| `transaction.merklepath.combine` | `{left,right}` | `{bytes}` for the combined canonical BRC-74 path |
| `transaction.merklepath.decode` | `{bytes}` | `{bytes,blockHeight,treeHeight}` for canonical BRC-74 binary |
| `transaction.merklepath.root` | `{bytes,txid}` | `{root}` using display-order txid/root strings |
| `transaction.p2pkh.sign` | `{bytes,inputIndex,sourceSatoshis,sourceScript,signatureHash,privateKey}` | `{unlockingScript}` using the pinned Go signer |
| `transaction.sighash` | `{bytes,inputIndex,sourceSatoshis,sourceScript,signatureHash}` | `{preimage,digest}` for canonical legacy or replay-protected signature-hash flags |

Stable error categories are `invalidEncoding`, `invalidCharacter`,
`invalidLength`, `truncated`, `trailingData`, `noncanonical`, `overflow`,
`resourceLimit`, `checksum`, `version`, `key`, `signature`, `scalar`,
`authentication`, `padding`, `numberTooLarge`, `nonminimal`, `divisionByZero`,
`insufficientEntropy`, `invalidRequestedByteCount`, `requestTooLarge`,
`reseedRequired`, `unsupportedOperation`, `oraclePanic`, `timeout`, `transport`,
and `internal`.
Typed errors take precedence. The one pinned message fallback is isolated and
unit tested; diagnostic messages are not a compatibility surface. An operation
panic is recovered as `oraclePanic`. Startup, pin, or stream corruption exits
nonzero; ordinary operation errors return a response and keep `serve` alive.
