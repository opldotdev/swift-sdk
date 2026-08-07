# Fable architecture review — 2026-08-07

Review channel: `claude-fable-5` through Claude Max subscription.

Authentication evidence: `apiKeySource: none`, `isUsingOverage: false`.

Review complete. I validated the plan against the Go SDK checkout, both crypto dependencies, and the Swift Bitcoin precedent. (Note: this environment gave me no file-writing tool, so the review is delivered inline rather than as a plan file — which fits the brief's read-only advisory contract.)

---

# Fable architecture review — Swift BSV SDK

## 1. Recommendation

**Approve with required changes.** The layering instinct, vector-first testing rule, and dependency-ADR discipline are sound. But I found four issues during evidence review that must be fixed before the skeleton is created, because each one changes either the target graph, the `Package.swift` dependency set, or the test-fixture layout. None requires a redesign.

## 2. Required changes, by severity and leverage

**R1 — The big-integer boundary is mis-sited and mis-scheduled (highest leverage).**
The Architecture doc treats arbitrary precision as a script-number concern living in `BSVScript`, decided around Phases 4–5. The Go SDK contradicts this: `primitives/ec/shamir.go` and `primitives/keyshares/polynomial.go` do polynomial interpolation over the secp256k1 order using `math/big` via `util/big.go` (`Umod`, `NewRandomBigInt`). That is **Phase 2 (`BSVCrypto`) functionality** — Shamir shares and key backups need modular big-integer arithmetic, and `P256K` does not publicly expose scalar-field arithmetic to substitute for it. Required change: site the arbitrary-precision capability in a target *below* `BSVCrypto` (see revised graph), and move the BigInt ADR and its consensus-scale experiment into Phase 1 so Phase 2 doesn't stall.

**R2 — Fixture licensing is a Phase 1 blocker, not a pre-release checkbox.**
The Go SDK is licensed under the **Open BSV License Version 5** (`/tmp/bsv-go-sdk-research/LICENSE`), which carries chain-restricted use terms. The plan's rule "copied material retains its upstream license" is technically coherent but means every copied fixture drags OBSV-5 terms into an MIT package. The license review must complete **before Phase 1 fixture copying begins**, because it determines the `Tests/Fixtures` layout the skeleton creates. Two mitigations to evaluate: (a) many Go script suites descend from Bitcoin Core's MIT-licensed `script_tests.json` — source those from their original upstream instead; (b) prefer the differential harness (run the pinned Go SDK to *generate* vectors) over copying files, since generated outputs are cleaner provenance than copied test sources.

**R3 — ChainTracker/Broadcaster protocol placement breaks the proposed graph.**
The plan puts chain-tracker interfaces in `BSVSPV`. In the Go SDK the `ChainTracker` and `Broadcaster` interfaces live in the *transaction* package (`transaction/chaintracker/`, `transaction/broadcaster.go`), because merkle-path and BEEF verification take a chain tracker as a parameter. Under the proposed graph, `BSVTransaction` cannot see `BSVSPV` protocols. Required change: define the `ChainTracker`/`Broadcaster` protocols in `BSVTransaction`; keep implementations (WhatsOnChain, ARC, headers client) in `BSVNetwork`, and full SPV verification (which needs the interpreter) in `BSVSPV`.

**R4 — Transaction value/reference semantics need an ADR before Phase 4.**
Go's `Transaction` is a mutable pointer graph: inputs hold `SourceTransaction *Transaction`, and BEEF/Atomic-BEEF de-duplication depends on graph identity. A naive Swift value type either deep-copies entire ancestries on mutation (memory blow-up, identity loss, silent divergence between "the same" ancestor in two branches) or forces an explicit graph store keyed by txid. The plan's "value types by default, references need justification" rule is right — and this is the justified exception, or at minimum the case needing a designed alternative. This is the single largest false-parity and API-regret risk in the plan. It does not block the skeleton, but the ADR plus a small prototype must be the *first* Phase 4 packet.

**R5 — Adopt "feature modules + umbrella" and accept the `@_exported` risk explicitly** (details in §3).

**R6 — Linux WebSocket transport needs an experiment before Phase 9.**
The Go auth layer includes a WebSocket transport (`auth/transports/websocket_transport.go`). `URLSessionWebSocketTask` in `FoundationNetworking` on Linux has a history of incompleteness. Required: the transport protocol abstraction lands in Phase 7 as planned, plus a spike proving Linux WebSocket viability; if it fails, an ADR for a fallback dependency (swift-nio websocket / async-http-client) before Phase 9 starts.

**R7 — Inventory Go script-number quirks and rule on each before Phase 5.**
`script/interpreter/number.go` has behaviors that are Go artifacts, not consensus: `Bytes()` clamps to int32 pre-Genesis, `MinimallyEncode` mutates its input slice, and overflow results remain valid until reinterpreted. Under your stated precedence (consensus > Go quirks), each of these needs an explicit `conformant`-vs-`deviation` ruling in the compatibility matrix, with differential tests pinning whichever behavior you choose. Doing this ad hoc mid-Phase-5 is how false parity happens.

## 3. Revised target graph

The consensus spine is right, including `BSVInterpreter` as the cycle-breaker over script + transaction (this matches the Go structure, where the interpreter imports both). Changes:

```text
BSVCore                      (bytes, cursor, varint, hex, errors)
  └─ BSVBigNum               (internal or @_spi: sign-magnitude/limb arithmetic,
  │                           modular ops; consumed by Crypto AND Script)
  ├─ BSVCrypto               (hashes, AES, DRBG, P256K wrappers, BRC-42, Shamir)
  │    └─ BSVKeys            (Base58Check, WIF, BIP-32/39, BSM, ECIES)
  │         └─ BSVScript     (bytecode, opcodes, ASM, script numbers, locking templates)
  │              └─ BSVTransaction  (tx model, sighash, BUMP/BEEF, merkle paths,
  │                   │              ChainTracker & Broadcaster *protocols*, signing templates)
  │                   └─ BSVInterpreter  (era configs, execution engine)
  │                        └─ BSVSPV     (full verification; needs interpreter)
  │                             └─ BSVNetwork  (tracker/broadcaster impls, HTTP; FoundationNetworking isolated here)
  │                                  └─ BSVWallet   (BRC-100, proto wallet, substrates)
  │                                       ├─ BSVAuth      (BRC-103/104, peer, transports)
  │                                       └─ BSVServices  (overlay + SHIP/SLAP + identity +
  │                                                        registry + KV + storage/UHRP, one target)
BSV  (umbrella: @_exported import of every public module)
```

Decisions embedded here, answering the flagged questions:

- **Umbrella:** ship both. Fine-grained public modules plus a thin `BSV` umbrella using `@_exported import`, with the risk accepted in an ADR. Precedent is strong: the Swift Bitcoin checkout does exactly this (`src/bitcoin/Exports.swift`), as does swift-nio's `NIO` module. The non-underscored alternatives (typealias shims) cannot re-export top-level functions and operators cleanly. Constrain underscored-attribute use to that one file, and document feature-module imports as the stable path so the umbrella is convenience, not load-bearing.
- **Target count:** keep the six-module consensus spine separate — that layering is compiler-enforced architecture and worth the target overhead. Above the wallet line, collapse `BSVOverlay` + `BSVServices` into one `BSVServices` target for the first release; those APIs are the least stable, and because most consumers import the umbrella, splitting later is cheap. Keep `BSVAuth` separate — it has genuinely distinct transport machinery and concurrency-sensitive session state (Go has dedicated concurrent tests for it).
- **`BSVBigNum`:** internal (or `@_spi`) target under both Crypto and Script, whether the implementation is `attaswift/BigInt`-backed or bespoke. Reserving this boundary now is what lets the BigInt decision be swapped later without graph surgery.

## 4. Dependency decisions and pre-approval experiments

1. **swift-secp256k1 (21-DOT-DEV) 0.23.x — one experiment required before skeleton.** The package uses SwiftPM **traits** (tools 6.1 manifest), with `ecdh`, `recovery`, `schnorrsig`, `musig` on by default — recovery and ECDH needs are covered. The experiment: confirm `P256K`'s key-agreement API can return the **raw/compressed shared point** (33 bytes) rather than only libsecp256k1's default SHA-256'd x-coordinate. BRC-42, BRC-77/ECIES, and Electrum-compatible ECDH all need the point itself. If `P256K` can't, the skeleton needs a small C-shim target against the exported (explicitly unstable) `libsecp256k1` product — that changes the target list, so this must be answered first. Also verify low-S normalization and DER handling parity in the same spike; libsecp256k1's RFC-6979 signing should match Go's but must be vector-proven.
2. **swift-crypto 4.x — approved.** I verified the checkout ships a non-underscored `CryptoExtras` product (alongside the legacy `_CryptoExtras`) with AES-CBC, AES block-function, CFB, and PBKDF2 test coverage. Pin to 4.x and use only the non-underscored product.
3. **Swift 6.1 floor — confirmed, and now compulsory.** The trait-based secp256k1 manifest effectively requires a 6.1+ toolchain for consumers anyway. Note the package's own caveat that Xcode doesn't resolve trait-conditioned Swift settings; defaults suffice for this SDK, so document "default traits only."
4. **BigInt — experiment in Phase 1, not Phase 4.** Test `attaswift/BigInt` against: sign-magnitude little-endian encode/decode at 750 KB and 32 MB (limits confirmed in `script/interpreter/config.go`), the arithmetic set, modular ops for Shamir, and allocation behavior under hostile inputs. One caution for the parity mindset: the Go reference's own byte-to-bigint conversion is O(n²) (per-byte `Lsh`/`Or` loop) and would be unusably slow at 32 MB — so **behavioral** parity is the target; do not reproduce Go's conversion strategy, and don't let differential tests at Chronicle scale time out into false confidence. A hybrid (Int64 fast path + big-num slow path, mirroring Go's own clamped `Int32()`/`Int64()` API surface) is the likely winner.
5. **Internal byte cursor over `swift-binary-parsing` — approved.** The Apple package is pre-1.0; a bounded cursor is a few hundred lines you fully control in consensus-critical paths. Revisit post-1.0 as a non-urgent ADR.
6. **RIPEMD-160 — write from the specification** (or adapt only from a permissive-licensed source with notices). Do not adapt from the OBSV-licensed Go tree, which would contaminate an MIT file.

## 5. Testing gaps that could allow false parity

- **The differential harness is scheduled too late relative to its new importance.** If R2 restricts fixture copying, generated differential vectors become the *primary* conformance mechanism, not the fallback. Make the pinned-Go-SDK harness a Phase 0/1 deliverable.
- **Error-category mapping has no artifact.** "Errors preserve a stable category" is untestable without a per-area table mapping Go error identifiers to Swift error cases. Without it, tests silently verify success paths only. Require the table per work packet.
- **Go's quirky behaviors need dedicated pinning tests** (the R7 list, plus `MinimallyEncode`'s in-place mutation, which a Swift value-semantics port will *accidentally fix* — that's a behavior change that must be a deliberate `deviation` row, not an accident).
- **Chronicle-scale boundaries:** tests at exactly 750,000 bytes and 32 MiB (accept/reject at limit ± 1), with memory ceilings asserted — a hostile 32 MB multiplication is also a DoS test.
- **Wallet substrate wire formats** need byte-level golden vectors (Go has these fixtures); JSON-level comparison would hide serialization drift.
- **Auth concurrency:** Go has `session_manager_concurrent_test.go` and `authhttp_concurrent_test.go`; port the *intent* under Swift 6 strict concurrency, or the Swift session manager may be "safe" only because it was never contended in tests.
- **Sourcing script suites from Bitcoin Core upstream** (per R2) also removes a subtle false-parity vector: it tests against consensus lineage rather than against whatever the Go SDK's copy happens to contain.

## 6. Risk assessment on the named areas

- **Swift 6 concurrency:** the danger zone is exactly where R4 lives — a mutable transaction graph cannot be `Sendable` without a strategy (final class + lock, actor isolation, or value + explicit store). Decide it in the R4 ADR, not opportunistically. Everything network-up should be `async/await`-native from the start; retrofitting callbacks under strict concurrency is the known failure mode.
- **Value/reference semantics:** covered by R4. Secondary note: stack elements in the interpreter can be megabytes post-Genesis; Swift COW makes value semantics fine there, but avoid patterns that force copies in hot loops (in-place mutation via `inout` on stack storage).
- **Binary parsing:** internal cursor approved; ensure declared-length fields are validated against remaining bytes *before* allocation (the Testing doc's adversarial list already covers this — keep it).
- **Big integers:** the largest technical risk, addressed by R1/experiment 4.
- **Crypto wrappers:** the one open risk is the ECDH raw-point question (experiment 1). Everything else needed is confirmed available in the two chosen packages.
- **Linux:** hashing/EC are BoringSSL-backed on Linux via swift-crypto (byte-identical; CI will prove it). The real Linux risk is WebSocket (R6).
- **Umbrella:** acceptable with the constraints in §3.

## 7. Milestone ordering changes

1. **Move the BigInt ADR + experiment into Phase 1** (prerequisite for Phase 2 Shamir/key shares — R1).
2. **Move the differential harness to Phase 0/1** (R2 consequence).
3. **Split Phase 6:** BUMP/BEEF/merkle-path *parsing and serialization* depend only on Phase 4 and can run **in parallel with Phase 5** as an independent packet track; only SPV `verify` (scripts-only execution) needs the interpreter. This is the biggest available parallelism win for independently testable packets.
4. **Add the P256K ECDH spike to Phase 0** (it gates the target list — experiment 1).
5. Make the R4 transaction-semantics ADR the first Phase 4 packet, before any model code.
The rest of the ordering is sound — BSM after compact recovery, sighash inside Phase 4 ahead of the interpreter, network after transport protocols exist.

## 8. Smallest set of questions that truly block the package skeleton

1. **Can `P256K` return the raw/compressed ECDH shared point?** Determines whether a `libsecp256k1` C-shim target exists in `Package.swift`.
2. **The licensing ruling on OBSV-5 fixture copying** (copy-with-notices vs. generate-only vs. re-source from MIT upstreams). Determines the `Tests/Fixtures` skeleton and `PROVENANCE.json` scheme.
3. **Final target list sign-off** per §3 — specifically: umbrella-via-`@_exported` accepted, `BSVBigNum` reserved, Overlay merged into Services, tracker protocols in `BSVTransaction`.

Everything else — BigInt selection, transaction semantics, Linux WebSocket — has a reserved boundary in the revised graph and can be decided inside its phase without touching the skeleton. The Swift 6.1 floor is no longer a question: the chosen secp256k1 dependency's trait-based manifest settles it.
