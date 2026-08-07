# Testing and conformance strategy

Status: Revised after Fable review under a conservative no-copy fixture policy.

## Vector-first rule

When an upstream vector exists, the vector loader and fixture must be present in
the same work packet as the primitive implementation. A primitive is not
complete until those vectors pass.

If a vector cannot execute because a lower-level prerequisite is unfinished:

1. Add or register the fixture early when licensing permits.
2. Add the test structure with the missing prerequisite named explicitly.
3. Track the blocked conformance row in the compatibility matrix.
4. Enable it in the first work packet that supplies the prerequisite.

Skipped tests are temporary dependency markers, not acceptance evidence.

## Fixture provenance

No Open BSV-licensed fixture is copied into the MIT repository. Committed
fixtures come from separately identified permissive or public-domain originals
and live under a versioned, license-isolated directory, for example:

```text
Tests/Fixtures/GoSDK/v1.3.3/
  Manifests/group.json
  LICENSE
  primitives/
  script/
  transaction/
  wallet/
```

Each per-group manifest fragment records the upstream repository, release/tag,
commit, original path, content hash, local transformation, and governing
license. Machine-generated Swift fixtures retain the original data file as the
source of truth where practical. The loader merges fragments deterministically
and cross-validates the entire fixture tree.

Prefer vectors sourced directly from permissively licensed original standards
repositories (Bitcoin Core, published BIPs, and NIST) over downstream copies.
The pinned Go SDK differential harness compares deterministic results without
importing Go source or fixture files into the Swift package. Oracle outputs are
ephemeral until their status is explicitly reviewed.

The local BRC repository commit is pinned separately. BRC examples promoted to
vectors record the BRC number, section, and source commit.

## Test layers

### Known-answer tests

- Permissively licensed original fixtures corresponding to Go SDK behavior.
- Published BRC vectors.
- Applicable standards vectors such as NIST cryptographic vectors and BIP
  vectors, using their original authoritative sources.

### Differential tests

For formats and operations without complete static vectors, a harness produces
the same deterministic cases in the pinned Go SDK and Swift SDK, then compares
serialized bytes, results, and error categories. Generated cases are replayable
from a committed seed.

The differential harness is a Phase 0/1 deliverable, not release hardening. It
also compares stable error categories using an explicit Go-to-Swift error map
owned by each feature work packet.

### Property and invariant tests

- Parse/serialize round trips.
- Canonical encoding idempotence.
- Sign/verify and encrypt/decrypt round trips.
- Public and private BRC-42 derivation agreement.
- Transaction ID and sighash stability.
- BEEF graph preservation.
- Script interpreter stack and limit invariants.

### Negative and adversarial tests

- Truncation at every input boundary.
- Non-minimal and overflow encodings.
- Invalid key and signature encodings.
- Oversized allocations and declared lengths.
- Malformed transaction graphs and merkle paths.
- Script resource limits and Chronicle-scale arithmetic boundaries.
- Script-number limits at 750,000 bytes and 32 MiB, including limit minus one,
  exact limit, and limit plus one, with allocation ceilings.
- Go implementation artifacts that require explicit parity/deviation rulings.
- Authentication replay, nonce, and certificate failures.

### Cross-platform tests

CI runs supported tests on macOS and Linux. Cryptographic outputs and wire
formats must be byte-identical. Platform networking behavior is tested through
transport protocols and deterministic mocks before live integration tests.

## Initial behavior-source inventory

The Go SDK exposes behavior and fixture families for:

- HMAC-DRBG.
- BRC-42 private and public derivation.
- Symmetric key encryption.
- Legacy and BIP-143 sighash.
- Script reference behavior and valid/invalid transactions.
- BUMP/BEEF transaction data.
- Wallet substrate requests and results.

The inventory identifies permissively licensed originals for these families
where available. Otherwise the family remains external-oracle-only; it is not
copied or mechanically transformed from the Go repository.

The complete inventory and hashes will be generated during Phase 0 rather than
manually transcribed.

## Completion evidence

Every primitive pull request or work batch reports:

- Test commands and platforms executed.
- Upstream vector groups passed.
- New negative/property cases.
- Remaining blocked matrix rows.
- Any behavior that intentionally differs from the Go SDK and the governing
  specification for that decision.
- The error-category mapping added or exercised by the packet.
