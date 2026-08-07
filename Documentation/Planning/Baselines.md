# Research baselines

All compatibility research and differential tests must identify these exact
baselines. A developer's mutable checkout is never an implicit source of truth.

## Go SDK

- Repository: `https://github.com/bsv-blockchain/go-sdk`
- Tag: `v1.3.3`
- Commit: `de26fdec57a945ddc06de5d5617f6c32374f3929`
- License: Open BSV License Version 5
- Runtime location: supplied through `BSV_GO_SDK_PATH`
- Vendored into this repository: no

The extracted research tree at `/private/tmp/bsv-go-sdk-research` was checked
against the archive for the pinned commit. Source content matches; differences
were limited to GitHub workflow metadata. Its `go.mod` SHA-256 is
`7dd043b15ec0f317eeb6aa2bbc336eed940c127343d613129c0f176153f9d8c5`.

The checkout at `~/code/go-sdk` is not an approved baseline. At the time of
this audit it was at commit `90f698893fbfab2b5690417746fa467f1bb5de3b` and
contained an unresolved `CHANGELOG.md` conflict.

## BRC specifications

- Repository checkout: `~/code/BRCs`
- Commit: `a0b5e42c01f13a1506b063a83070e81d4090debb`
- Fixture-copy policy: examples are specifications and research input only
  until their licensing/provenance is independently cleared.

## Swift dependencies already approved for the skeleton

- `apple/swift-crypto` 4.5.1, exact pin in `Package.resolved`.
- `21-DOT-DEV/swift-secp256k1` 0.23.2, exact pin in `Package.resolved`.

The `P256K` audit is recorded in `P256K-Audit.md`. No raw-ECDH C shim target is
needed; arbitrary high-S signature normalization needs a narrow Swift wrapper
over the C symbol already present in that dependency.

## Advisor channel

Fable reviews use the signed-in Claude Max subscription with
`ANTHROPIC_API_KEY` removed from the environment. The health check reported
`apiKeySource: none` and `isUsingOverage: false`.
