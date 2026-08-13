# Research baselines

## Go SDK

Live reference: `~/code/go-sdk`. This checkout tracks
`bsv-blockchain/go-sdk` `master`. Read it when you implement or compare
behaviour.

The differential oracle lock at `Tools/Conformance/go-sdk.lock.json` still
names tag `v1.3.3` / commit `de26fdec57a945ddc06de5d5617f6c32374f3929` for
replay of those tests. Set `BSV_GO_SDK_PATH` to `$HOME/code/go-sdk` for
ordinary work. Point it at that locked tag only when you rerun the locked
oracle suite.

- Repository: `https://github.com/bsv-blockchain/go-sdk`
- License: Open BSV License Version 5
- Runtime location: `BSV_GO_SDK_PATH`, default `$HOME/code/go-sdk`
- Vendored into this repository: no

## BRC specifications

- Repository checkout: `~/code/BRCs`
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
