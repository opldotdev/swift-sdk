# ADR-0003: Do not vendor Open BSV fixtures

- Status: Accepted as a conservative engineering policy
- Date: 2026-08-07
- Owners: Open Protocol Labs

## Context

The SDK's original code is MIT licensed. Go SDK v1.3.3 uses Open BSV License
Version 5, which includes notice and chain-use conditions. The local BRC
repository has no license file, but its README declares Open BSV licensing
through an external mutable link without pinning the license text or version.

## Decision

Do not copy Go SDK fixtures or Open-BSV-licensed BRC examples into the initial
package.
Commit vectors only from permissive or public-domain original sources with
provenance. Use an external pinned Go SDK checkout as an ephemeral differential
oracle.

## Consequences

The package retains an unambiguous MIT boundary. The conformance harness becomes
a Phase 0/1 requirement. Committing generated oracle outputs requires a later
specific review. This policy is not a substitute for legal advice.
