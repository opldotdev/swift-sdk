# Third-party notices

This repository's original Swift source is licensed under the MIT License.
Runtime dependencies retain their own licenses:

- Apple Swift Crypto: Apache License 2.0.
- 21-DOT-DEV swift-secp256k1 and Bitcoin Core libsecp256k1: see the resolved
  dependency source for exact notices.
- attaswift BigInt: MIT License. The dependency is isolated behind the internal
  `BSVBigNum` target and pinned exactly in `Package.resolved`.

The BSV Go SDK is a behavioral compatibility reference and optional external
conformance oracle. Its source and fixtures are not included in this repository
and remain governed by Open BSV License Version 5.

Committed test vectors must include source-specific provenance and notices.
