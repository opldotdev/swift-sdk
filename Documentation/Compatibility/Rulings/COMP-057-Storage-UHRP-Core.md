# COMP-057: Bounded UHRP storage core

Pinned Go storage joins UHRP value conversion to overlay resolution, downloader
HTTP, authenticated upload APIs, and untyped service responses. Those concerns
have materially different resource, transport, and authority policies.

`BSVStorage` preserves the canonical UHRP Base58Check version and SHA-256
content mapping. It provides immutable bounded URL and content values plus a
narrow `Sendable` content-provider protocol.

The package excludes HTTP, host discovery, upload/download clients, auth,
wallet operations, persistence, and service metadata. Each needs a separate
packet with an explicit transport and authorization design.

## Signed host advertisements (2026-11-16)

`BSVStorage` now decodes and authenticates UHRP host advertisements with
`UHRPAdvertisement`, following TypeScript
`packages/sdk/src/storage/UHRPAdvertisementValidation.ts` (the code the
`tm_uhrp` topic manager runs): six canonical lock-before PushDrop fields
(host identity key, SHA-256 hash, HTTPS URL of at most 2048 bytes, expiry and
file size as canonical CompactSize values from 1 to 2^53 - 1, DER signature),
a locking key linked to the host by BRC-42 under `[2, "uhrp advertisement"]`,
key ID `"1"`, counterparty anyone, and a signature over fields 0 to 4. This
adds a `BSVScript` dependency to `BSVStorage`. Advertisement creation stays
with hosts and is not provided.

`UHRPURL` also accepts `uhrp:<id>` without slashes, as TypeScript
`normalizeURL` does.
