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
