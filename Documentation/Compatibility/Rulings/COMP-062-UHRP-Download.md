# COMP-062: Bounded UHRP discovery and download

`BSVStorage` owns the transport-neutral UHRP identifier, content value, and
content-provider protocol. `BSVNetwork` owns concrete discovery and HTTP
policy.

`UHRPDownloader` requires an injected `OverlayLookupResolving` service and
explicit BEEF, PushDrop, overlay, UHRP, advertisement, host, and timeout
limits. It sends the canonical `ls_uhrp` query. It accepts only an output-list
answer and exact four-field `beforeCompatibility` PushDrop advertisements.
The content hash and UHRP field must match the requested identifier. Expiry
must be one complete canonical CompactSize value.

Host URLs must use HTTPS and must not contain credentials or fragments. The
downloader deduplicates and sorts them. It makes at most one GET request to
each host. It sets the response-body limit before the transport reads the
body, preserves cancellation, accepts only a successful HTTP status, bounds
the MIME value, and verifies SHA-256 before it returns content.

The downloader has no built-in tracker, proxy, cookie, cache, retry,
persistence, wallet, upload, renewal, or payment policy.
