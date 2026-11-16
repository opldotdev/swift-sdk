# COMP-062: Bounded UHRP discovery and download

`BSVStorage` owns the transport-neutral UHRP identifier, content value, and
content-provider protocol. `BSVNetwork` owns concrete discovery and HTTP
policy.

`UHRPDownloader` requires an injected `OverlayLookupResolving` service and
explicit BEEF, PushDrop, overlay, UHRP, advertisement, host, and timeout
limits. It sends the `ls_uhrp` query TypeScript sends,
`{"uhrpUrl":"<bare id>","limit":100,"offset":0}`, with the limit lowered to
the configured advertisement maximum when that is smaller. It accepts only an
output-list answer and advertisements that `UHRPAdvertisement` authenticates
(COMP-057). The advertised hash must match the requested identifier and the
expiry must not be in the past.

Host URLs must use HTTPS, must not contain credentials, fragments, or control
characters, and may be up to 2048 bytes, the TypeScript limit. The
downloader deduplicates and sorts them. It makes at most one GET request to
each host. It sets the response-body limit before the transport reads the
body, preserves cancellation, accepts only a successful HTTP status, bounds
the MIME value, and verifies SHA-256 before it returns content.

The downloader has no built-in tracker, proxy, cookie, cache, retry,
persistence, wallet, upload, renewal, or payment policy.

## TypeScript 4.1.1 alignment (2026-11-16)

The four-field unsigned layout this ruling first described
(`[hash, UHRP URL, host URL, expiry]`) is not what TypeScript hosts publish.
Every real advertisement has six signed fields, so the old decoder found no
hosts for any real file. The downloader now uses the TypeScript layout and
rejects the old shape. `UHRPDownloadConfiguration` no longer takes
`pushDropLimits`; the advertisement decoder applies the TypeScript bounds.
