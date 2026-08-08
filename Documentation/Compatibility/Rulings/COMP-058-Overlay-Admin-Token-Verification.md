# COMP-058: Strict overlay administration-token verification

## Decision

`BSVOverlay` accepts a signed SHIP or SLAP administration advertisement only
after bounded, exact `beforeCompatibility` PushDrop decoding. It validates the
identity public key, transport-neutral host text, typed topic or service, and
the DER signature over the four advertised fields using the PushDrop locking
key.

The resulting value is immutable, `Sendable`, and redacted in diagnostics and
reflection.

## Go differences

Pinned Go exposes a mutable wallet-backed template that creates and spends
tokens. Its decoder accepts a field prefix, returns an unvalidated identity
key, and ignores the appended signature. Those are not safe discovery inputs.

Swift does not select HTTP endpoints, trackers, retry policy, resolver hosts,
or a wallet capability. It also does not provide a partial unsigned token
constructor. Later construction and spending work must use explicit wallet
capabilities and preserve the verified four-field signing payload.
