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

## @bsv/sdk 4.1.1 alignment

Verification now matches `OverlayAdminTokenTemplate.ts:159-222`, which is what
live discovery applies:

- The PushDrop locking key must be the BRC-42 child of the advertised identity
  key for invoice `2-service host interconnect-1` (SHIP) or
  `2-service lookup availability-1` (SLAP), with the "anyone" key (scalar 1)
  as counterparty. The signature must verify under that derived key. A key that
  is not derived from the identity no longer authenticates the identity, so a
  forged advertisement cannot claim another operator's identity. A correctly
  signed token whose locking key belongs to another identity throws
  `unlinkedLockingKey`. Legacy advertisements signed with a self-derived key
  fail with `invalidSignature`, as they do in TS.
- The identity key must be canonical compressed (`02` or `03`).
- Each field is at most 4096 bytes and all five together at most 8192 bytes.
- The signature field is 8 to 80 bytes of canonical DER.
- The host field must be an advertisement URI TS accepts: an `https`,
  `https+bsvauth`, `https+bsvauth+smf`, `https+bsvauth+scrypt-offchain` or
  `https+rtt` origin, a `wss` URL, or a `js8c+bsvauth+smf` coordinate URI.
  Localhost, punycode labels, credentials, fragments, and control characters
  are rejected. The Swift parser reads the same ASCII forms TS parses with the
  WHATWG URL parser, and is stricter only on forms no writer emits (any `@`,
  backslashes, non-ASCII host text).

Discovery (COMP-061) also requires the advertising output to hold exactly one
satoshi, as `LookupResolver.ts` and `SHIPBroadcaster.ts` do.
