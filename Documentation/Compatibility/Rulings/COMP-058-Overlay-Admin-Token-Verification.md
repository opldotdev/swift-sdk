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
  are rejected.
- Hosts are parsed as the WHATWG URL parser in TS parses them. A host that
  ends in a number must be a valid IPv4 address in one of the WHATWG forms
  (`2130706433`, `0x7f.1`, `1.2.3`, octal parts), and is written as a dotted
  quad, so `https://2130706433/` is the origin `https://127.0.0.1`. Hosts such
  as `1.2.3.4.5`, `256.1.1.1` and `a.b.c.1` are rejected. Bracketed IPv6 hosts
  are validated and written in canonical form (`[0:0:0:0:0:0:0:1]` is `[::1]`).
  Before this, Swift kept those hosts as written, so one address under two
  spellings was two hosts, and malformed IP hosts that TS rejects were accepted.
- Swift accepts nothing TS rejects. It rejects a few forms the WHATWG parser
  repairs and no advertisement writer emits: percent-encoded or non-ASCII host
  text (TS applies IDNA), any `@` in the authority, backslashes, dot segments
  or other text in a path that must be `/`, extra slashes after the scheme, and
  leading or trailing spaces.

Discovery (COMP-061) also requires the advertising output to hold exactly one
satoshi, as `LookupResolver.ts` and `SHIPBroadcaster.ts` do.
