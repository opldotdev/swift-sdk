# COMP-045: Canonical and bounded wallet-wire decoding

## Context

Pinned Go wallet serializers accept several values that cannot be reproduced
without ambiguity or unsafe allocation. Their readers accept nonminimal
CompactSize counts, optional Boolean bytes `02...fe`, UInt32 truncation, and an
uninitialized counterparty byte. Some result readers ignore trailing payload,
accept unknown enum bytes as zero values, or consume only the first 32 HMAC
bytes. Error-result framing also permits trailing bytes after the stack.
Pinned Go's ECDSA parser also normalizes a valid high-S signature to low-S, so
deserializing and reserializing call-16 requests or call-15 results can change
their bytes even when the DER structure is canonical.

## Ruling

Swift emits canonical CompactSize and applies explicit frame, payload, text,
originator, error-message, and error-stack bounds before copying fields. It
accepts optional Boolean only as `00`, `01`, or one-byte `ff`; a missing
privileged reason is one-byte `ff`. Public counterparties are self, anyone, or
one exact compressed SEC1 key. UInt32 values do not truncate.

The Swift request models store `forSelf` as a required Boolean. Swift accepts
the Go optional-Boolean absence byte and normalizes it to `false`. Canonical
Swift output emits `00` for `false` and `01` for `true`. It does not emit the
absence byte for this required value.

The pinned-Go oracle applies a non-allocating, call-aware byte-index preflight
before invoking a selected wallet serializer. For calls 8, 11 through 16, and
23 through 28 it checks the complete request and success-result grammar:
canonical CompactSize widths, bounded counts before slicing, exact fixed
fields and sentinels, checked UInt32 heights, protocol/key/access/counterparty
fields, both public-key request arms, signature data/digest arms, bounded DER
structure, empty-call shapes, and full consumption. A declaration above its
field or operation maximum is a resource-limit failure; a declaration within
the maximum that exceeds the remaining packet is a truncation. Remote-error
message and stack counts use the same distinction. The final process-level
panic recovery remains a sanitized last resort and never includes packet data.
DER preflight validates nonzero R and S scalars below the secp256k1 order with
fixed-width byte comparisons and requires S at or below the curve half-order.
High-S is rejected as non-round-trippable before pinned Go can normalize it.

Typed result decoding requires exact HMAC, public-key, DER-signature, header,
authentication, network, and empty-success shapes. A verification or
wait-for-authentication success represents only `true`; `false` cannot be
encoded through a Go-compatible success frame. Empty optional strings/bytes
that Go changes into absence, and empty verify-signature data that changes the
semantic arm, are rejected as non-round-trippable.

## Consequences

Canonical Swift values for the 13 key/query calls remain byte-compatible with
Go v1.3.3. A Go absent `forSelf` value is the documented exception: Swift
accepts it and emits explicit false on re-encoding. Malformed inputs fail with
redacted typed errors rather than being normalized, truncated, ignored, or
used to allocate without a bound. Raw
request framing still recognizes all defined calls 1 through 28, but the typed
key/query API is intentionally closed to calls 8, 11 through 16, and 23 through
28. COMP-046 adds the separate typed action subset. Certificate, transport,
wallet behavior, persistence, and permission policy remain outside this
checkpoint. The hostile Go matrix specifically
covers FD/FE/FF CompactSize widths including
MaxUInt64, noncanonical and truncated encodings, bounded-versus-short declared
counts, fixed-field truncations, invalid discriminators, UInt32 overflow, DER
structure and scalar boundaries, high-S rejection, empty/fixed result shapes,
and trailing bytes in the applicable
request and result grammar families. Swift tests cover exact success/failure
frame maxima, CompactSize prefix growth, checked-add overflow, and limit
relationships. A persistent pinned-Go oracle checks canonical request and
result re-encoding in both directions without importing Go fixtures.
