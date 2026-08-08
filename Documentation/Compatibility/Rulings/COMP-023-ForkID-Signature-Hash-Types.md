# COMP-023: Complete ForkID signature-hash types

## Context

Go SDK v1.3.3 represents signature-hash flags as an unrestricted byte. Its
`AnyOneCanPayForkID` constant is `0xc0`: the `ANYONECANPAY` and `FORKID`
modifiers without an ALL, NONE, or SINGLE base mode. Formatting unknown values
falls back to `ALL`, which can hide the incomplete combination.

## Ruling

Swift exposes a validated `ForkIDSignatureHashType`. It accepts exactly the six
complete replay-protected combinations: ALL, NONE, or SINGLE, each with or
without `ANYONECANPAY`. The raw `0xc0` modifier constant, missing ForkID,
Chronicle/OTDA flags outside this pinned v1.3.3 ForkID profile, undefined base
modes, and unrelated high bits are rejected with a typed error.

Preimage generation requires explicit source-output metadata and caller-selected
resource limits. The P2PKH signer additionally requires that the source locking
script is an exact P2PKH template whose hash matches the selected public-key
serialization. Signing mutates the input only after the candidate transaction
passes all bounds.

## Consequences

Callers cannot accidentally sign an ambiguous flag. Exact preimages and digests
for all six valid combinations are compared with the pinned Go SDK, and the
compressed P2PKH unlocking script is compared byte-for-byte. Unsupported future
digest flags require a new explicit API/ruling rather than being silently
accepted by this ForkID type.
