# COMP-049: Strict transaction JSON

## Decision

Swift emits the compact JSON object used by Go SDK v1.3.3. The field order is
`txid`, `hex`, `inputs`, `outputs`, `version`, and `lockTime`. Input field order
is `unlockingScript`, `txid`, `vout`, and `sequence`. Output field order is
`satoshis` and `lockingScript`.

Pinned Go raw parsing leaves zero-length input and output slices nil. Its
canonical JSON therefore uses `null` for an empty input or output collection.
Swift emits the same form. The strict parser accepts `null` and `[]` as the
same empty value but emits only `null`.

Swift parses only complete bounded objects. It rejects unknown and duplicate
keys, invalid UTF-8, escaped field names and values, uppercase or malformed
hexadecimal text, trailing values, and integers above 9,007,199,254,740,991.
All expanded fields and `txid` must match `hex`.

The format describes the raw transaction. It does not carry source outputs,
unlocking-script size estimates, or change markers. These construction values
remain outside raw bytes, transaction IDs, equality, and hashing.

## Go difference

Pinned Go gives a nonempty `hex` field priority and ignores inconsistent or
unknown expanded fields. If `hex` is empty or absent, it keeps only `version`
and `lockTime` and discards the supplied inputs and outputs. Go also accepts
duplicate keys and emits `uint64` JSON numbers that exceed the exact integer
range used by common JSON consumers.

The pinned component decoder also accepts missing input and output fields. Its
transaction-ID parser accepts short and uppercase text and pads it to 32 bytes.
Swift requires every component field and one exact lowercase 32-byte ID.

Swift does not inherit these lossy behaviors. Persistent live-Go tests cover
canonical documents in both directions and record each divergence.
