# COMP-046: Strict wallet-wire action values

## Context

Go v1.3.3 has useful wallet-wire serializers for calls 1 through 7. Some
readers also accept values that they cannot reproduce. Examples include
unordered or duplicate spend indexes, truncated UInt32 values, permissive
Boolean bytes, empty optional data, and result payloads with trailing data.
Go also decodes a present empty create-input slice as absent and decodes an
empty create-output locking script through its optional-byte helper. Both
forms change or fail when Go writes or reads them again. A present zero-length
string-slice element becomes the absent-string sentinel when Go writes it.
The Go action-result structs also store a transaction ID as a fixed array.
Their serializers always emit that field, even when a caller did not set it.
The create-action serializer cannot preserve its signable-transaction union
without also emitting this fixed zero transaction ID.

## Ruling

Swift provides stateless, bounded, typed codecs for create, sign, abort, list,
internalize, list-output, and relinquish-output calls. Callers must supply
explicit `BEEFLimits`. Swift parses BEEF and Atomic BEEF values before it
admits them to the typed model.

Swift emits spend-map entries in ascending input-index order. It rejects
duplicate or unordered indexes on input. It uses the exact Go field-specific
transaction ID order: display order in action and outpoint fields, and wire
order in transaction-ID lists and completed-action results. It requires
canonical CompactSize, exact discriminators, checked UInt32 conversion,
bounded text and collections, and full payload consumption.

The encoder writes through a payload-bounded destination. It uses checked size
arithmetic and stops an append before the destination can exceed the caller's
`maximumPayloadByteCount`.

Swift rejects values that the Go codec cannot reproduce without loss. This
includes an absent transaction ID in create-action and sign-action results,
the pinned Go signable create-action result artifact, false values for
implicit-success results, empty optional values that become absent, and list
totals that do not match their item counts.

Swift also rejects a present empty create-input slice, an empty create-output
locking script, and a present zero-length string-slice element. Required slice
fields cannot use the absent sentinel. The Swift ABI cannot preserve the Go
distinction between an absent required slice and an empty slice, so accepting
the sentinel would normalize the value and change its bytes.

Pinned Go v1.3.3 writes list-action input source locking scripts, input
unlocking scripts, and output locking scripts with its optional-byte writer,
but reads the same three fields with its required-byte reader. The sentinel
that the writer emits for `nil` is not readable by that reader. The Swift
subset therefore requires all three scripts and rejects the sentinel before
the pinned reader runs.

## Consequences

Canonical packets in the Swift action subset round-trip through the pinned Go
v1.3.3 serializers. Hostile or lossy packets fail before the oracle calls Go.
The codec does not add wallet execution, a processor, transport, storage, or
permission policy.
