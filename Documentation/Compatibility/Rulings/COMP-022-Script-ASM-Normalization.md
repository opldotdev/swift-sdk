# COMP-022: Script ASM normalization and malformed programs

## Context

Bitcoin ASM describes operations rather than preserving their original byte
encoding. Go SDK v1.3.3 formats pushed bytes without their length opcode, so
parsing that text emits the SDK's shortest push-length form. Its formatter also
returns an empty string for malformed push programs, and its parser silently
ignores an error when a standalone push opcode name is supplied.

## Ruling

Swift ASM parsing and formatting are explicitly byte-bounded. Default
formatting uses BRC-106 names (`OP_FALSE` and `OP_TRUE`); compact output follows
BRC-14 SASM. Parsing always requires the caller to select a dialect. A named
Go-SDK dialect preserves the pinned SDK's conflicting
Chronicle/NOP map for exact interop. Common unambiguous aliases remain accepted.
Pushed data is lowercase hexadecimal
and non-minimal push forms normalize on reassembly. Standalone push opcodes,
malformed/truncated programs, ambiguous spacing, and exhausted resource limits
return typed errors instead of an empty result or partial script.

BRC-14's compact spelling is ambiguous for `OP_10` through `OP_16`, because
bare `10` through `16` are also valid pushed-data hex. Swift always interprets
the bare forms as data, matching Go ASM, and retains `OP_10`...`OP_16` in
compact output so formatting and parsing cannot silently change the program.

## Consequences

Use raw script bytes or hexadecimal when exact push-opcode preservation matters.
Use ASM for readable semantic interchange. Differential tests cover the stable
Go behavior, while focused Swift tests pin the deliberate error-policy changes.
