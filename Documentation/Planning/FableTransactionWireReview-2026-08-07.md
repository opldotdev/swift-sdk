# Fable review: transaction wire foundation

- Date: 2026-08-07
- Reviewer: Claude Fable 5 through the read-only advisor lane
- Authentication: signed-in Claude Max subscription; `ANTHROPIC_API_KEY` unset
- Scope: transaction IDs, outpoints, inputs/outputs, bounded legacy wire parsing,
  canonical serialization, source-output metadata, tests, and oracle extension
- Verdict: ship after one allocation fix; otherwise sound and next-layer-ready

## Finding

The initial parser reserved capacity for the complete attacker-declared input
or output count before parsing an element. Although counts were explicitly
bounded, a short hostile prefix could still request memory proportional to the
configured count rather than the available wire data, and a failed Swift
allocation can trap.

The review also required source-output hydration semantics to be frozen before
release because synthesized equality and hashing included non-wire metadata.

## Resolution

- Input capacity reservation is capped by the number of minimum 41-byte inputs
  that can fit in the remaining bytes.
- Output capacity reservation is capped by the number of minimum 9-byte outputs
  that can fit in the remaining bytes.
- A hostile million-input declaration with no body is covered by a regression
  test and fails structurally without count-amplified reservation.
- `TransactionInput` equality and hashing now cover only its outpoint,
  unlocking script, and sequence. `sourceOutput` is explicitly non-wire
  hydration metadata. ADR 0005 records the value/graph decision.

No other overflow, allocation, byte-order, size-preflight, or next-layer API
defect was found.
