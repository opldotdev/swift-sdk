# COMP-051: Immutable bounded interpreter diagnostics

## Decision

Swift provides opt-in diagnostics through one `ScriptDebugSession` callback that
receives immutable, `Sendable`, bounded events. It covers Go's execution,
step, opcode, script-change, success/error, and stack push/pop lifecycle
points. Snapshots copy only caller-bounded stack prefixes; they never expose a
mutable VM, a transaction, or script bytes through descriptions or reflection.

Cancellation is explicit and stops only executions that opted into the session.
The debugger has no effect on ordinary interpreter calls.

## Go difference

Pinned Go v1.3.3 stores a mutable list of debugger callbacks and can pass
cloned mutable interpreter state. Its `WithRewind` option is declared but has
no implementation in the referenced debugger package. Swift intentionally
does not reproduce either surface: a single immutable event stream avoids
mutable-state races, and rewind is omitted rather than implied by a no-op API.
