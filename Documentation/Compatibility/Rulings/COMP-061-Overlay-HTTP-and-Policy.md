# COMP-061: Bounded overlay HTTP and deterministic policy

Pinned Go combines SHIP and SLAP HTTP with default trackers, mutable host maps,
unbounded fan-out, scheduler-dependent aggregation, and a transaction object
that retains its full source-transaction graph.

`BSVNetwork` provides bounded HTTPS lookup and topic facilitators. They require
an absolute HTTPS origin without credentials, path, query, fragment, or a
trailing slash. Lookup accepts only strict bounded JSON or aggregated BEEF.
Topic submission is one POST. A transport failure or cancellation after that
POST begins has uncertain delivery and is not retried.

`BSVOverlay` provides an immutable `LookupResolver`. Callers supply all
trackers, overrides, additional hosts, limits, and transport. The resolver
deduplicates and sorts hosts, caps host count and concurrent work, verifies
signed SLAP advertisements, selects the first freeform answer in sorted host
order, and sorts merged output keys by transaction ID and output index. It
rejects mixed answer representations.

`OverlayTopicBroadcaster` accepts caller-supplied Atomic BEEF because the Swift
transaction value does not retain a full ancestor graph. It verifies signed
SHIP advertisements, submits once to each sorted interested host, and applies
explicit acknowledgment rules. It does not add default hosts, wallet behavior,
persistence, automatic retry, or a partial transaction-to-BEEF conversion.
