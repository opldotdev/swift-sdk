# COMP-061: Bounded overlay HTTP and deterministic policy

Pinned Go combines SHIP and SLAP HTTP with default trackers, mutable host maps,
unbounded fan-out, scheduler-dependent aggregation, and a transaction object
that retains its full source-transaction graph.

`BSVNetwork` provides bounded HTTPS lookup and topic facilitators. They require
an absolute HTTPS origin without credentials, path, query, or fragment; a
single trailing slash is accepted, as in `@bsv/sdk`. Lookup accepts bounded
JSON or aggregated BEEF. Topic submission is one POST. A transport failure or
cancellation after that POST begins has uncertain delivery and is not retried.

`BSVOverlay` provides an immutable `LookupResolver`. Callers supply all
trackers, overrides, additional hosts, limits, and transport. The resolver
deduplicates and sorts hosts, caps host count and concurrent work, verifies
signed SLAP advertisements, selects the first freeform answer in sorted host
order, and sorts merged output keys by transaction ID and output index. When
hosts answer with both representations, the output lists win.

`OverlayTopicBroadcaster` accepts caller-supplied Atomic BEEF because the Swift
transaction value does not retain a full ancestor graph. It verifies signed
SHIP advertisements, submits once to each sorted interested host with the
topics that host advertised, and applies explicit acknowledgment rules. It does
not add default hosts, wallet behavior, persistence, automatic retry, or a
partial transaction-to-BEEF conversion.

## @bsv/sdk 4.1.1 wire alignment

Live overlay hosts run `@bsv/sdk` 4.1.1 and Overlay Express (ts-stack
`3b1abc569`). Where the earlier rules differed on the wire, Swift now follows
the TS hosts:

- **Aggregated lookup answers.** The octet-stream answer holds many outputs and
  one shared BEEF. Swift used to give every output the shared BEEF, so a reader
  that took its last transaction saw one transaction for every outpoint. Each
  output now gets Atomic BEEF for its own transaction, selected the way
  `Beef.toBinaryAtomic` does (`LookupResolver.ts:880-935`), plus its
  `transactionID` and `context`. When the shared BEEF lacks part of that
  transaction's ancestry, the output keeps the shared BEEF and its
  `transactionID` names the subject. Any other failure to build the Atomic
  BEEF fails the answer. Merkle paths are kept and renumbered as TS does: those
  the selected records reference, in first-reference order.
- **Reading an output.** `OutputListItem.transaction(beefLimits:)` is public, so
  callers read the transaction an output belongs to the way the resolver does:
  the `transactionID` when present, else the Atomic BEEF subject, else the last
  transaction.
- **JSON answers.** `beef` may be a byte array (what `res.json` sends), an
  object with numeric keys, or canonical base64. Outputs may carry `context`
  (byte array) and `txid`; unknown keys are ignored. A null or missing
  `outputs` still reads as empty for Go hosts. Output lists are read straight
  from the bytes, so a byte array costs one byte per element rather than one
  boxed number; `JSONSerialization` is used only for a freeform `result`, whose
  text may be at most twice the freeform limit.
- **STEAK.** The camelCase keys TS hosts send (`outputsToAdmit`,
  `coinsToRetain`, optional `coinsRemoved`) are read, as is Go's PascalCase.
  A STEAK naming a topic that was not submitted is malformed. An instruction
  object with no keys is read as Go's shape: no instructions.
- **Submission.** `X-Topics` is comma-separated, as `SHIPBroadcaster.ts` sends
  and Overlay Express reads. Off-chain values are sent, not dropped: header
  `x-includes-off-chain-values: true` and body `varint(beef length) || beef ||
  offChainValues` (`SHIPBroadcaster.ts:331-372`).
- **Status and content type.** Any 2xx status is success, and every response
  that is not `application/octet-stream` is parsed as JSON, as `response.ok`
  and `response.json()` do in TS. Body size limits still apply first.
- **Per-host topics.** Each SHIP host is sent only the topics it advertised
  (`SHIPBroadcaster.ts:468-482`).
- **Acknowledgment.** Requirements follow `SHIPBroadcaster.ts:466-545`. By
  default some host must acknowledge every topic and other hosts may fail, so
  one bogus one-satoshi advertisement no longer fails every broadcast. A host
  whose submission fails, whose STEAK is empty, or that acknowledges a topic it
  was not sent counts as acknowledging nothing; a requirement on every host or
  on that host then fails. An unmet requirement throws `acknowledgmentFailed`
  when every host answered and `uncertainDelivery` when a host failed, since
  that host may have admitted the transaction. `broadcastDetailed` reports each
  host's acknowledged topics and each failure with its error. Hosts past the
  host limit are left out, as TS stops at its host cap, instead of failing.
  Acknowledgment-policy keys that are not `https://` origins are rejected when
  the broadcaster is made, since no discovered host could match them.
- **Host normalization.** Discovered hosts, caller-supplied resolver hosts that
  are `https://` origins, and acknowledgment-policy keys are normalized to the
  origin TS requests (canonical host, no default port, no trailing slash), so
  `https://a.example/` and `https://a.example` are one host. One origin twice
  in a caller list is a duplicate, as in TS (`LookupResolver.ts:551-568`).
  Advertisements that are not HTTPS origins are skipped.
- **Discovered hosts must be public.** By default (`discoveredHostPolicy:
  .publicNetworkOnly`) discovery skips an advertised host that is a loopback,
  private, link-local, shared, multicast or reserved IPv4 or IPv6 address, or
  `localhost`, `.localhost`, `.local`, `.internal` or `.home.arpa`. Anyone can
  publish a one-satoshi advertisement, and TS refuses such addresses in
  `createPublicNetworkFetch` (`storage/PublicHTTPSFetch.ts:114-158`). TS also
  resolves names and refuses private answers; that needs DNS and belongs to
  the transport. `.anyHTTPSOrigin` turns the filter off for private
  deployments. Caller-supplied hosts are never filtered.
- **Bad outputs.** An output whose transaction cannot be read, whose `txid`
  disagrees with its BEEF, or whose index is out of range is left out, as TS
  does, instead of failing the lookup. `resolveDetailed` reports each such
  output and each failed host with its error. `resolve` throws
  `invalidLookupOutput` only when hosts returned outputs and none was usable.
- **Mixed answers.** Output lists win over freeform answers, as in
  `LookupResolver.ts:1508-1528`. `inconsistentAnswerTypes` is no longer thrown.
  When every host fails, Swift still throws `noSuccessfulResponses` instead of
  returning an empty list as TS does: an empty list would hide that no host
  answered. When every answer is freeform, the first in sorted host order is
  returned, as before.
- **Context size.** The per-output context default is 1 MiB, the TS ceiling,
  where it was 64 KiB.
